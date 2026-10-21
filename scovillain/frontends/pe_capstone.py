"""PE/x64 frontend — capstone + pefile (+ optional PDB publics).

Why this one first (and not IDA): the IDA path in this lab dies mid-session
(idalib-mcp worker goes unreachable and cannot be revived inside a session),
while `capstone` + `pefile` over the raw .sys is the measured-reliable route.
This frontend therefore has **no IDA dependency** and no MCP dependency; a PDB
is optional and only supplies names.

It emits `ir.schema.Module` and nothing else. Downstream never imports it.

## The only thing that matters here: edge-loss completeness (DECISION.md §6)

`dispatch/frontier.py` is sound *given* that this file emits an `EdgeLossSite`
for **every** class of control transfer that is not a known CALLS edge. Miss a
class and an empty frontier (a `REFUTED`) becomes a lie. What this frontend
claims to cover, and how:

| EdgeLossKind        | detector here                                              |
|---------------------|------------------------------------------------------------|
| INDIRECT_CALL       | `call reg`, `call [reg+..]`, `call [rip+X]` where X is NOT  |
|                     | an import slot; **and every `__guard_dispatch_icall`**      |
|                     | (kCFG thunk — the real target is in rax, so the call to the |
|                     | thunk is a loss, never a resolved edge)                     |
| INDIRECT_TAILCALL   | `jmp reg`, `jmp [reg+..]`, `jmp [rip+X]` non-import         |
| CODEPTR_ESCAPE      | (i) `lea reg, [rip+X]` where X is a known function start —   |
|                     | a code pointer left local control. (ii) **a function pointer |
|                     | sitting in initialised DATA** (`FLT_OPERATION_REGISTRATION`, |
|                     | driver dispatch tables, static vtables): no `lea` is ever    |
|                     | executed for those, so a lea-only detector misses the single |
|                     | most important instance — a registered kernel callback.      |
|                     | Measured 2026-10-17 on bfs 9711: two rundown-protection      |
|                     | holders had **zero known callers**, i.e. they are reached    |
|                     | only this way.                                              |
| EXCEPTION_DISPATCH  | UNWIND_INFO with E/U handler flag -> `__C_specific_handler` |
|                     | scope table parsed for filter + jump targets                |

Known, deliberate under-approximations (each one *adds* frontier sites, i.e.
errs toward MODULO, never toward a false REFUTED):

- A `call [rip+X]` whose slot holds a non-zero in-image pointer at rest keeps
  that pointer as a *candidate* target but stays a loss site (the slot is
  writable at runtime).
- Jump tables are not decoded: a `jmp reg` stays fully-unknown.
- Data-held function pointers are attributed to the image entry point
  (DriverEntry), because that is where registration tables are consumed. That is
  a *choice*, and its consequence is explicit: such a site enters a frontier only
  when DriverEntry is forward-reachable from the query's source, which it usually
  is not. So these sites are enumerated and listable (`data_codeptrs`) but they
  do not inflate ordinary source->sink queries. Attributing them to the real
  registrar needs the registration struct decoded per-framework; until then this
  is an OPEN design item, not a solved one.
- Import calls are known edges to a synthetic import node; we do NOT model what
  the kernel does inside (e.g. `ExQueueWorkItem` invoking a callback later) —
  that deferred invocation is caught on the *producer* side as a
  CODEPTR_ESCAPE, which is why the escape detector is the load-bearing one.

CLI:
    python -m scovillain.frontends.pe_capstone <image.sys> [image.pdb] [--json out]
"""

from __future__ import annotations

import os
import re
import struct
import sys
import uuid
from dataclasses import dataclass
from typing import Optional

from scovillain.ir.schema import (
    CallResolution, Edge, EdgeKind, EdgeLossKind, EdgeLossSite, Module, Node,
    NodeKind,
)

# The lab keeps these in a user site-dir; tolerate both layouts.
for _p in ("~/.local/lib/python3.10/site-packages", "/usr/lib/python3/dist-packages"):
    _e = os.path.expanduser(_p)
    if _e not in sys.path:
        sys.path.append(_e)

import capstone  # noqa: E402
import pefile  # noqa: E402

_CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_CS.detail = False

_RIP = re.compile(r"\[rip \+ (0x[0-9a-f]+)\]")
_IMM = re.compile(r"^0x([0-9a-f]+)$")
# kCFG / XFG dispatch thunks: the call target lives in a register, so a call to
# the thunk is an indirect call, not an edge to the thunk.
_GUARD = re.compile(r"guard_(dispatch|check|xfg)_icall", re.I)

# Import nodes get synthetic ids outside any plausible RVA space.
_IMPORT_BASE = 1 << 40


@dataclass
class _Img:
    pe: pefile.PE
    data: bytes
    funcs: dict[int, list[tuple[int, int]]]  # start rva -> [(start, end), ...]
                                            #   several ranges == a split/chained
                                            #   function (hot/cold, UNW_CHAININFO)
    names: dict[int, str]                   # rva -> symbol name
    iat: dict[int, str]                     # iat slot rva -> import name
    unwind: dict[int, int]                  # func rva -> unwind info rva


def _cv_guid(pe: pefile.PE) -> str:
    """Build identity. CV GUID, not FileVersion: the lab has been burned by
    'live' copies whose version string lies (see harness CLAUDE.md §1-b)."""
    for e in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
        if e.struct.Type == 2:
            d = pe.__data__[e.struct.PointerToRawData:
                            e.struct.PointerToRawData + e.struct.SizeOfData]
            if len(d) >= 24:
                return uuid.UUID(bytes_le=d[4:20]).hex.upper() + "%d" % struct.unpack("<I", d[20:24])[0]
    return ""


def _pdb_names(pdb_path: str, pe: pefile.PE) -> dict[int, str]:
    try:
        import pdbparse
    except Exception:
        return {}
    try:
        pdb = pdbparse.parse(pdb_path)
        sects = pdb.STREAM_SECT_HDR.sections
        out: dict[int, str] = {}
        for s in pdb.STREAM_GSYM.globals:
            if hasattr(s, "offset") and hasattr(s, "segment"):
                try:
                    out.setdefault(sects[s.segment - 1].VirtualAddress + s.offset, s.name)
                except Exception:
                    pass
        return out
    except Exception:
        return {}


def _pdata(pe: pefile.PE, data: bytes) -> tuple[dict[int, list[tuple[int, int]]],
                                                dict[int, int]]:
    """Function extents from .pdata RUNTIME_FUNCTION[].

    ★ Chained regions must be merged (measured 2026-10-17 on bfs 9711). MSVC
    splits functions, and each region gets its own .pdata entry whose UNWIND_INFO
    carries UNW_FLAG_CHAININFO (0x4) plus a chained RUNTIME_FUNCTION pointing at
    the primary region. Treating a region as a function produces two lies at
    once: the fragment looks **callerless** (control enters it by a jump, not a
    call), and its forward closure is **truncated at the jump out** — which can
    yield a false REFUTED, the one bug this project exists to prevent. The first
    real-binary pairing run produced exactly such a phantom lead
    (`bfs!sub_35d2`, a 70-byte tail ending in `je`), which is how this was found.
    """
    sec = [s for s in pe.sections if s.Name.startswith(b".pdata")]
    if not sec:
        return {}, {}
    pd = sec[0].get_data()
    raw: list[tuple[int, int, int]] = []
    for i in range(0, len(pd) - 11, 12):
        b, e, u = struct.unpack("<III", pd[i:i + 12])
        if b and e > b:
            raw.append((b, e, u))

    def chained_parent(u: int) -> Optional[int]:
        """If this UNWIND_INFO chains, return the primary region's begin RVA."""
        try:
            off = pe.get_offset_from_rva(u)
            verflags, _prolog, ncodes, _frame = struct.unpack("<BBBB", data[off:off + 4])
            if not ((verflags >> 3) & 0x4):          # UNW_FLAG_CHAININFO
                return None
            p = off + 4 + 2 * ncodes
            if ncodes & 1:
                p += 2
            pb, _pe_, _pu = struct.unpack("<III", data[p:p + 12])
            return pb or None
        except Exception:
            return None

    parent: dict[int, int] = {}
    for b, _e, u in raw:
        pb = chained_parent(u)
        if pb and pb != b:
            parent[b] = pb

    def root(b: int, depth: int = 0) -> int:
        while b in parent and depth < 16:
            b = parent[b]
            depth += 1
        return b

    funcs: dict[int, list[tuple[int, int]]] = {}
    unwind: dict[int, int] = {}
    for b, e, u in raw:
        r = root(b)
        funcs.setdefault(r, []).append((b, e))
        if r == b:
            unwind.setdefault(b, u)
    for r in funcs:
        funcs[r] = sorted(set(funcs[r]))
    return funcs, unwind


def _iat_map(pe: pefile.PE) -> dict[int, str]:
    out: dict[int, str] = {}
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass
    base = pe.OPTIONAL_HEADER.ImageBase
    for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = d.dll.decode(errors="replace") if d.dll else "?"
        for imp in d.imports:
            if imp.address is None:
                continue
            nm = imp.name.decode(errors="replace") if imp.name else "ord_%s" % imp.ordinal
            out[imp.address - base] = "%s!%s" % (dll, nm)
    return out


def _scope_targets(img: _Img, func_rva: int) -> tuple[int, ...]:
    """__C_specific_handler scope table -> (filter, jump-target) RVAs in-image.

    UNWIND_INFO: ver/flags, prolog, #codes, frame; then #codes*2 bytes of codes
    (padded to 4); then handler RVA; then the scope table for the C handler.
    """
    u = img.unwind.get(func_rva)
    if not u:
        return ()
    try:
        off = img.pe.get_offset_from_rva(u)
        verflags, _prolog, ncodes, _frame = struct.unpack("<BBBB", img.data[off:off + 4])
        flags = verflags >> 3
        if not (flags & 0x3):                      # EHANDLER|UHANDLER
            return ()
        p = off + 4 + 2 * ncodes
        if ncodes & 1:
            p += 2
        n = struct.unpack("<I", img.data[p + 4:p + 8])[0]
        if not (0 < n < 4096):
            return ()
        out: list[int] = []
        rec = p + 8
        for i in range(n):
            b, e, h, j = struct.unpack("<IIII", img.data[rec + 16 * i: rec + 16 * i + 16])
            for t in (h, j):
                # 1 means EXCEPTION_EXECUTE_HANDLER (no filter func); 0 = none
                if t > 1 and img.pe.get_section_by_rva(t) is not None:
                    out.append(t)
        return tuple(sorted(set(out)))
    except Exception:
        return ()


def _qword_at(img: _Img, rva: int) -> Optional[int]:
    try:
        off = img.pe.get_offset_from_rva(rva)
        return struct.unpack("<Q", img.data[off:off + 8])[0]
    except Exception:
        return None


def load_module(sys_path: str, pdb_path: str | None = None,
                build: str = "") -> Module:
    """Disassemble one PE and emit the IR. Pure function of the file bytes."""
    pe = pefile.PE(sys_path)
    data = pe.__data__
    funcs, unwind = _pdata(pe, data)
    names = _pdb_names(pdb_path, pe) if pdb_path and os.path.exists(pdb_path) else {}
    img = _Img(pe=pe, data=data, funcs=funcs, names=names, iat=_iat_map(pe),
               unwind=unwind)

    mod = Module(binary_hash=_cv_guid(pe), arch="x86_64",
                 base=pe.OPTIONAL_HEADER.ImageBase,
                 build=build or os.path.basename(sys_path))

    for rva, ranges in funcs.items():
        attrs = {"size": sum(e - b for b, e in ranges)}
        if len(ranges) > 1:
            attrs["regions"] = len(ranges)
        mod.add_node(Node(id=rva, kind=NodeKind.FUNCTION,
                          name=names.get(rva, "sub_%x" % rva), attrs=attrs))

    imp_id: dict[str, int] = {}

    def import_node(name: str) -> int:
        if name not in imp_id:
            nid = _IMPORT_BASE + len(imp_id)
            imp_id[name] = nid
            mod.add_node(Node(id=nid, kind=NodeKind.FUNCTION, name=name,
                              attrs={"import": True}))
        return imp_id[name]

    def add_call(src: int, dst: int, res: CallResolution) -> None:
        mod.add_edge(Edge(src=src, dst=dst, kind=EdgeKind.CALLS, resolution=res))

    def loss(site: int, func: int, kind: EdgeLossKind,
             targets: tuple[int, ...] = (), detail: str = "") -> None:
        mod.add_edge_loss(EdgeLossSite(site=site, func=func, kind=kind,
                                       known_targets=targets, detail=detail))

    for rva, ranges in funcs.items():
      for (b, e) in ranges:
        try:
            off = pe.get_offset_from_rva(b)
        except Exception:
            continue
        for ins in _CS.disasm(data[off:off + (e - b)], b):
            mn, ops = ins.mnemonic, ins.op_str
            if mn not in ("call", "jmp", "lea"):
                continue

            if mn == "lea":
                m = _RIP.search(ops)
                if m:
                    t = ins.address + ins.size + int(m.group(1), 16)
                    if t in funcs:
                        loss(ins.address, rva, EdgeLossKind.CODEPTR_ESCAPE,
                             (t,), "lea of %s" % names.get(t, "sub_%x" % t))
                continue

            direct = _IMM.match(ops)
            if direct:
                t = int(direct.group(1), 16)
                if mn == "jmp" and any(lo <= t < hi for lo, hi in ranges):
                    continue                      # intra-procedural branch
                if t not in funcs:                # thunk / unlisted target
                    mod.add_node(Node(id=t, kind=NodeKind.FUNCTION,
                                      name=names.get(t, "sub_%x" % t)))
                add_call(rva, t, CallResolution.DIRECT)
                continue

            m = _RIP.search(ops)
            if m:
                slot = ins.address + ins.size + int(m.group(1), 16)
                nm = img.iat.get(slot)
                if nm and not _GUARD.search(nm):
                    add_call(rva, import_node(nm), CallResolution.INDIRECT_RESOLVED)
                    continue
                kind = (EdgeLossKind.INDIRECT_CALL if mn == "call"
                        else EdgeLossKind.INDIRECT_TAILCALL)
                if nm:                            # kCFG thunk: target is in rax
                    loss(ins.address, rva, kind, (), "via %s (target in reg)" % nm)
                    continue
                q = _qword_at(img, slot)
                cand: tuple[int, ...] = ()
                if q and mod.base <= q < mod.base + pe.OPTIONAL_HEADER.SizeOfImage:
                    r = q - mod.base
                    if r in funcs:
                        cand = (r,)
                loss(ins.address, rva, kind, cand,
                     "global fptr @ rva %#x%s" % (slot, " (at-rest target)" if cand else ""))
                continue

            # call/jmp reg, call/jmp [reg+..]: destination unknown
            loss(ins.address, rva,
                 EdgeLossKind.INDIRECT_CALL if mn == "call"
                 else EdgeLossKind.INDIRECT_TAILCALL,
                 (), "operand %s" % ops)

      tg = _scope_targets(img, rva)
      if tg:
        if True:
            loss(rva, rva, EdgeLossKind.EXCEPTION_DISPATCH, tg,
                 "C-specific scope table, %d target(s)" % len(tg))

    # ---- (ii) function pointers held in initialised data ------------------
    entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    owner = entry if entry in funcs else (min(funcs) if funcs else 0)
    size_img = pe.OPTIONAL_HEADER.SizeOfImage
    for sec in pe.sections:
        # skip executable sections: a qword there is code, not a pointer table
        if sec.Characteristics & 0x20000000:      # IMAGE_SCN_MEM_EXECUTE
            continue
        blob = sec.get_data()
        srva = sec.VirtualAddress
        for o in range(0, len(blob) - 7, 8):
            q = struct.unpack_from("<Q", blob, o)[0]
            if not q or not (mod.base <= q < mod.base + size_img):
                continue
            t = q - mod.base
            if t in funcs:
                loss(srva + o, owner, EdgeLossKind.CODEPTR_ESCAPE, (t,),
                     "fptr in data @ rva %#x -> %s (registration table?)"
                     % (srva + o, names.get(t, "sub_%x" % t)))

    return mod


def data_codeptrs(mod: Module) -> list[tuple[int, int, str]]:
    """(data_rva, target_func, detail) for every function pointer found in
    initialised data. This is the registered-callback population — the thing a
    human enumerates by hand when asked "who can invoke this?"."""
    out = []
    for s in mod.edge_loss:
        if s.kind is EdgeLossKind.CODEPTR_ESCAPE and "fptr in data" in s.detail:
            out.append((s.site, s.known_targets[0] if s.known_targets else 0, s.detail))
    return sorted(out)


# --------------------------------------------------------------------------
# helpers the queries want (name <-> addr), kept here so callers need no PDB code
# --------------------------------------------------------------------------

def by_name(mod: Module, name: str) -> int:
    """Exact-then-unique-substring lookup. Raises if ambiguous or absent, because
    a silently-wrong anchor is how a whole analysis goes wrong (harness
    CLAUDE.md: re-derive anchors per build)."""
    for nid, n in mod.nodes.items():
        if n.name == name:
            return nid
    hits = [nid for nid, n in mod.nodes.items() if name in n.name]
    if len(hits) == 1:
        return hits[0]
    raise KeyError("%r: %d matches" % (name, len(hits)))


def summarize(mod: Module) -> str:
    from collections import Counter
    res = Counter(e.resolution.value for e in mod.edges
                  if e.kind is EdgeKind.CALLS and e.resolution)
    kinds = Counter(s.kind.value for s in mod.edge_loss)
    unk = sum(1 for s in mod.edge_loss if s.fully_unknown)
    return (
        "build=%s cv=%s\nfunctions=%d (imports=%d)\ncall edges: %s\n"
        "edge-loss sites=%d (fully_unknown=%d): %s" % (
            mod.build, mod.binary_hash,
            sum(1 for n in mod.nodes.values() if not n.attrs.get("import")),
            sum(1 for n in mod.nodes.values() if n.attrs.get("import")),
            dict(res), len(mod.edge_loss), unk, dict(kinds)))


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__.strip().splitlines()[-1])
        return 2
    sysf = argv[0]
    pdbf = argv[1] if len(argv) > 1 and not argv[1].startswith("--") else None
    mod = load_module(sysf, pdbf)
    print(summarize(mod))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
