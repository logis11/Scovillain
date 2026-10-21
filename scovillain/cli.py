"""Command line entry — the one place allowed to import both a frontend and the
queries (the IR boundary says nothing *downstream* imports a frontend).

    python -m scovillain.cli frontier <image.sys> [image.pdb] <source> <sink>
    python -m scovillain.cli pairs    <image.sys> [image.pdb] [--all]
"""

from __future__ import annotations

import os
import sys

from scovillain.frontends.pe_capstone import by_name, load_module, summarize
from scovillain.graph.store import NetworkxStore
from scovillain.query.pairing import sweep
from scovillain.query.reach import reachable


def _resolve(mod, tok: str) -> int:
    return int(tok, 16) if tok.lower().startswith("0x") else by_name(mod, tok)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd, img = argv[0], argv[1]
    rest = argv[2:]
    pdb = rest[0] if rest and rest[0].endswith(".pdb") else None
    if pdb:
        rest = rest[1:]
    elif os.path.exists(img[:-4] + ".pdb"):
        pdb = img[:-4] + ".pdb"
    mod = load_module(img, pdb, build=os.path.basename(img).rsplit(".", 1)[0])

    if cmd == "pairs":
        reps = sweep(NetworkxStore(mod), leads_only="--all" not in rest)
        print(summarize(mod).splitlines()[0])
        if not reps:
            print("no paired-operation lead (and that is a result: the "
                  "population was symmetric wherever a pair was found)")
        for r in reps:
            print()
            print(r.render())
        return 0

    if cmd == "frontier":
        if len(rest) < 2:
            print("need <source> <sink>")
            return 2
        st = NetworkxStore(mod)
        ans = reachable(st, _resolve(mod, rest[0]), _resolve(mod, rest[1]))
        print("%s  [build=%s cv=%s]" % (ans.summary(), ans.build, ans.binary_hash))
        if ans.evidence.path:
            print("path:", " -> ".join(
                mod.nodes[a].name if a in mod.nodes else hex(a) for a in ans.evidence.path))
        for fs in ans.evidence.frontier[:15]:
            print("  %8.2f  %#x in %#x  %s" % (fs.score, fs.site, fs.loss.func, fs.reason))
        return 0

    print("unknown command %r" % cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
