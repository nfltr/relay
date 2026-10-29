#!/usr/bin/env python3
# Copyright 2026 nfltr
# SPDX-License-Identifier: Apache-2.0

"""sast-baseline.py: baseline gate for gosec and semgrep JSON reports.

make check-gosec / make check-semgrep run the scanner, then:

    sast-baseline.py check  <gosec|semgrep> <report.json> <baseline.txt> <repo-root>
    sast-baseline.py update <gosec|semgrep> <report.json> <baseline.txt> <repo-root>
    sast-baseline.py --self-test

A finding's key is "<rule> <path> <sha256 of the flagged source line, whitespace
stripped>", so a key survives line moves and edits elsewhere in the file but not
a change to the flagged line itself. The baseline is a multiset of keys (one per
line, a trailing "# <snippet>" for reviewers). check fails (exit 1) on a finding
whose key is not in the baseline (new) and on a baseline key no longer reported
(stale: the finding was fixed or its line changed, so the baseline shrinks with
`update`).
"""
import collections
import hashlib
import json
import os
import sys
import tempfile


def findings(tool, report):
    """Yields (rule, absolute-or-relative path, 1-based line) from a report."""
    if tool == "gosec":
        for i in report.get("Issues") or []:
            yield i["rule_id"], i["file"], int(str(i["line"]).split("-")[0])
    elif tool == "semgrep":
        for r in report.get("results") or []:
            yield r["check_id"].rsplit(".", 1)[-1], r["path"], int(r["start"]["line"])
    else:
        raise SystemExit(f"unknown tool {tool!r}")


def keys(tool, report, root):
    lines_by_file = {}
    out = collections.Counter()
    snippets = {}
    for rule, path, line in findings(tool, report):
        rel = os.path.relpath(path, root) if os.path.isabs(path) else path
        rel = rel.replace(os.sep, "/")
        if rel not in lines_by_file:
            with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
                lines_by_file[rel] = f.read().split("\n")
        src = lines_by_file[rel]
        text = "".join(src[line - 1].split()) if 0 < line <= len(src) else ""
        key = f"{rule} {rel} {hashlib.sha256(text.encode()).hexdigest()[:16]}"
        out[key] += 1
        snippets[key] = (src[line - 1].strip() if 0 < line <= len(src) else "")[:80]
    return out, snippets


def read_baseline(path):
    c = collections.Counter()
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.split("#", 1)[0].strip()
            if line:
                c[line] += 1
    return c


def write_baseline(path, tool, got, snippets):
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# {tool} baseline (scripts/sast-baseline.py): accepted or false-positive\n"
                "# findings, triaged by rule.\n"
                "# Regenerate only after triaging every new finding:\n"
                f"#   scripts/check-{tool}.sh --update\n")
        for key in sorted(got):
            for _ in range(got[key]):
                f.write(f"{key}  # {snippets[key]}\n")


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) != 6 or argv[1] not in ("check", "update"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, tool, report_path, baseline_path, root = argv[1:]
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    got, snippets = keys(tool, report, root)
    if mode == "update":
        write_baseline(baseline_path, tool, got, snippets)
        print(f"{tool}: wrote {sum(got.values())} findings to {baseline_path}")
        return 0
    base = read_baseline(baseline_path)
    new, stale = got - base, base - got
    for key in sorted(new):
        print(f"NEW {key}  # {snippets[key]}")
    for key in sorted(stale):
        print(f"STALE {key}")
    print(f"{tool}: {sum(got.values())} findings, {sum(base.values())} baselined, "
          f"{sum(new.values())} new, {sum(stale.values())} stale")
    if new:
        print(f"FAIL: new {tool} findings: fix them, or (accepted with a reason) add a "
              "targeted suppression, or (false positive) re-baseline with "
              f"scripts/check-{tool}.sh --update", file=sys.stderr)
    if stale:
        print(f"FAIL: stale {baseline_path} entries (fixed or changed lines): "
              f"scripts/check-{tool}.sh --update", file=sys.stderr)
    return 1 if new or stale else 0


def self_test():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "a"))
        with open(os.path.join(d, "a", "x.go"), "w") as f:
            f.write("package a\n\nfunc f() {\n\tos.ReadFile(p)\n\tos.ReadFile(p)\n\texec.Command(c)\n}\n")
        gosec = {"Issues": [
            {"rule_id": "G304", "file": os.path.join(d, "a", "x.go"), "line": "4"},
            {"rule_id": "G304", "file": os.path.join(d, "a", "x.go"), "line": "5"},
        ]}
        semgrep = {"results": [{"check_id": "go.lang.security.audit.dangerous-exec-command",
                                "path": "a/x.go", "start": {"line": 6}}]}
        rep, base = os.path.join(d, "r.json"), os.path.join(d, "base.txt")

        def run(mode, tool, report):
            with open(rep, "w") as f:
                json.dump(report, f)
            return main(["x", mode, tool, rep, base, d])

        for tool, report in (("gosec", gosec), ("semgrep", semgrep)):
            assert run("check", tool, report) == 1, f"{tool}: unbaselined finding must fail"
            assert run("update", tool, report) == 0
            assert run("check", tool, report) == 0, f"{tool}: baselined findings must pass"
        # Two identical flagged lines are two entries: a third copy is new.
        third = {"Issues": gosec["Issues"] + [gosec["Issues"][0]]}
        run("update", "gosec", gosec)
        assert run("check", "gosec", third) == 1, "a duplicate beyond the baseline count must fail"
        # A fixed finding leaves a stale entry, which fails until re-baselined.
        assert run("check", "gosec", {"Issues": gosec["Issues"][:1]}) == 1, "stale entry must fail"
        # Moving the flagged line (an edit above it) keeps its key.
        with open(os.path.join(d, "a", "x.go"), "w") as f:
            f.write("package a\n\n// moved\nfunc f() {\n\tos.ReadFile(p)\n\tos.ReadFile(p)\n}\n")
        moved = {"Issues": [dict(i, line=str(int(i["line"]) + 1)) for i in gosec["Issues"]]}
        assert run("check", "gosec", moved) == 0, "a moved line must keep its key"
        # Changing the flagged line itself is a new finding.
        with open(os.path.join(d, "a", "x.go"), "w") as f:
            f.write("package a\n\n// moved\nfunc f() {\n\tos.ReadFile(q)\n\tos.ReadFile(p)\n}\n")
        assert run("check", "gosec", moved) == 1, "an edited flagged line must be re-triaged"
    print("sast-baseline self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
