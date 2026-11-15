"""
Write the tick table of every documented function into the Results section
of its document (ARCHITECTURE.md section 10).

Usage: python3 -I tests/runner/tick_tables.py RESULTS_DIR BUILD_DIR
Runs from the repo root.

- RESULTS_DIR holds results-<os>-<isa>.txt: the test output of each target.
  Its "FUNCTION <name> PASS" lines give the functions whose tests all passed:
  the runner prints them for the core, the shell loop test for the shell.
- BUILD_DIR holds <os>-<isa>/calls.txt from platform/check.py: the calls
  each function makes on that target.

An OS cell gets a tick when that target's tests printed PASS for the
function. A function with no tests of its own (an L0 helper) is tested
through the functions that call it: it gets a tick when every L2 function
that reaches it on that target passed there. A function documented for
some OSes ("- OS:" line) gets ticks on those OSes only. A missing results
file leaves the cells of its target empty. The proof cells stay empty: CI checks no
proofs.
"""

import glob
import os
import re
import sys

OSES = ("linux", "windows", "macos")
ISAS = (("x86_64", "x86-64"), ("arm64", "ARM64"), ("riscv64", "RISC-V"))
SUPPORTED = {(o, i) for o in OSES for i, _ in ISAS} - {("windows", "riscv64"), ("macos", "riscv64")}
TICK = "✅"
MARKER = "<!-- CI generates the tick table for each function here. -->"


OS_NAMES = {"Linux": "linux", "Windows": "windows", "macOS": "macos"}
os_of = {}


def documented():
    """[(path, [(function, role)])] in document order; os_of gets the "- OS:" lines."""
    docs = []
    for path in sorted(glob.glob("docs/reference/*.md")):
        functions, current = [], None
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"## Function `([^`]+)`", line)
                if m:
                    current = [m.group(1), None]
                    functions.append(current)
                elif line.startswith("## "):
                    current = None
                elif current:
                    m = re.match(r"- Role: (L[012])\.", line)
                    if m:
                        current[1] = m.group(1)
                    m = re.match(r"- OS: ([\w, ]+)\.", line)
                    if m:
                        os_of[current[0]] = {OS_NAMES.get(n.strip()) for n in m.group(1).split(",")}
        if functions:
            docs.append((path, [tuple(f) for f in functions]))
    return docs


def passed(results_dir, os_name, isa):
    path = os.path.join(results_dir, f"results-{os_name}-{isa}.txt")
    if not os.path.exists(path):
        return set()
    with open(path, encoding="utf-8", errors="replace") as f:
        return {m.group(1) for m in re.finditer(r"^FUNCTION (\S+) PASS\s*$", f.read(), re.M)}


def callers(build_dir, os_name, isa):
    """{callee: {callers}} from the calls.txt of a target."""
    graph = {}
    path = os.path.join(build_dir, f"{os_name}-{isa}", "calls.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                caller, callee = line.split()
                graph.setdefault(callee, set()).add(caller)
    return graph


def reaching_l2(function, graph, roles):
    """The L2 functions that call function, directly or through others."""
    seen, todo, found = set(), [function], set()
    while todo:
        for caller in graph.get(todo.pop(), ()):
            if caller in seen:
                continue
            seen.add(caller)
            if roles.get(caller) == "L2":
                found.add(caller)
            todo.append(caller)
    return found


def tick(function, role, os_name, isa, results_dir, graph, roles):
    if (os_name, isa) not in SUPPORTED or os_name not in os_of.get(function, {os_name}):
        return False
    ok = passed(results_dir, os_name, isa)
    if function in ok:
        return True
    if role == "L2":
        return False
    tested_by = reaching_l2(function, graph, roles)
    return bool(tested_by) and tested_by <= ok


def table(function, role, results_dir, graphs, roles):
    lines = [f"### `{function}`", "", "| ISA | Linux | Windows | macOS | `equal` |", "|---|---|---|---|---|"]
    for isa, label in ISAS:
        cells = [TICK if tick(function, role, o, isa, results_dir, graphs[(o, isa)], roles) else "" for o in OSES]
        lines.append("| " + " | ".join([label] + cells + [""]) + " |")
    return "\n".join(lines)


def main(results_dir, build_dir):
    docs = documented()
    roles = {f: r for _, functions in docs for f, r in functions}
    graphs = {(o, isa): callers(build_dir, o, isa) for o in OSES for isa, _ in ISAS}
    for path, functions in docs:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        m = re.search(r"^## Results\n", text, re.M)
        if not m:
            sys.exit(f"{path}: no Results section")
        end = re.search(r"^## ", text[m.end():], re.M)
        rest = text[m.end() + end.start():] if end else ""
        tables = "\n\n".join(table(f, r, results_dir, graphs, roles) for f, r in functions)
        new = text[: m.end()] + "\n" + MARKER + "\n\n" + tables + "\n" + ("\n" + rest if rest else "")
        if new != text:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            print(f"updated {path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: tick_tables.py RESULTS_DIR BUILD_DIR")
    main(sys.argv[1], sys.argv[2])
