#!/usr/bin/env python
"""Check GENERIC_ALLOWED in progent_agentdojo.py against the authors' patched task_suite.py files (AST, no import)."""
import ast, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))
src = (ROOT / "harness" / "progent_agentdojo.py").read_text()
ns = {}
exec(src.split("# Injection tasks the Progent authors removed")[0].split("ROOT = ")[1].split("\n", 1)[1], ns)  # GENERIC_ALLOWED dict
ok = True
for suite, (mine, mine_flag) in ns["GENERIC_ALLOWED"].items():
    f = ROOT / "progent-repo/agentdojo/src/agentdojo/default_suites/v1" / suite / "task_suite.py"
    tree = ast.parse(f.read_text())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "update_always_allowed_tools"]
    assert len(calls) == 1, (suite, len(calls))
    c = calls[0]
    theirs = [e.value for e in c.args[0].elts]
    flag = any(k.arg == "allow_all_no_arg_tools" and k.value.value is True for k in c.keywords)
    same = theirs == mine and flag == mine_flag
    ok &= same
    print(f"{suite:10} {'MATCH' if same else 'MISMATCH'}  n_tools={len(theirs)} allow_all_no_arg_tools={flag}")
sys.exit(0 if ok else 1)
