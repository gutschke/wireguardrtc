#!/usr/bin/env python3
# 29_ast_lint.py — static check for the corruption shape that bit v0.2.0.
#
# Walks the AST of every Python executable in `daemon/` and fails on:
#
#   1. Statement-level bare expressions whose value is a `Name` or `Attribute`.
#      e.g.   `main`                  # forgot ()
#             `loop.close`            # forgot ()
#             `t.cancel`              # forgot ()
#
#   2. Method-shaped attributes used in a boolean context (if / while / not /
#      and / or / assert / ternary test).  A bound method is always truthy,
#      so `if not t.done` is always False — silent dead branch.
#
#   3. Assignments `name = obj.method` where the attribute name strongly
#      implies a call (e.g. `parse_args`, `new_event_loop`, `read`, `strip`).
#      Variables whose name itself signals callable-storage (`_fn`, `_factory`,
#      `_provider`, `_callback`, `_handler`, `_func`, `_cb`, `_thunk`) are
#      exempt; legitimately storing the method ref is fine.
#
# This is intentionally conservative — false positives turn into allowlist
# entries below.  False negatives are caught by the runtime smoke test
# (28_help_smoke.py).
#
# Background: commit 9876e79 (v0.2.0 restructure) stripped `()` from ~80
# call sites in the daemon.  The file remained syntax-valid because every
# corrupted site is a legal bound-method reference.  Restoring the daemon
# in PS28 cost a full session; this lint costs <1 s and would have
# blocked the corruption at CI time.

import ast
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Attribute names that almost-certainly should be called.  Add carefully —
# every entry here is a "calling without ()" trap door.
CALL_LIKE_ATTRS = frozenset({
    # argparse / argparser
    "parse_args", "parse_known_args",
    # asyncio
    "new_event_loop", "run", "close", "run_until_complete", "run_forever",
    "stop", "create_task",
    "done", "cancel", "canceled", "closed",
    # subprocess.Process
    "communicate", "wait", "poll", "terminate", "kill",
    # file-likes
    "read", "readline", "readlines", "write", "writelines", "flush",
    "fileno",
    # str
    "lower", "upper", "strip", "lstrip", "rstrip", "splitlines", "split",
    "decode", "encode", "title", "casefold",
    "isalpha", "isdigit", "isspace", "isupper", "islower", "isalnum",
    "startswith", "endswith",
    # bytes/bytearray
    "hex", "hexdigest", "digest",
    # dict
    "keys", "values", "items", "popitem",
    # os/pathlib
    "isfile", "isdir", "exists", "stat", "listdir",
    # logging
    "isEnabledFor", "getEffectiveLevel", "hasHandlers",
})

# LHS variable-name suffixes that legitimately store callables.
CALLABLE_NAME_SUFFIXES = (
    "_fn", "_factory", "_provider", "_callback", "_handler",
    "_func", "_cb", "_thunk", "_hook",
)

# Per-file allowlist of `(line, kind, name)` tuples for legitimate
# attribute reads that share a name with a known method.  Empty for now.
ALLOWLIST = {
    # "wireguardrtc": {(123, "expr", "foo.bar")},
}


def _attr_chain(node):
    """Return the dotted-name string of an Attribute chain (or None)."""
    chain = []
    cur = node
    while isinstance(cur, ast.Attribute):
        chain.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        chain.append(cur.id)
        return ".".join(reversed(chain))
    return None


class Linter(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.findings = []
        self._allowlist = ALLOWLIST.get(filename, set())

    def _flag(self, lineno, kind, snippet):
        if (lineno, kind, snippet) in self._allowlist:
            return
        self.findings.append((lineno, kind, snippet))

    # 1. statement-level bare Name / Attribute
    def visit_Expr(self, node):
        v = node.value
        if isinstance(v, ast.Name):
            self._flag(node.lineno, "expr-name", v.id)
        elif isinstance(v, ast.Attribute):
            chain = _attr_chain(v)
            if chain is not None:
                self._flag(node.lineno, "expr-attr", chain)
        self.generic_visit(node)

    # 2. method-shaped attributes in boolean contexts
    def _check_bool_ctx(self, expr):
        if (isinstance(expr, ast.Attribute)
                and expr.attr in CALL_LIKE_ATTRS):
            chain = _attr_chain(expr) or expr.attr
            self._flag(expr.lineno, "bool-ctx", chain)

    def visit_If(self, node):
        self._check_bool_ctx(node.test)
        self.generic_visit(node)

    def visit_While(self, node):
        self._check_bool_ctx(node.test)
        self.generic_visit(node)

    def visit_Assert(self, node):
        self._check_bool_ctx(node.test)
        self.generic_visit(node)

    def visit_IfExp(self, node):
        self._check_bool_ctx(node.test)
        self.generic_visit(node)

    def visit_BoolOp(self, node):
        for v in node.values:
            self._check_bool_ctx(v)
        self.generic_visit(node)

    def visit_UnaryOp(self, node):
        if isinstance(node.op, ast.Not):
            self._check_bool_ctx(node.operand)
        self.generic_visit(node)

    # 3. name = obj.method (method-shaped attr) assignments
    def visit_Assign(self, node):
        v = node.value
        if isinstance(v, ast.Attribute) and v.attr in CALL_LIKE_ATTRS:
            # Skip if any LHS name signals callable-storage
            exempt = False
            for t in node.targets:
                name = None
                if isinstance(t, ast.Name):
                    name = t.id
                elif isinstance(t, ast.Attribute):
                    name = t.attr
                if name and name.endswith(CALLABLE_NAME_SUFFIXES):
                    exempt = True
                    break
            if not exempt:
                chain = _attr_chain(v) or v.attr
                lhs_chain = []
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        lhs_chain.append(t.id)
                    elif isinstance(t, ast.Attribute):
                        lhs_chain.append(ast.unparse(t))
                lhs_str = ", ".join(lhs_chain)
                self._flag(node.lineno, "assign-attr",
                           f"{lhs_str} = {chain}")
        self.generic_visit(node)


def lint_file(path):
    filename = os.path.basename(path)
    with open(path) as f:
        src = f.read()
    tree = ast.parse(src, filename=path)
    lint = Linter(filename)
    lint.visit(tree)
    return lint.findings


# Files to consider.  Each is inspected — only those with a Python
# shebang are linted; bash wrappers are silently skipped.
CANDIDATES = [
    "wireguardrtc",
    "wireguardrtc-key-oracle",
    "wireguardrtc-raw-helper",
    "wireguardrtc-provision-broker",
    "wireguardrtc-provision-client",
    "wireguardrtc-provision-default",
    "build_docs.py",
]


def is_python_source(path):
    """True if the file looks like a Python script.

    Detection order:
      * extension `.py` — definitive
      * first line matches `#!.*python` — common case for chmod+x scripts
    """
    if path.endswith(".py"):
        return True
    try:
        with open(path, "rb") as f:
            first = f.readline(256)
    except OSError:
        return False
    return first.startswith(b"#!") and b"python" in first


total_findings = 0
linted = 0
for target in CANDIDATES:
    path = os.path.join(REPO, target)
    if not os.path.isfile(path):
        continue
    if not is_python_source(path):
        continue
    linted += 1
    try:
        findings = lint_file(path)
    except SyntaxError as e:
        print(f"  FAIL [{target}]: SyntaxError: {e}")
        total_findings += 1
        continue
    if not findings:
        print(f"  PASS [{target}]")
        continue
    print(f"  FAIL [{target}]: {len(findings)} site(s)")
    for lineno, kind, snippet in findings:
        print(f"      L{lineno}  [{kind}]  {snippet}")
    total_findings += len(findings)

print()
print(f"summary: {total_findings} total finding(s) across {linted} Python target(s)")
sys.exit(0 if total_findings == 0 else 1)
