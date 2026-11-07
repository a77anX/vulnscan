"""Lightweight, intraprocedural taint tracking for the Python AST rules.

This is a single forward pass over each function body (and the module's top level), tracking
which local names could hold attacker-influenced data. It is NOT a full dataflow analysis:
no branch/loop-aware merging, no interprocedural tracking across function calls. That's a
deliberate, documented trade-off -- a scanner that analyses one file at a time can't know what
every caller passes in, so two confidence tiers are used instead of a single yes/no:

  'source'  -- traced directly, in this function, to a known external-input API
               (request.args/.form/.json/..., input(), os.environ, sys.stdin, ...).
  'param'   -- traced to one of the function's own parameters. The parameter *might* carry
               untrusted data depending on who calls the function; we can't prove it here,
               so findings on this path keep their normal severity but get a note added.
  None      -- traced to nothing but local constants. No plausible external influence,
               so the caller (python_rules.py) skips the finding entirely.

Known limitations (worth stating plainly rather than overselling precision):
- Control-flow insensitive: an `if` that reassigns a name is treated the same as code that
  always runs, so taint can leak across branches it wouldn't survive in real execution.
- Assumes conventional names: recognises `request`/`req` for Flask/Django-style objects.
  A request object assigned to an unusual name won't be recognised as a source.
- No cross-function/cross-module tracking: if function A receives tainted data and passes
  it to function B, B's own analysis starts fresh and only sees "parameter", not "source".
"""
from __future__ import annotations
import ast

NONE, PARAM, SOURCE = None, "param", "source"
_RANK = {NONE: 0, PARAM: 1, SOURCE: 2}


def _stronger(a, b):
    return a if _RANK[a] >= _RANK[b] else b


def dotted(n):
    if isinstance(n, ast.Name):
        return n.id
    if isinstance(n, ast.Attribute):
        d = dotted(n.value)
        return f"{d}.{n.attr}" if d else n.attr
    if isinstance(n, ast.Call):
        return dotted(n.func)
    return ""


_OBJS = ("request", "req")
_ATTRS = ("args", "form", "values", "cookies", "json", "data", "files", "GET", "POST",
          "META", "headers")
SOURCE_ATTR_PREFIXES = tuple(f"{o}.{a}" for o in _OBJS for a in _ATTRS)
SOURCE_CALL_NAMES = {"input", "os.environ.get", "os.getenv", "sys.stdin.read",
                     "sys.stdin.readline", "sys.argv"}
PASSTHROUGH_METHODS = {"strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize",
                       "encode", "decode", "replace", "format", "join", "split", "get"}
PASSTHROUGH_FUNCS = {"str", "int", "float", "repr", "bytes"}


def _matches_prefix(name):
    return any(name == p or name.startswith(p + ".") for p in SOURCE_ATTR_PREFIXES)


class TaintScope:
    """Taint state for one function body (or the module's top level)."""

    def __init__(self):
        self.kind = {}  # name -> NONE/PARAM/SOURCE

    def declare_param(self, name):
        self.kind[name] = PARAM

    def set(self, name, kind):
        self.kind[name] = kind

    def _is_source_node(self, node):
        if isinstance(node, (ast.Attribute, ast.Name)):
            return _matches_prefix(dotted(node))
        if isinstance(node, ast.Subscript):
            return _matches_prefix(dotted(node.value))
        if isinstance(node, ast.Call):
            cname = dotted(node.func)
            return _matches_prefix(cname) or cname in SOURCE_CALL_NAMES
        return False

    def kind_of(self, node):
        """Return NONE/PARAM/SOURCE for the value `node` could evaluate to."""
        if node is None:
            return NONE
        if self._is_source_node(node):
            return SOURCE
        if isinstance(node, ast.Name):
            return self.kind.get(node.id, NONE)
        if isinstance(node, ast.Constant):
            return NONE
        if isinstance(node, ast.JoinedStr):
            k = NONE
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    k = _stronger(k, self.kind_of(v.value))
            return k
        if isinstance(node, ast.BinOp):
            return _stronger(self.kind_of(node.left), self.kind_of(node.right))
        if isinstance(node, ast.BoolOp):
            k = NONE
            for v in node.values:
                k = _stronger(k, self.kind_of(v))
            return k
        if isinstance(node, ast.IfExp):
            return _stronger(self.kind_of(node.body), self.kind_of(node.orelse))
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            k = NONE
            for e in node.elts:
                k = _stronger(k, self.kind_of(e))
            return k
        if isinstance(node, ast.Subscript):
            return self.kind_of(node.value)
        if isinstance(node, ast.Attribute):
            return self.kind_of(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in PASSTHROUGH_METHODS:
                k = self.kind_of(node.func.value)
                for a in node.args:
                    k = _stronger(k, self.kind_of(a))
                return k
            fname = dotted(node.func)
            if fname in PASSTHROUGH_FUNCS:
                k = NONE
                for a in node.args:
                    k = _stronger(k, self.kind_of(a))
                return k
            # Unknown call: be conservative and still look at its arguments, so e.g.
            # some_helper(request.args.get('x')) isn't silently treated as untainted.
            k = NONE
            for a in node.args:
                k = _stronger(k, self.kind_of(a))
            return k
        return NONE

    def apply_assign(self, targets, value_node):
        k = self.kind_of(value_node)
        for t in targets:
            if isinstance(t, ast.Name):
                self.set(t.id, k)
            elif isinstance(t, (ast.Tuple, ast.List)):
                for elt in t.elts:
                    if isinstance(elt, ast.Name):
                        self.set(elt.id, k)  # approximation: same kind for every unpacked name


def is_pure_constant(node):
    """True only if `node` contains no variable/call at all -- a literal through and through.
    Used as a secondary signal alongside TaintScope.kind_of (which already returns NONE for
    this case too); kept separate so callers can distinguish "definitely a literal" from
    "a local variable we just couldn't trace to anything external" if they want to."""
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(is_pure_constant(v.value) if isinstance(v, ast.FormattedValue) else True
                  for v in node.values)
    if isinstance(node, ast.BinOp):
        return is_pure_constant(node.left) and is_pure_constant(node.right)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(is_pure_constant(e) for e in node.elts)
    return False


def params_of(fn_node):
    """All parameter names of a function/lambda, across positional, kw-only, *args, **kwargs."""
    a = fn_node.args
    names = [p.arg for p in a.posonlyargs] + [p.arg for p in a.args] + [p.arg for p in a.kwonlyargs]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return names
