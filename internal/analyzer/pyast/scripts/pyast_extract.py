#!/usr/bin/env python3
"""Extract crypto-relevant AST information from Python source files."""
import ast
import json
import sys

class CryptoVisitor(ast.NodeVisitor):
    def __init__(self):
        self.imports = []    # {"module": "...", "names": ["..."], "line": N}
        self.calls = []      # {"func": "...", "args": [...], "kwargs": {...}, "line": N}
        self.assignments = [] # {"target": "...", "value": "...", "line": N}

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({"module": alias.name, "alias": alias.asname or alias.name, "line": node.lineno})
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        for alias in node.names:
            self.imports.append({
                "module": f"{node.module}.{alias.name}" if node.module else alias.name,
                "alias": alias.asname or alias.name,
                "line": node.lineno,
                "from": node.module or ""
            })
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = self._get_call_name(node)
        if func_name:
            args = []
            for arg in node.args:
                args.append(self._get_value(arg))
            kwargs = {}
            for kw in node.keywords:
                if kw.arg:
                    kwargs[kw.arg] = self._get_value(kw.value)
            self.calls.append({"func": func_name, "args": args, "kwargs": kwargs, "line": node.lineno})
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            name = self._get_name(target)
            value = self._get_value(node.value)
            if name and value:
                self.assignments.append({"target": name, "value": value, "line": node.lineno})
        self.generic_visit(node)

    def _get_call_name(self, node):
        if isinstance(node.func, ast.Attribute):
            obj = self._get_name(node.func.value)
            if obj:
                return f"{obj}.{node.func.attr}"
            return node.func.attr
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _get_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            obj = self._get_name(node.value)
            if obj:
                return f"{obj}.{node.attr}"
            return node.attr
        elif isinstance(node, ast.Subscript):
            return self._get_name(node.value)
        return None

    def _get_value(self, node):
        if isinstance(node, ast.Constant):
            if isinstance(node.value, bytes):
                return node.value.decode("utf-8", errors="replace")
            return node.value
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_name(node)
        elif isinstance(node, ast.Call):
            return self._get_call_name(node)
        elif isinstance(node, ast.List):
            return [self._get_value(e) for e in node.elts]
        elif isinstance(node, ast.Num):  # Python 3.7 compat
            return node.n
        elif isinstance(node, ast.Str):  # Python 3.7 compat
            return node.s
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: pyast_extract.py <file.py>"}))
        sys.exit(1)
    try:
        with open(sys.argv[1], "r") as f:
            source = f.read()
        tree = ast.parse(source, filename=sys.argv[1])
        visitor = CryptoVisitor()
        visitor.visit(tree)
        print(json.dumps({
            "imports": visitor.imports,
            "calls": visitor.calls,
            "assignments": visitor.assignments,
        }))
    except SyntaxError as e:
        print(json.dumps({"error": f"syntax error: {e}"}))
        sys.exit(0)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
