#!/usr/bin/env python3
"""Hash and index the owned algorithm surface; this is not a semantic proof."""
import argparse
import ast
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--verclo-source', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args()
    rows=[]
    for component in ('HTGLThesis','PaEForge'):
        root=a.verclo_source if component=='HTGLThesis' and a.verclo_source else a.project/component
        for path in sorted((root/'src').rglob('*.py')):
            if '__pycache__' in path.parts or any(x.endswith('.egg-info') for x in path.parts): continue
            source=path.read_text(); tree=ast.parse(source); calls=[]
            for node in ast.walk(tree):
                if isinstance(node,ast.Call):
                    name=ast.unparse(node.func)
                    if any(term in name.lower() for term in ('hash','sha256','sign','verify','sort','random','rng','heap','deque','executor','bootstrap','wasserstein','sample','closure','quorum','merkle','estimate')):
                        calls.append({'line':node.lineno,'call':name})
            rows.append(dict(path=f'{component}/'+path.relative_to(root).as_posix(),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                lines=len(source.splitlines()),functions=sum(isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) for n in ast.walk(tree)),
                loops=sum(isinstance(n,(ast.For,ast.While,ast.AsyncFor)) for n in ast.walk(tree)),algorithm_call_hints=calls))
    report=dict(format='algorithm-surface-inventory.v1',scope='All owned Python source modules in the two consumer src trees; excludes dependencies, generated artifacts, frozen releases and tests. AST call hints guide manual review and do not prove absence of other algorithms.',
        modules=len(rows),functions=sum(r['functions'] for r in rows),lines=sum(r['lines'] for r in rows),
        components={c:sum(r['path'].startswith(c+'/') for r in rows) for c in ('HTGLThesis','PaEForge')},files=rows)
    with a.output.open('x') as f: json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:v for k,v in report.items() if k!='files'}))

if __name__=='__main__':main()
