#!/usr/bin/env python3
"""Create a NEW PUBLIC GitHub repository from a source-only allowlist using authenticated gh.

Never updates an existing repository, modifies global Git configuration, or includes runtime
workspaces/credentials. Review --dry-run first. Requires git and GitHub CLI on your machine.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
DIRECTORIES=('src','tests','scripts','docs','examples','.github')
ROOT_FILES=('README.md','LICENSE','SECURITY.md','CONTRIBUTING.md','CHANGELOG.md',
            'pyproject.toml','Dockerfile','compose.yaml','.gitignore','.dockerignore','MANIFEST.in')
SUFFIXES={'.py','.md','.toml','.yaml','.yml','.js','.css','.html','.txt','.json','.csv','.xml','.log','.sarif','.lyrdb','.png','.svg'}
SECRET_PATTERNS=[re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
                 re.compile(rb'\bghp_[A-Za-z0-9]{30,}\b'),
                 re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{30,}\b')]


def files() -> list[Path]:
    selected=[ROOT/name for name in ROOT_FILES if (ROOT/name).is_file()]
    for directory in DIRECTORIES:
        selected.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                        and p.suffix in SUFFIXES and not any(part == '__pycache__' or part.endswith('.egg-info') for part in p.parts))
    for p in selected:
        if p.is_symlink():
            raise ValueError(f'refusing a symlink: {p.relative_to(ROOT)}')
        if p.suffix!='.png' and any(pattern.search(p.read_bytes()) for pattern in SECRET_PATTERNS):
            raise ValueError(f'possible credential found; review before publishing: {p.relative_to(ROOT)}')
    return sorted(set(selected))


def run(command, cwd=None, capture=False):
    return subprocess.run(command,cwd=cwd,text=True,check=True,capture_output=capture)


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner',required=True)
    parser.add_argument('--name',default='OpenWaiver')
    parser.add_argument('--public',action='store_true',help='explicitly authorize PUBLIC source-code publication')
    parser.add_argument('--dry-run',action='store_true',help='print only the source allowlist and hashes; no network/writes')
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9-]+',args.owner) or not re.fullmatch(r'[A-Za-z0-9_.-]+',args.name):
        parser.error('invalid GitHub owner/repository name')
    selected=files()
    manifest={'repository':f'{args.owner}/{args.name}','visibility':'public','files':[
        {'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
        for p in selected]}
    if args.dry_run:
        print(json.dumps(manifest,indent=2));return 0
    if not args.public:
        parser.error('--public is required; this operation publishes source code to everyone')
    if not shutil.which('git') or not shutil.which('gh'):
        raise ValueError('Install Git and GitHub CLI, then run gh auth login on your machine. Do not paste tokens into chat.')
    run(['gh','auth','status'],capture=True)
    login=run(['gh','api','user','--jq','.login'],capture=True).stdout.strip()
    if login.lower()!=args.owner.lower():
        raise ValueError('Authenticated gh account does not match --owner; no repository was created')
    full=f'{args.owner}/{args.name}'
    existing=subprocess.run(['gh','repo','view',full,'--json','name'],text=True,capture_output=True)
    if existing.returncode==0:
        raise ValueError('Repository already exists. This create-only script will not overwrite or change its visibility.')
    with tempfile.TemporaryDirectory(prefix='openwaiver-public-source-') as temp:
        stage=Path(temp)
        for source in selected:
            target=stage/source.relative_to(ROOT)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,target)
        run(['git','init','-b','main'],cwd=stage)
        run(['git','add','--all'],cwd=stage)
        run(['git','-c','user.name=OpenWaiver contributors','-c',f'user.email={args.owner}@users.noreply.github.com',
             'commit','-m','Initial OpenWaiver 0.1.0 source release'],cwd=stage)
        run(['gh','repo','create',full,'--public','--source',str(stage),'--remote','origin','--push',
             '--description','Local-first cross-tool EDA waiver lifecycle management with fail-closed review and release gates'],cwd=stage)
        verified=json.loads(run(['gh','repo','view',full,'--json','url,isPrivate'],capture=True).stdout)
        if verified['isPrivate']:
            raise ValueError('Unexpected repository visibility; inspect GitHub before proceeding')
        print(json.dumps({'published':True,'public':True,'url':verified['url'],'files':len(selected)},indent=2))
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (ValueError,OSError,subprocess.CalledProcessError) as exc:
        print(f'publish: {exc}',file=sys.stderr)
        raise SystemExit(2)
