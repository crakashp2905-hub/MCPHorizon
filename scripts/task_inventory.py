#!/usr/bin/env python3
"""Safe bootstrap for MCPHorizon master-spec task inventory.

This does NOT launch autonomous agents, infer dependencies, or mark tasks complete.
It gives future P75+ orchestrators a checked immutable-ID inventory using SQLite WAL.
Stdlib only. The service/recovery/verification code in P76+ is not yet implemented.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sqlite3
from pathlib import Path

TASK_RE = re.compile(r'^- \[ \] \*\*(P\d{1,2}-\d{2})\*\*\s*(.+)$', re.MULTILINE)
EXPECTED = 1686


def parse(text: str) -> list[tuple[str, int, str, str]]:
    matches = TASK_RE.findall(text)
    ids = [item[0] for item in matches]
    if len(ids) != len(set(ids)):
        raise ValueError(f'duplicate task IDs found: {len(ids) - len(set(ids))}')
    if len(ids) != EXPECTED:
        raise ValueError(f'expected {EXPECTED} tasks, found {len(ids)}; verify specification version')
    phases = {int(item[1:item.find('-')]) for item in ids}
    if phases != set(range(95)):
        raise ValueError('missing/extra phase in original + bootstrap specification')
    for ph in sorted(phases):
        nums = sorted(int(task.split('-')[1]) for task in ids if task.startswith(f'P{ph}-'))
        if nums != list(range(1, len(nums) + 1)):
            raise ValueError(f'missing/invalid ordinal within phase P{ph}')
    return [(identifier, int(identifier[1:identifier.find('-')]), description,
             hashlib.sha256((identifier + '\n' + description).encode()).hexdigest())
            for identifier, description in matches]


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('''CREATE TABLE IF NOT EXISTS tasks(
        id TEXT PRIMARY KEY, phase INTEGER NOT NULL, description TEXT NOT NULL,
        spec_task_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK(status IN ('PENDING','READY','LEASED','RUNNING','VERIFYING','VERIFIED',
        'RETRY_WAIT','WAITING_EXTERNAL','NEEDS_APPROVAL','NEEDS_RECONCILIATION',
        'BLOCKED_SECURITY','REJECTED','NOT_APPLICABLE_APPROVED')))''')
    return db


def init(db_path: Path, spec_path: Path) -> dict:
    source = spec_path.read_text(encoding='utf-8')
    parsed = parse(source)
    spec_hash = hashlib.sha256(source.encode()).hexdigest()
    with connect(db_path) as db:
        old = db.execute("SELECT value FROM meta WHERE key='spec_sha256'").fetchone()
        if old and old[0] != spec_hash:
            raise ValueError('spec changed; refusing silent reinitialization. Reconcile and migrate explicitly.')
        db.executemany('INSERT OR IGNORE INTO tasks(id,phase,description,spec_task_hash) VALUES(?,?,?,?)', parsed)
        existing = db.execute('SELECT id,spec_task_hash FROM tasks').fetchall()
        if len(existing) != EXPECTED or dict(existing) != {x[0]: x[3] for x in parsed}:
            raise ValueError('database has unexpected tasks or hashes; abort and investigate')
        db.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('spec_sha256',?)",(spec_hash,))
    return {'spec_sha256': spec_hash, 'tasks': len(parsed), 'db': str(db_path)}


def status(db_path: Path) -> dict:
    if not db_path.exists():
        raise ValueError('ledger not initialized; run init first')
    with connect(db_path) as db:
        rows = db.execute('SELECT status,COUNT(*) FROM tasks GROUP BY status').fetchall()
        meta = db.execute("SELECT value FROM meta WHERE key='spec_sha256'").fetchone()
    return {'spec_sha256': meta[0] if meta else None,
            'total': sum(num for _,num in rows), 'statuses': dict(rows),
            'note':'Inventory bootstrap only; a durable verifier, DAG and worker scheduler must be implemented in P75–P82.'}


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['init','status'])
    p.add_argument('--db',type=Path,default=Path('.mcphorizon/ledger.sqlite3'))
    p.add_argument('--spec',type=Path,default=Path('docs/MCPHORIZON_2_0_MASTER_SPEC.md'))
    a=p.parse_args()
    try:
        result=init(a.db,a.spec) if a.command=='init' else status(a.db)
        print(json.dumps(result,indent=2))
    except (ValueError,FileNotFoundError,sqlite3.Error) as exc:
        p.exit(2,f'ERROR: {exc}\n')

if __name__=='__main__': main()
