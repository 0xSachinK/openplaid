"""Operator CLI: JSON output, no interactive secrets, no scheduler or payout implementation."""
import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from .common import Rejected, strict_json
from .control import Ledger


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=".local/verification/ledger.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("pause")
    create = commands.add_parser("create-ticket")
    for name in ("award", "contributor", "revision", "capability"):
        create.add_argument(f"--{name}", required=True)
    create.add_argument("--expires", required=True, type=int)
    judge = commands.add_parser("judge")
    for name in ("ticket", "actor", "decision", "evidence-digest"):
        judge.add_argument(f"--{name}", required=True)
    judge.add_argument("--version", type=int, required=True)
    reserve = commands.add_parser("reserve")
    reserve.add_argument("--ticket", required=True)
    reserve.add_argument("--request-key", required=True)
    reserve.add_argument("--maximum-micro-usd", type=int, required=True)
    reserve.add_argument("--binding-file", required=True)
    expense = commands.add_parser("reserve-expense")
    expense.add_argument("--ref", required=True)
    expense.add_argument("--maximum-micro-usd", type=int, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    path = Path(args.db)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = Ledger(path)
    result = None
    if args.command == "status":
        result = db.status()
    elif args.command == "pause":
        db.pause()
        result = db.status()
    elif args.command == "create-ticket":
        result = db.create_ticket(award=args.award, contributor=args.contributor, revision=args.revision,
                                  capability=args.capability, expires=args.expires)
    elif args.command == "judge":
        result = db.judge(args.ticket, actor=args.actor, version=args.version,
                         decision=args.decision, evidence_digest=args.evidence_digest)
    elif args.command == "reserve":
        result = db.reserve(args.ticket, args.request_key,
                            strict_json(Path(args.binding_file).read_bytes()), args.maximum_micro_usd)
    elif args.command == "reserve-expense":
        db.reserve_external(args.ref, args.maximum_micro_usd)
        result = db.status()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Rejected as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(1)
    except (OSError, ValueError, sqlite3.Error):
        print(json.dumps({"error": "operation_failed"}))
        sys.exit(1)
