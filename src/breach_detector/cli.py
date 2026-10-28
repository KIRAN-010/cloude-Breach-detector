import argparse
import json
from pathlib import Path
from .engine import Engine, timestamp


def main():
    parser = argparse.ArgumentParser(description='Replay sanitized CloudTrail fixtures; does not call AWS')
    parser.add_argument('input', type=Path)
    parser.add_argument('--database', default='replay.sqlite3')
    parser.add_argument('--output', type=Path, default=Path('replay.jsonl'))
    parser.add_argument('--received-at', help='ISO8601 collection time; fixture evaluation only')
    args = parser.parse_args()
    if args.input.stat().st_size > 10 * 1024 * 1024:
        parser.error('input exceeds 10 MiB; split into bounded batches')
    records = json.loads(args.input.read_text())['Records']
    if not isinstance(records, list):
        parser.error('Records must be an array')
    # A replay batch is sorted by event time; a streaming watermark is not implemented.
    valid, invalid = [], []
    for record in records:
        try:
            valid.append((timestamp(record['eventTime']), record))
        except (KeyError, TypeError, ValueError, AttributeError):
            invalid.append(record)
    engine = Engine(args.database)
    errors = []
    for record in [r for _, r in sorted(valid, key=lambda x: x[0])] + invalid:
        result = engine.process(record, f'fixture://{args.input.name}', args.received_at)
        if result and 'error' in result:
            errors.append(result)
    # Regenerate the complete output from durable results after a restart.
    temporary = args.output.with_suffix('.tmp')
    temporary.write_text(''.join(json.dumps(r) + '\n' for r in engine.results()))
    temporary.replace(args.output)
    args.output.with_suffix('.errors.json').write_text(json.dumps(errors, indent=2))
    args.output.with_suffix('.health.json').write_text(json.dumps(engine.metrics, indent=2))
    print(json.dumps(engine.metrics))
    engine.close()
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
