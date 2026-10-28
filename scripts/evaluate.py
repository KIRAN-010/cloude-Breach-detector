"""Run labeled offline evaluation; reports rule occurrences, not production accuracy."""
import json
from collections import Counter
from pathlib import Path
from breach_detector.engine import Engine

root = Path(__file__).resolve().parents[1]
scenarios = json.loads((root/'fixtures/scenarios.json').read_text())
tp = fp = fn = 0
rows = []
for s in scenarios:
    engine = Engine()
    actual = []
    for event in s['events']:
        result = engine.process(event, received_at='2026-10-28T10:10:00Z', context=s.get('context'))
        actual += list(filter(None, result['cbd']['matches'].split(',')))
    a, e = Counter(actual), Counter(s['expected'])
    tp += sum((a & e).values())
    fp += sum((a - e).values())
    fn += sum((e - a).values())
    rows.append(dict(scenario=s['name'], expected=s['expected'], actual=actual, passed=actual == s['expected']))
    engine.close()
report = dict(dataset='synthetic-v0.1.0', scenarios=len(rows), events=sum(len(s['events']) for s in scenarios),
              true_positives=tp, false_positives=fp, false_negatives=fn,
              precision=tp/(tp+fp) if tp+fp else None, recall=tp/(tp+fn) if tp+fn else None,
              limitations='Small hand-authored fixture set; Python semantics only. Does not establish Wazuh behavior or real-world accuracy.', results=rows)
(root/'evidence/evaluation.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k != 'results'}, indent=2))
raise SystemExit(0 if all(r['passed'] for r in rows) else 1)
