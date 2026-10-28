import json
from pathlib import Path
from breach_detector.cases import create, transition, response_dry_run
from breach_detector.engine import Engine

out = Path('output'); out.mkdir(exist_ok=True)
records = json.loads(Path('fixtures/demo.json').read_text())['Records']
engine = Engine()
alerts = [engine.process(e, received_at='2026-10-28T10:10:00Z') for e in records]
ids = [i for a in alerts for i in a['cbd']['alert_ids']]
case = create('SIMULATION: suspicious lab identity and logging activity', 'high', 'demo-analyst', ids)
case = transition(case, 'triaged', 'demo-analyst', 'Synthetic fixtures reviewed; no live incident')
case['response_actions'].append(response_dry_run('111122223333', '111122223333', 'SIMULATED-KEY', 'disable_access_key', ids, {'Project':'cloude-breach-detection'}))
(out/'demo-case.json').write_text(json.dumps(case, indent=2)+'\n')
print('Created output/demo-case.json; no cloud calls were made.')
