"""Offline structural checks; not a substitute for Terraform or wazuh-logtest."""
import json
import xml.etree.ElementTree as ET
from pathlib import Path
root = Path(__file__).resolve().parents[1]
ids = []
for path in (root/'detections').glob('*.xml'):
    doc = ET.parse(path)
    ids.extend(rule.attrib['id'] for rule in doc.findall('.//rule'))
assert len(ids) == len(set(ids)), 'duplicate Wazuh IDs'
for path in root.rglob('*.json'):
    if '.terraform' not in str(path):
        json.loads(path.read_text())
for path in (root/'dashboards').glob('*.ndjson'):
    for line in path.read_text().splitlines():
        json.loads(line)
print(f'Valid XML, {len(ids)} unique Wazuh rule IDs, and valid JSON artifacts')
