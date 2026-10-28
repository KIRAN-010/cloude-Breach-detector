"""Deterministic CloudTrail enrichment/replay with persistent deduplication.

The optional worker emits context for native Wazuh rules. It is a separate
integration from Wazuh's supported AWS S3 collector; see docs/architecture.md.
"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from urllib.parse import unquote

VERSION = '0.1.0'


def timestamp(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('timestamp must include a timezone')
    return dt.timestamp()


def policy_document(value):
    if isinstance(value, str):
        value = json.loads(unquote(value))
    if not isinstance(value, dict):
        raise ValueError('policy must be an object')
    return value


def high_privilege(value):
    doc = policy_document(value)
    statements = doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    for s in statements:
        actions = s.get('Action', [])
        resources = s.get('Resource', [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if s.get('Effect') == 'Allow' and '*' in resources and any(
            a.lower() in ('*', 'iam:*') for a in actions
        ):
            return True
    return False


def normalize(event, source, received_at):
    if not isinstance(event, dict):
        raise ValueError('event must be an object')
    for field in ('eventID', 'eventTime', 'eventName', 'eventSource', 'recipientAccountId'):
        if not isinstance(event.get(field), str) or not event[field]:
            raise ValueError(f'missing or invalid {field}')
    ts = timestamp(event['eventTime'])
    identity = event.get('userIdentity') or {}
    if not isinstance(identity, dict):
        raise ValueError('userIdentity must be an object')
    params = event.get('requestParameters') or {}
    if not isinstance(params, dict):
        raise ValueError('requestParameters must be an object')
    response = event.get('responseElements') or {}
    if not isinstance(response, dict):
        raise ValueError('responseElements must be an object')
    actor = identity.get('arn') or identity.get('principalId') or 'unknown'
    return {
        'event_id': event['eventID'], 'event_time': event['eventTime'], 'ts': ts,
        'account': event['recipientAccountId'], 'region': event.get('awsRegion', 'unknown'),
        'name': event['eventName'], 'service': event['eventSource'],
        'actor': actor, 'identity_type': identity.get('type', 'unknown'),
        'username': identity.get('userName'), 'source_ip': event.get('sourceIPAddress', 'unknown'),
        'resource': params.get('bucketName') or params.get('userName') or params.get('roleName') or params.get('trailName') or params.get('name') or 'unknown',
        'failed': bool(event.get('errorCode')) or response.get('ConsoleLogin') == 'Failure',
        'error': event.get('errorCode'), 'params': params, 'response': response,
        'source_reference': source, 'received_at': received_at,
        'late': timestamp(received_at) - ts > 900,
        'service_context': bool(identity.get('invokedBy')),
    }


class Engine:
    def __init__(self, database=':memory:'):
        self.db = sqlite3.connect(database)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS events (account TEXT, id TEXT, ts REAL, actor TEXT, ip TEXT, name TEXT, failed INTEGER, PRIMARY KEY(account,id))')
        self.db.execute('CREATE TABLE IF NOT EXISTS results (account TEXT, id TEXT, result TEXT, PRIMARY KEY(account,id))')
        self.metrics = {'processed': 0, 'duplicates': 0, 'parse_failures': 0, 'late': 0}

    def process(self, event, source='fixture://unknown', received_at=None, context=None):
        received_at = received_at or datetime.now(timezone.utc).isoformat()
        context = context or {}
        try:
            e = normalize(event, source, received_at)
        except (ValueError, TypeError, AttributeError) as exc:
            self.metrics['parse_failures'] += 1
            return {'error': str(exc), 'source_reference': source}
        if self.db.execute('SELECT 1 FROM events WHERE account=? AND id=?', (e['account'], e['event_id'])).fetchone():
            self.metrics['duplicates'] += 1
            return None
        matches, missing = [], []
        p, name = e['params'], e['name']
        if not e['failed']:
            if e['identity_type'] == 'Root' and not e['service_context']:
                matches.append('D01')
            if name == 'ConsoleLogin' and e['response'].get('ConsoleLogin') == 'Success' and e['actor'] != 'unknown' and not e['late']:
                count = self.db.execute('SELECT count(*) FROM events WHERE account=? AND actor=? AND ip=? AND name=? AND failed=1 AND ts BETWEEN ? AND ?',
                    (e['account'], e['actor'], e['source_ip'], 'ConsoleLogin', e['ts'] - 600, e['ts'])).fetchone()[0]
                if count >= 5:
                    matches.append('D02')
            if name == 'CreateAccessKey':
                if not context.get('approved_provisioning', False) or (p.get('userName') and p['userName'] != e['username']):
                    matches.append('D03')
            if name in ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy', 'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy'):
                document = p.get('policyDocument') or context.get('policy_document')
                if p.get('policyArn', '').endswith(':policy/AdministratorAccess'):
                    matches.append('D04')
                elif document:
                    try:
                        if high_privilege(document):
                            matches.append('D04')
                    except (ValueError, TypeError, AttributeError):
                        missing.append('invalid policy document')
                else:
                    missing.append('managed policy version unavailable; privilege unknown')
            if name in ('StopLogging', 'DeleteTrail'):
                matches.append('D05')
            elif name == 'UpdateTrail':
                if p.get('isMultiRegionTrail') is False or p.get('includeGlobalServiceEvents') is False or p.get('enableLogFileValidation') is False:
                    matches.append('D05')
                elif not context.get('previous_trail'):
                    missing.append('prior trail state unavailable; destination changes need investigation')
            if name in ('PutBucketPolicy', 'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock', 'PutPublicAccessBlock', 'DeletePublicAccessBlock'):
                # Candidate alert, deliberately never a claim of effective public access.
                matches.append('D06')
                missing.append('effective exposure unknown; verify bucket and account blocks, policy and ACL')
        result = {'integration': 'cloud_breach_lab', 'cbd': {
            **{k: v for k, v in e.items() if k not in ('params', 'response', 'ts')},
            'rule_version': VERSION, 'matches': ','.join(matches), 'missing_evidence': '; '.join(missing),
            'outcome': 'failed' if e['failed'] else 'successful',
            'alert_ids': [hashlib.sha256(f"{e['account']}:{e['event_id']}:{r}:{VERSION}".encode()).hexdigest()[:24] for r in matches],
        }}
        # Atomic input + output persistence: retries cannot lose a committed alert.
        with self.db:
            self.db.execute('INSERT INTO events VALUES (?,?,?,?,?,?,?)', (e['account'], e['event_id'], e['ts'], e['actor'], e['source_ip'], name, e['failed']))
            self.db.execute('INSERT INTO results VALUES (?,?,?)', (e['account'], e['event_id'], json.dumps(result)))
        self.metrics['processed'] += 1
        self.metrics['late'] += int(e['late'])
        return result

    def results(self):
        return [json.loads(row[0]) for row in self.db.execute('SELECT result FROM results ORDER BY rowid')]

    def close(self):
        self.db.close()
