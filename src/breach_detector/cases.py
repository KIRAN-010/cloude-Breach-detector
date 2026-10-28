"""Local structured cases. Filesystem permissions are the authorization boundary."""
from copy import deepcopy
from datetime import datetime, timezone
import uuid

STATES = ['new', 'triaged', 'investigating', 'contained', 'resolved', 'closed']


def create(title, severity, owner, alert_ids):
    if severity not in ('low', 'medium', 'high', 'critical') or not title or not owner:
        raise ValueError('title, valid severity and owner required')
    now = datetime.now(timezone.utc).isoformat()
    return dict(case_id=str(uuid.uuid4()), title=title, severity=severity, status='new',
                owner=owner, created_at=now, updated_at=now, alert_ids=list(alert_ids),
                evidence=[], timeline=[], notes=[], response_actions=[], closure_reason=None,
                history=[dict(actor=owner, at=now, action='created')])


def transition(case, target, actor, reason):
    if target not in STATES or not actor or not reason.strip():
        raise ValueError('known status, actor and reason are required')
    current = case['status']
    allowed = (STATES.index(target) == STATES.index(current) + 1 or
               (target == 'closed' and reason.startswith('false-positive:')) or
               (current == 'closed' and target == 'investigating'))
    if not allowed:
        raise ValueError('invalid transition')
    result = deepcopy(case)
    now = datetime.now(timezone.utc).isoformat()
    result['status'] = target
    result['updated_at'] = now
    result['history'].append(dict(actor=actor, at=now, previous=current, status=target, reason=reason))
    if target == 'closed':
        result['closure_reason'] = reason
    return result


def response_dry_run(account, allowed_account, target, action, evidence, lab_tags):
    if account != allowed_account or lab_tags.get('Project') != 'cloude-breach-detection':
        raise ValueError('target outside lab scope')
    if action not in ('disable_access_key', 'remove_ingress_rule', 'restore_public_access_block'):
        raise ValueError('action not allowed')
    if not target or not evidence:
        raise ValueError('specific target and evidence required')
    return dict(mode='recommendation-only', executable=False, account=account,
                target=target, action=action, evidence=evidence,
                required_checks=['Capture previous state', 'Check dependencies',
                                 'Obtain human approval', 'Re-read target and verify lab scope'],
                warning='No AWS mutation is implemented by this tool.')
