import json
import tempfile
import unittest
from pathlib import Path
from breach_detector.engine import Engine, high_privilege, normalize
from breach_detector.cases import create, transition, response_dry_run

ROOT = Path(__file__).resolve().parents[1]


def event(name='ListBuckets', **changes):
    value = dict(eventID='test-1', eventTime='2026-10-28T10:00:00Z', eventName=name,
                 eventSource='iam.amazonaws.com', recipientAccountId='111122223333',
                 userIdentity={'type': 'IAMUser', 'arn': 'arn:aws:iam::111122223333:user/alice', 'userName': 'alice'},
                 sourceIPAddress='192.0.2.10', requestParameters={}, responseElements={})
    value.update(changes)
    return value


class EngineTests(unittest.TestCase):
    def test_labeled_scenarios(self):
        scenarios = json.loads((ROOT/'fixtures/scenarios.json').read_text())
        for scenario in scenarios:
            with self.subTest(scenario=scenario['name']):
                engine = Engine()
                actual = []
                for e in scenario['events']:
                    result = engine.process(e, received_at='2026-10-28T10:10:00Z', context=scenario.get('context'))
                    actual.extend(filter(None, result['cbd']['matches'].split(',')))
                self.assertEqual(actual, scenario['expected'])
                engine.close()

    def test_missing_identity_does_not_crash(self):
        self.assertEqual(normalize(event(userIdentity=None), 'fixture', '2026-10-28T10:00:00Z')['actor'], 'unknown')

    def test_timezone_required(self):
        self.assertIn('error', Engine().process(event(eventTime='2026-10-28T10:00:00')))

    def test_invalid_record(self):
        self.assertIn('error', Engine().process({'eventID': 'bad'}))

    def test_persistent_dedup_and_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d)/'state.db')
            engine = Engine(path)
            engine.process(event('StopLogging'))
            engine.close()
            engine = Engine(path)
            self.assertIsNone(engine.process(event('StopLogging')))
            self.assertEqual(len(engine.results()), 1)
            self.assertEqual(engine.results()[0]['cbd']['matches'], 'D05')
            engine.close()

    def test_dedup_account_boundary(self):
        engine = Engine()
        self.assertIsNotNone(engine.process(event()))
        self.assertIsNotNone(engine.process(event(recipientAccountId='444455556666')))

    def test_late_record_searchable(self):
        result = Engine().process(event('StopLogging'), received_at='2026-10-28T11:00:00Z')
        self.assertTrue(result['cbd']['late'])
        self.assertEqual(result['cbd']['matches'], 'D05')

    def test_policy_deny_is_not_grant(self):
        self.assertFalse(high_privilege({'Statement': {'Effect': 'Deny', 'Action': '*', 'Resource': '*'}}))

    def test_encoded_policy(self):
        self.assertTrue(high_privilege('%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22*%22%2C%22Resource%22%3A%22*%22%7D%7D'))

    def test_unknown_managed_policy_visible(self):
        result = Engine().process(event('AttachUserPolicy', requestParameters={'policyArn': 'arn:aws:iam::111122223333:policy/Custom'}))
        self.assertIn('unknown', result['cbd']['missing_evidence'])
        self.assertEqual(result['cbd']['matches'], '')

    def test_source_reference_preserved(self):
        result = Engine().process(event(), source='s3://example/AWSLogs/a.json.gz#0')
        self.assertEqual(result['cbd']['source_reference'], 's3://example/AWSLogs/a.json.gz#0')


class CaseTests(unittest.TestCase):
    def test_normal_workflow(self):
        case = create('Test', 'high', 'analyst', ['alert-1'])
        for status in ('triaged', 'investigating', 'contained', 'resolved', 'closed'):
            case = transition(case, status, 'analyst', 'evidence reviewed')
        reopened = transition(case, 'investigating', 'analyst', 'new evidence')
        self.assertEqual(len(reopened['history']), 7)

    def test_reject_skip(self):
        with self.assertRaises(ValueError):
            transition(create('Test', 'high', 'a', []), 'closed', 'a', 'done')

    def test_false_positive_reason(self):
        case = transition(create('Test', 'low', 'a', []), 'closed', 'a', 'false-positive: approved maintenance')
        self.assertEqual(case['status'], 'closed')

    def test_reject_response_outside_scope(self):
        with self.assertRaises(ValueError):
            response_dry_run('wrong', 'lab', 'key-1', 'disable_access_key', ['a'], {'Project': 'cloude-breach-detection'})

    def test_response_never_executes(self):
        result = response_dry_run('lab', 'lab', 'key-1', 'disable_access_key', ['a'], {'Project': 'cloude-breach-detection'})
        self.assertFalse(result['executable'])


if __name__ == '__main__':
    unittest.main()
