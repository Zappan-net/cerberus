import json
import os
import sqlite3
import sys
import unittest
from datetime import datetime, timezone
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))
from vhost_cve_monitor.state_store import StateStore
from vhost_cve_monitor.models import NotificationEvent
from vhost_cve_monitor.scanner import CerberusScanner


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.path = self.tmp.name + '/state.db'
        self.state = StateStore(self.path)
        self.payload = dict(vhost='app.example.net', stack='nodejs', ecosystem='npm',
                            dependency='sample', version='1', source_path='/srv/app/package-lock.json',
                            vuln_id='GHSA-aaaa-bbbb-cccc', severity='HIGH', aliases=[])

    def tearDown(self):
        self.tmp.cleanup()

    def test_decisions_persist_aliases_diffs_and_scan_ids(self):
        first_scan = self.state.begin_scan()
        self.assertTrue(self.state.should_alert('ghsa', self.payload))
        self.state.record_delivery([self.state.decision_ids["ghsa"]], "success", "test", "accepted")
        second_scan = self.state.begin_scan()
        updated = dict(self.payload, vuln_id='CVE-2026-12345', aliases=[self.payload['vuln_id']],
                       advisory_summary='New title', source_line=40)
        self.assertFalse(self.state.should_alert('cve', updated))
        self.assertTrue(self.state.should_alert('cve', dict(updated, severity='MEDIUM')))
        self.state.record_delivery([self.state.decision_ids["cve"]], "success", "test", "accepted")
        self.assertFalse(self.state.should_alert('cve', dict(updated, severity='MEDIUM')))
        self.assertTrue(self.state.should_alert('other', dict(updated, vhost='other.example.net')))
        rows = [r for r in StateStore(self.path).notification_history() if r['phase'] == 'decision']
        self.assertEqual(len(rows), 5)
        enrichment = rows[-2]
        self.assertEqual(enrichment['scan_id'], second_scan)
        self.assertEqual(rows[-1]['scan_id'], first_scan)
        self.assertEqual(enrichment['before'], self.payload)
        self.assertIn('vuln_id', enrichment['changed_fields'])
        self.assertEqual(enrichment['reason'], 'progressive_enrichment')
        self.assertEqual(rows[1]['reason'], 'unchanged')
        self.assertIn('severity', rows[2]['changed_fields'])
        self.assertEqual(len(self.state.notification_history(advisory='CVE-2026-12345')), 7)
        self.assertEqual(len(self.state.notification_history(vhost='other.example.net')), 1)

    def test_migration_is_empty_and_append_only(self):
        self.state.should_alert('old', self.payload)
        self.state.record_delivery([self.state.decision_ids["old"]], "success", "test", "accepted")
        with self.state._connect() as db:
            db.execute('DROP TABLE notification_journal')
        migrated = StateStore(self.path)
        self.assertEqual(migrated.notification_history(), [])
        self.assertFalse(migrated.should_alert('old', self.payload))
        with migrated._connect() as db:
            for sql in ('DELETE FROM notification_journal', "UPDATE notification_journal SET reason='changed'"):
                with self.assertRaises(sqlite3.IntegrityError):
                    db.execute(sql)
            self.assertEqual(db.execute('SELECT count(*) FROM alert_state').fetchone()[0], 1)

    def test_dry_run_does_not_consume_future_alert(self):
        self.state.begin_scan(dry_run=True)
        self.assertTrue(self.state.should_alert('one', self.payload))
        self.assertEqual(self.state.notification_history()[0]['dry_run'], 1)
        self.state.begin_scan()
        self.assertTrue(self.state.should_alert('one', self.payload))

    def test_delivery_phases_reference_decision_and_never_log_exception_secrets(self):
        self.state.should_alert('one', self.payload)
        scanner = CerberusScanner.__new__(CerberusScanner)
        scanner.state, scanner.dry_run, scanner.mailer = self.state, False, Mock()
        event = NotificationEvent(fingerprint='one', subject='test', body='test', category='vulnerability', metadata=self.payload, created_at=datetime.now(timezone.utc))
        scanner._send_notification(event)
        rows = self.state.notification_history()
        self.assertEqual([row['phase'] for row in rows], ['success', 'attempt', 'decision'])
        self.assertEqual(rows[0]['notification_id'], rows[1]['notification_id'])
        self.assertEqual(rows[0]['decision_id'], rows[2]['id'])
        scanner.mailer.send.side_effect = RuntimeError('secret-password')
        with self.assertRaises(RuntimeError):
            scanner._send_notification(event)
        self.assertEqual(self.state.notification_history()[0]['phase'], 'failure')
        self.assertNotIn('secret-password', json.dumps(self.state.notification_history()))
        scanner.dry_run = True
        scanner.mailer.send.side_effect = None
        scanner._send_notification(event)
        self.assertEqual(self.state.notification_history()[0]['phase'], 'dry_run')

    def test_digest_delivery_records_each_host_decision(self):
        for host in ('app.example.net', 'admin.example.net'):
            self.state.should_alert(host, dict(self.payload, vhost=host))
        scanner = CerberusScanner.__new__(CerberusScanner)
        scanner.state, scanner.dry_run, scanner.mailer = self.state, False, Mock()
        event = NotificationEvent(fingerprint='digest', subject='test', body='test', category='digest',
                                  metadata={'decision_ids': list(self.state.decision_ids.values())}, created_at=datetime.now(timezone.utc))
        scanner._send_notification(event)
        rows = self.state.notification_history()
        self.assertEqual(len(rows), 6)
        self.assertEqual({row['vhost'] for row in rows if row['phase'] == 'success'}, {'app.example.net', 'admin.example.net'})

    def test_failed_and_unattempted_alerts_retry_after_restart(self):
        hosts = ('first.example.net', 'failed.example.net', 'unsent.example.net')
        for host in hosts:
            self.assertTrue(self.state.should_alert(host, dict(self.payload, vhost=host)))
        self.state.record_delivery([self.state.decision_ids[hosts[0]]], 'success', 'one', 'accepted')
        self.state.record_delivery([self.state.decision_ids[hosts[1]]], 'failure', 'two', 'transport_error')
        restarted = StateStore(self.path)
        self.assertEqual([restarted.should_alert(h, dict(self.payload, vhost=h)) for h in hosts],
                         [False, True, True])

    def test_outbox_replays_original_batch_even_without_rediscovery(self):
        events = []
        for host in ("one", "two"):
            self.state.should_alert(host, dict(self.payload, vhost=host))
            events.append(NotificationEvent("vulnerability", host, host, "body", datetime.now(timezone.utc),
                                            {"decision_ids": [self.state.decision_ids[host]]}))
        queued = self.state.enqueue_notifications(events)
        scanner = CerberusScanner.__new__(CerberusScanner)
        scanner.state, scanner.dry_run, scanner.mailer = self.state, False, Mock()
        scanner.mailer.send.side_effect = RuntimeError("offline")
        with self.assertRaises(RuntimeError):
            scanner._send_notification(queued[0][1], queued[0][0])
        scanner.state = StateStore(self.path)
        scanner.mailer.send.side_effect = None
        pending = list(scanner.state.pending_notifications())
        self.assertEqual(pending, queued)
        for queue_id, event in pending:
            scanner._send_notification(event, queue_id)
        self.assertFalse(list(scanner.state.pending_notifications()))
        for host in ("one", "two"):
            self.assertFalse(scanner.state.should_alert(host, dict(self.payload, vhost=host)))
