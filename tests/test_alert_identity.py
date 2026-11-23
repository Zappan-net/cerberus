import os
import sys
import unittest
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))
from vhost_cve_monitor.state_store import StateStore


class AlertIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.store = StateStore(self.tmp.name + '/state.db')
        self.payload = dict(vhost='app.example.net', stack='nodejs', ecosystem='npm',
                            dependency='sample', version='1.0', source_path='/srv/app/package-lock.json',
                            source_line=10, vuln_id='GHSA-aaaa-bbbb-cccc', aliases=[], references=[],
                            advisory_summary='Original title', severity='HIGH', audit_scope='runtime')

    def tearDown(self):
        self.tmp.cleanup()

    def test_alias_title_line_and_fix_changes_do_not_notify(self):
        self.assertTrue(self.store.should_alert('ghsa', self.payload))
        enriched = dict(self.payload, vuln_id='CVE-2026-12345', advisory_summary='Revised title',
                        source_line=99, fixed_version='2.0', fix_is_semver_major=True,
                        references=['https://github.com/advisories/GHSA-aaaa-bbbb-cccc'])
        self.assertFalse(self.store.should_alert('cve', enriched))
        self.assertFalse(self.store.should_alert('ghsa', self.payload))
        self.assertFalse(self.store.should_alert('cve', enriched))

    def test_equal_titles_do_not_hide_distinct_advisories(self):
        self.assertTrue(self.store.should_alert('one', self.payload))
        self.assertTrue(self.store.should_alert('two', dict(self.payload, vuln_id='GHSA-dddd-eeee-ffff')))

    def test_new_host_and_severity_change_notify_once(self):
        self.store.should_alert('one', self.payload)
        other = dict(self.payload, vhost='admin.example.net')
        self.assertTrue(self.store.should_alert('other-host', other))
        self.assertFalse(self.store.should_alert('other-host', other))
        changed = dict(self.payload, vuln_id='CVE-2026-12345', aliases=[self.payload['vuln_id']], severity='CRITICAL')
        self.assertTrue(self.store.should_alert('cve', changed))
        self.assertFalse(self.store.should_alert('one', dict(self.payload, severity='CRITICAL')))
        # Returning to an old fingerprint must compare against the latest logical state.
        self.assertTrue(self.store.should_alert('one', self.payload))
        self.assertFalse(self.store.should_alert('cve', dict(changed, severity='HIGH')))

    def test_unknown_metadata_and_line_changes_do_not_resend(self):
        self.store.should_alert('one', self.payload)
        self.assertFalse(self.store.should_alert('one', dict(self.payload, source_line=40, severity='UNKNOWN')))
        self.assertFalse(self.store.should_alert('one', self.payload))

    def test_existing_database_without_history_is_correlated(self):
        self.store.should_alert('one', self.payload)
        with self.store._connect() as db:
            db.execute('DELETE FROM alert_history')
        self.assertFalse(self.store.should_alert('cve', dict(self.payload, vuln_id='CVE-2026-12345',
                        aliases=[self.payload['vuln_id']], advisory_summary='Changed')))

    def test_other_ecosystem_identifier_is_correlated(self):
        original = dict(self.payload, ecosystem='PyPI', stack='python', vuln_id='PYSEC-2026-123')
        self.assertTrue(self.store.should_alert('pysec', original))
        self.assertFalse(self.store.should_alert('cve', dict(original, vuln_id='CVE-2026-12345', aliases=['PYSEC-2026-123'])))

    def test_distinct_package_version_path_and_ecosystem_remain_new(self):
        self.store.should_alert('original', self.payload)
        for field, value in [('dependency', 'another'), ('version', '2.0'),
                             ('source_path', '/srv/other/package-lock.json'), ('ecosystem', 'PyPI')]:
            with self.subTest(field=field):
                self.assertTrue(self.store.should_alert(field, dict(self.payload, **{field: value})))
