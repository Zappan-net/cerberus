import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vhost_cve_monitor.systemd_codex import codex_home_path, install_dropin


class SystemdCodexTests(unittest.TestCase):
    def test_install_reinstall_and_disable_preserve_other_overrides(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = {"codex_analysis": {"enabled": True, "codex_home": str(root / 'account % home')}}
            target = root / 'systemd/vhost-cve-monitor.service.d'
            target.mkdir(parents=True)
            custom = target / 'local.conf'
            custom.write_text('[Service]\nNice=5\n')
            install_dropin(config, root / 'systemd')
            generated = target / '30-cerberus-codex.conf'
            content = generated.read_text()
            self.assertIn('account %% home"', content)
            self.assertNotIn('ProtectHome=false', content)
            install_dropin(config, root / 'systemd')
            self.assertEqual(generated.read_text(), content)
            config['codex_analysis']['enabled'] = False
            install_dropin(config, root / 'systemd')
            self.assertFalse(generated.exists())
            self.assertTrue(custom.exists())

    def test_default_home_matches_runtime(self):
        self.assertEqual(codex_home_path({}), Path('/var/lib/vhost-cve-monitor/codex'))

    def test_reject_broad_write_permission(self):
        with TemporaryDirectory() as tmp:
            for home in ('/', '/root', '/home', '/var/lib', '/usr/local'):
                with self.subTest(home=home), self.assertRaises(ValueError):
                    install_dropin({'codex_analysis': {'enabled': True, 'codex_home': home}}, Path(tmp))
