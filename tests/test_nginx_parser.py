import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from vhost_cve_monitor.nginx_parser import parse_nginx_file


class NginxParserTestCase(unittest.TestCase):
    def test_parse_nginx_file_extracts_server_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            include_file = tmp_path / "php.conf"
            include_file.write_text("fastcgi_pass unix:/run/php/php8.2-fpm.sock;\n", encoding="utf-8")
            nginx_file = tmp_path / "site.conf"
            nginx_file.write_text(
                """
                server {
                    server_name example.org www.example.org;
                    root /home/webserv/example/current/public;
                    include php.conf;
                    location / {
                        proxy_pass http://127.0.0.1:3000;
                    }
                }
                """,
                encoding="utf-8",
            )

            vhosts = parse_nginx_file(nginx_file)

            self.assertEqual(len(vhosts), 1)
            vhost = vhosts[0]
            self.assertEqual(vhost.server_names, ["example.org", "www.example.org"])
            self.assertEqual(vhost.roots, ["/home/webserv/example/current/public"])
            self.assertIn("php.conf", vhost.includes)
            self.assertIn("http://127.0.0.1:3000", vhost.proxy_passes)
            self.assertIn("unix:/run/php/php8.2-fpm.sock", vhost.fastcgi_passes)

    def test_parse_nginx_file_marks_redirect_only_server(self) -> None:
        with TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            nginx_file = tmp_path / "redirect.conf"
            nginx_file.write_text(
                """
                server {
                    server_name ai-and-tech.com www.ai-and-tech.com;
                    return 302 https://link.me/ai.and.tech$request_uri;
                }
                """,
                encoding="utf-8",
            )

            vhosts = parse_nginx_file(nginx_file)

            self.assertEqual(len(vhosts), 1)
            vhost = vhosts[0]
            self.assertTrue(vhost.is_redirect_only)
            self.assertEqual(vhost.returns, ["302 https://link.me/ai.and.tech$request_uri"])


if __name__ == "__main__":
    unittest.main()
