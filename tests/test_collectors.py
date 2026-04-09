import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "src"))

from vhost_cve_monitor.collectors import collect_python_dependencies
from vhost_cve_monitor.models import StackMatch


class CollectorsTestCase(unittest.TestCase):
    def test_python_requirements_preserve_source_line(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "# comment\nrequests==2.32.5\nflask==3.0.2\n",
                encoding="utf-8",
            )
            stack = StackMatch(stack_name="python", confidence="high", reasons=["test"], root_path=str(root))

            dependencies, failures = collect_python_dependencies(stack, timeout=1)

            self.assertEqual(len(failures), 0)
            self.assertEqual(len(dependencies), 2)
            self.assertEqual(dependencies[0].name, "requests")
            self.assertEqual(dependencies[0].source_line, 2)
            self.assertEqual(dependencies[1].name, "flask")
            self.assertEqual(dependencies[1].source_line, 3)


if __name__ == "__main__":
    unittest.main()
