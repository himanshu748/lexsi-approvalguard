from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONPATH": str(ROOT / "src")}


class CLITests(unittest.TestCase):
    def run_cli(self, *args: str) -> str:
        proc = subprocess.run([sys.executable, "-m", *args], cwd=ROOT, env=ENV, capture_output=True, text=True, check=True)
        return proc.stdout

    def test_end_to_end_cpu_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = root / "data"
            before = root / "before"
            after = root / "after"
            self.run_cli("approvalguard.generate", "--out-dir", str(data))
            self.run_cli("approvalguard.evaluate", "--dataset", str(data / "test.jsonl"), "--agent", "text_trust_heuristic", "--out-dir", str(before))
            self.run_cli("approvalguard.evaluate", "--dataset", str(data / "test.jsonl"), "--agent", "reference_policy", "--out-dir", str(after))
            self.run_cli("approvalguard.compare", "--before", str(before / "traces.jsonl"), "--after", str(after / "traces.jsonl"), "--out", str(root / "comparison.json"))
            report = json.loads((root / "comparison.json").read_text())
            self.assertEqual(report["case_count"], 120)
            self.assertEqual(report["metrics"]["attack_success_attempt_rate"]["after_minus_before"], -1)
            self.assertFalse((root / "data" / "train_model.bin").exists())


if __name__ == "__main__":
    unittest.main()
