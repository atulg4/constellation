"""Keep the old provider/auth contract unchanged while adding runner selection."""

import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Byte hashes of upstream files at 2213ee45859eaea46a177fd3cdbafe812901b205.
EXPECTED = {
    "plan": "ebca55084a39eeaf23f87f24afe07b7ba7231380ef9824cf154ad8e4ddabff8e",
    "implement": "4e68280d25082c908111cdf698ee529bcd6531362e08f580df861e992af1be42",
}
INPUT = """      runs_on:
        description: JSON runner target for every job
        required: false
        type: string
        default: '\"constellation-runners\"'
"""


class CompatibilityTest(unittest.TestCase):
    def test_only_runner_selection_changes_from_the_pinned_upstream(self):
        for name, expected in EXPECTED.items():
            path = ROOT / f".github/workflows/forge-compat-{name}.yml"
            text = path.read_text().replace(INPUT, "")
            text = text.replace(
                "runs-on: ${{ fromJSON(inputs.runs_on) }}", "runs-on: ubuntu-latest"
            )
            self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), expected, name)


if __name__ == "__main__":
    unittest.main()
