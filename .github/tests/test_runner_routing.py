"""Prevent jobs silently falling back to VM or hosted runners during ARC migration."""

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
POOL = "constellation-runners"
HOSTED = {}


class RunnerRoutingTest(unittest.TestCase):
    def test_every_job_targets_its_declared_runner(self):
        checked = 0
        for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
            workflow = yaml.safe_load(path.read_text())
            for name, job in workflow.get("jobs", {}).items():
                key = f"{path.name}:{name}"
                expected = HOSTED.get(key, POOL)
                with self.subTest(job=key):
                    if "uses" in job:
                        target = job.get("with", {}).get("runs_on")
                        self.assertIsNotNone(
                            target, "Reusable workflows must receive runs_on"
                        )
                        self.assertEqual(json.loads(target), expected)
                    elif job["runs-on"] == "${{ fromJSON(inputs.runs_on) }}":
                        default = workflow[True]["workflow_call"]["inputs"]["runs_on"][
                            "default"
                        ]
                        self.assertEqual(json.loads(default), expected)
                    else:
                        self.assertEqual(job["runs-on"], expected)
                checked += 1
        self.assertGreater(checked, 0)

    def test_pod_smoke_exercises_isolation_and_artifact_handoff(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/forge-pod-smoke.yml").read_text()
        )
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        jobs = workflow["jobs"]
        self.assertEqual(jobs["handoff"]["needs"], "probe")
        for job in jobs.values():
            self.assertEqual(job["timeout-minutes"], 10)
            self.assertNotIn("secrets", job)
        probe = "\n".join(step.get("run", "") for step in jobs["probe"]["steps"])
        self.assertIn("bwrap --unshare-user --unshare-pid --unshare-net", probe)
        self.assertIn("test_runner_routing.py", probe)
        self.assertTrue(
            any(
                "actions/upload-artifact@" in step.get("uses", "")
                for step in jobs["probe"]["steps"]
            )
        )
        self.assertTrue(
            any(
                "actions/download-artifact@" in step.get("uses", "")
                for step in jobs["handoff"]["steps"]
            )
        )


if __name__ == "__main__":
    unittest.main()
