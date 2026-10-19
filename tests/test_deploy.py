import base64
import json
import re
import unittest
from unittest.mock import patch

import yaml

import deploy as d


class FakeGitHub:
    def __init__(self, private=False, unrelated=False):
        self.private = private
        self.unrelated = unrelated
        self.calls = []

    def request(self, method, path, payload=None, **kwargs):
        self.calls.append((method, path, payload))
        if path == "/user":
            return {"login": "test-owner"}
        if path.endswith("/onrecord-dataset-updater"):
            return {"id": 123, "private": self.private, "default_branch": "main"}
        if "/contents/" in path:
            return None if self.unrelated else {"content": base64.b64encode(json.dumps(d.MARKER).encode()).decode()}
        if "/git/ref/" in path:
            return {"object": {"sha": "a" * 40}}
        if method == "GET" and "/git/commits/" in path:
            return {"tree": {"sha": "b" * 40}}
        if method == "GET" and path.endswith("/actions/workflows/refresh.yml"):
            return {"id": 1, "state": "active"}
        if path.endswith(("/git/blobs", "/git/trees", "/git/commits")):
            return {"sha": "c" * 40}
        return None


class DeploymentTests(unittest.TestCase):
    def test_actions_secret_is_sealed_for_github_and_never_sent_as_plaintext(self):
        from nacl.public import PrivateKey, SealedBox
        private = PrivateKey.generate()

        class Secrets:
            payload = None

            def request(self, method, path, payload=None):
                if method == "GET":
                    return {"key_id": "example", "key": base64.b64encode(bytes(private.public_key)).decode()}
                self.payload = payload

        github = Secrets()
        d.set_hf_secret(github, "example/repo", "example-token")
        ciphertext = base64.b64decode(github.payload["encrypted_value"])
        self.assertEqual(SealedBox(private).decrypt(ciphertext), b"example-token")
        self.assertTrue("example-token" not in json.dumps(github.payload))

    def test_token_length_boundaries(self):
        from nacl.public import PrivateKey

        class Secrets:
            def request(self, method, path, payload=None):
                return {"key_id": "example", "key": base64.b64encode(bytes(PrivateKey.generate().public_key)).decode()}

        for size in (4095, 4096, 4097):
            if size == 4097:
                with self.assertRaises(d.DeploymentError):
                    d.set_hf_secret(Secrets(), "example/repo", "x" * size)
            else:
                d.set_hf_secret(Secrets(), "example/repo", "x" * size)

    def test_export_contains_only_standalone_public_material(self):
        files = d.export_files()
        self.assertEqual(len([p for p in files if p.startswith("baselines/")]), 9)
        self.assertTrue(all(not p.startswith(("review/", ".run/", ".venv/", "investigations/", "onrecord-studio/")) for p in files))
        self.assertIn(".github/workflows/refresh.yml", files)
        pattern = re.compile(rb"\b(?:hf|gh[pousr])_[A-Za-z0-9]{20,}\b")
        for path, content in files.items():
            self.assertTrue(pattern.search(content) is None, f"Unexpected credential pattern in {path}")

    def test_workflow_respects_no_hosting_charge_constraints(self):
        files = d.export_files()
        raw = files[".github/workflows/refresh.yml"].decode()
        workflow = yaml.safe_load(raw)
        for job in workflow["jobs"].values():
            self.assertEqual(job["runs-on"], "ubuntu-latest")
            self.assertIn("github.event.repository.private == false", job["if"])
            self.assertLessEqual(job["timeout-minutes"], 20)
        self.assertNotIn("upload-artifact", raw)
        self.assertNotIn("actions/cache", raw)
        self.assertIn("enable-cache: false", raw)

    def test_private_repository_is_refused_before_any_mutation(self):
        github = FakeGitHub(private=True)
        with self.assertRaises(d.DeploymentError):
            d.deploy(github, {"README.md": b"example"}, "secret", set_secret=lambda *args: self.fail("secret must not be set"))
        self.assertTrue(all(method == "GET" for method, _, _ in github.calls))

    def test_unrelated_repository_is_not_overwritten(self):
        github = FakeGitHub(unrelated=True)
        with self.assertRaises(d.DeploymentError):
            d.deploy(github, {"README.md": b"example"}, "secret", set_secret=lambda *args: None)
        self.assertTrue(all(method == "GET" for method, _, _ in github.calls))

    def test_interrupted_own_creation_can_resume_only_for_its_recorded_repository_id(self):
        github = FakeGitHub(unrelated=True)
        state = {"repository": "test-owner/onrecord-dataset-updater", "repository_id": 123}
        result = d.deploy(github, {"README.md": b"example"}, "secret", set_secret=lambda *args: None, state=state)
        self.assertEqual(result["repository"], state["repository"])
        state["repository_id"] = 124
        with self.assertRaises(d.DeploymentError):
            d.deploy(FakeGitHub(unrelated=True), {}, "secret", set_secret=lambda *args: None, state=state)

    def test_deployment_has_no_billing_calls_and_does_not_force_push(self):
        github = FakeGitHub()
        secrets = []
        result = d.deploy(github, {"README.md": b"example"}, "secret", set_secret=lambda *args: secrets.append(args))
        self.assertEqual(result["repository"], "test-owner/onrecord-dataset-updater")
        self.assertEqual(secrets, [(result["repository"], "secret")])
        ref_update = next(payload for method, path, payload in github.calls if method == "PATCH")
        self.assertFalse(ref_update["force"])
        self.assertTrue(all("billing" not in path and "onrecord-studio" not in path for _, path, _ in github.calls))
        self.assertTrue(github.calls[-1][1].endswith("/dispatches"))

    def test_first_workflow_registration_can_be_delayed(self):
        class Delayed(FakeGitHub):
            attempts = 0

            def request(self, method, path, payload=None, **kwargs):
                if method == "GET" and path.endswith("/actions/workflows/refresh.yml"):
                    self.attempts += 1
                    if self.attempts == 1:
                        return None
                return super().request(method, path, payload, **kwargs)

        github = Delayed()
        with patch.object(d.time, "sleep") as sleep:
            d.deploy(github, {"README.md": b"example"}, "secret", set_secret=lambda *args: None)
        self.assertEqual(github.attempts, 2)
        sleep.assert_called_once_with(2)


if __name__ == "__main__":
    unittest.main()
