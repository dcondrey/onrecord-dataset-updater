import base64
import copy
import gzip
import json
import io
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import updater as u


ROOT = Path(__file__).resolve().parents[1]


class DataTests(unittest.TestCase):
    def test_actual_baseline_signatures_and_config(self):
        config = u.load_config(ROOT / "sources.json")
        self.assertEqual(len(config["packs"]), 9)
        for pack in config["packs"]:
            signed = json.loads((ROOT / pack["baseline_manifest"]).read_text())
            self.assertEqual(u.verify_baseline(signed, pack["repo"])["pack"], pack["repo"].split("onrecord-")[1])
            with self.subTest(pack=pack["repo"]):
                for field in ("manifestSha256", "manifestCanonicalBase64"):
                    bad = copy.deepcopy(signed)
                    bad[field] = "00"
                    with self.assertRaises(Exception):
                        u.verify_baseline(bad, pack["repo"])
                bad = copy.deepcopy(signed)
                bad["manifest"]["packVersion"] = "changed"
                with self.assertRaises(u.Refusal):
                    u.verify_baseline(bad, pack["repo"])

    def test_csv_preserves_text_and_records_provenance(self):
        raw = b'id,amount,note\n001,000.50,"first\nsecond"\n'
        item = {"table": "payments", "url": "https://source.test/data.csv", "baseline_rows": 1}
        data, count, headers = u.convert_csv(raw, ["id", "amount", "note"], item, "2026-10-19T00:00:00Z", 4096)
        value = json.loads(gzip.decompress(data))
        self.assertEqual(json.loads(value["record_json"]), {"id": "001", "amount": "000.50", "note": "first\nsecond"})
        self.assertEqual((count, headers, value["source_row"]), (1, ["id", "amount", "note"], 1))
        self.assertEqual(value["source_sha256"], u.digest(raw))

    def test_header_sample_can_end_inside_a_later_utf8_record(self):
        self.assertEqual(u.csv_header(b"id,note\n001,\xc3"), ["id", "note"])

    def test_row_drop_boundaries(self):
        item = {"table": "payments", "url": "https://source.test/data.csv", "baseline_rows": 100}
        for count in (79, 80, 81):
            raw = ("id\n" + "1\n" * count).encode()
            with self.subTest(count=count):
                if count == 79:
                    with self.assertRaises(u.Refusal):
                        u.convert_csv(raw, ["id"], item, "now", 100000)
                else:
                    self.assertEqual(u.convert_csv(raw, ["id"], item, "now", 100000)[1], count)

    def test_raw_schema_can_gain_columns_but_not_lose_them(self):
        item = {"table": "payments", "url": "https://source.test/data.csv", "baseline_rows": 0}
        self.assertEqual(u.convert_csv(b"id,new\n001,x\n", ["id"], item, "now", 4096)[1], 1)
        for raw in (b"new\nx\n", b"id,id\n1,2\n", b"id\n1,2\n", b"id\n", b'id,note\n1,"unterminated\n'):
            with self.subTest(raw=raw), self.assertRaises(u.Refusal):
                u.convert_csv(raw, ["id"], item, "now", 4096)

    def test_row_limit_boundaries(self):
        item = {"table": "payments", "url": "https://source.test/data.csv", "baseline_rows": 0}
        with patch.object(u, "MAX_ROWS", 3):
            for rows in (2, 3, 4):
                raw = ("id\n" + "1\n" * rows).encode()
                if rows == 4:
                    with self.assertRaises(u.Refusal):
                        u.convert_csv(raw, ["id"], item, "now", 4096)
                else:
                    self.assertEqual(u.convert_csv(raw, ["id"], item, "now", 4096)[1], rows)

    def test_unsafe_paths_and_urls_are_rejected(self):
        for path in ("../x", "a/../x", "/x", "a\\x", "a//b", ""):
            with self.subTest(path=path), self.assertRaises(u.Refusal):
                u.safe_path(path)
        for url in ("http://source.test/a", "https://source.test.evil/a", "https://user:pass@source.test/a", "https://source.test:123/a", "https://127.0.0.1/a"):
            with self.subTest(url=url), self.assertRaises(u.Refusal):
                u.allowed_url(url, ["source.test"])
        self.assertEqual(u.allowed_url("https://source.test/a", ["source.test"]), "https://source.test/a")

    def test_presigned_credentials_are_removed_from_public_provenance(self):
        result = u.public_url("https://source.test/a?X-Amz-Signature=secret&token=secret&year=2026")
        self.assertEqual(result, "https://source.test/a?year=2026")

    def test_year_discovery_keeps_working_after_first_new_year(self):
        source = {"url": "https://seshat.datasd.org/a/items_2026_datasd.csv", "year": 2026, "baseline_rows": 10}
        years = u.discover_years([source], 2029)
        self.assertEqual([s["year"] for s in years], [2026, 2027, 2028, 2029])
        self.assertEqual(len({s["url"] for s in years}), 4)
        self.assertTrue(all(s["baseline_rows"] == 0 for s in years[1:]))

    def test_card_preserves_doi_configs_body_and_has_one_managed_section(self):
        original = b"---\nlicense: pddl\ndoi: 10.57967/hf/example\nconfigs:\n- config_name: old\n  data_files: parquet/*.parquet\n---\nOriginal body.\n"
        entries = {"id": {"rows_path": "auto-updates/files/x/y/rows.jsonl.gz"}}
        first = u.update_card(original, entries)
        second = u.update_card(first, entries)
        self.assertEqual(first, second)
        metadata = yaml.safe_load(first.decode().split("---", 2)[1])
        self.assertEqual(metadata["doi"], "10.57967/hf/example")
        self.assertEqual(metadata["configs"][0], {"config_name": "old", "data_files": "parquet/*.parquet"})
        self.assertIn(b"Original body.", first)
        self.assertEqual(first.decode().count(u.START), 1)

    def test_unrelated_existing_configuration_is_preserved(self):
        with self.assertRaises(u.Refusal):
            u.update_card(b"---\nconfigs:\n- config_name: auto_updates\n  data_files: other.csv\n---\nBody\n", {"x": {"rows_path": "auto-updates/x.jsonl.gz"}})


class Response(io.BytesIO):
    def __init__(self, data, status=200, length=None):
        super().__init__(data)
        self.status = status
        self.headers = {} if length is None else {"Content-Length": str(length)}


class NetworkTests(unittest.TestCase):
    def test_response_size_boundaries_without_a_declared_length(self):
        for size in (7, 8, 9):
            network = u.Network(["source.test"])
            with patch.object(network.opener, "open", return_value=Response(b"x" * size)):
                if size == 9:
                    with self.assertRaises(u.Refusal):
                        network.read("https://source.test/a", 8)
                else:
                    self.assertEqual(len(network.read("https://source.test/a", 8)), size)

    def test_partial_and_truncated_source_downloads_are_rejected(self):
        for response in (Response(b"abc", status=206), Response(b"abc", length=4)):
            network = u.Network(["source.test"])
            with patch.object(network.opener, "open", return_value=response), self.assertRaises(u.Refusal):
                network.read("https://source.test/a", 8)

    def test_robots_unavailability_is_distinct_from_rate_limits_and_outages(self):
        for code in (403, 404, 429, 503):
            network = u.Network(["source.test"])
            with patch.object(network, "read", side_effect=u.Refusal(f"HTTP {code}")):
                if code in (403, 404):
                    network.check_robots("https://source.test/a")
                else:
                    with self.assertRaises(u.Refusal):
                        network.check_robots("https://source.test/a")

    def test_explicit_crawling_prohibition_is_honored(self):
        network = u.Network(["source.test"])
        with patch.object(network, "read", return_value=b"User-agent: *\nDisallow: /private\n"):
            with self.assertRaises(u.Refusal):
                network.check_robots("https://source.test/private/a")


class FakeNetwork:
    def __init__(self, data):
        self.data = data
        self.bytes_read = 0

    def read(self, url, limit, **kwargs):
        data = self.data[url]
        if len(data) > limit:
            raise u.Refusal("Response exceeds the byte limit")
        self.bytes_read += len(data)
        return data


class FakeHub:
    publish = True

    def __init__(self, baseline, original):
        self.baseline = baseline
        self.original = original
        self.index = None
        self.files = {}
        self.commits = []
        self.fail = False

    def info(self, repo):
        return {"sha": "a" * 40, "siblings": [{"rfilename": p} for p in self.files]}

    def read(self, repo, commit, path, **kwargs):
        if path == "manifest.json":
            return self.baseline
        if path == u.INDEX_PATH:
            return self.index
        if path == "README.md":
            return b"---\nlicense: pddl\n---\nCurated baseline.\n"
        return self.original

    def commit(self, repo, parent, files):
        if self.fail:
            raise RuntimeError("failure containing a hypothetical credential")
        self.commits.append((repo, parent, files))
        self.files.update(files)
        self.index = files[u.INDEX_PATH]
        return "b" * 40


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw().hex()
        self.item = {"table": "payments", "url": "https://source.test/payments.csv", "baseline_path": "originals/payments.csv", "baseline_rows": 1, "baseline_bytes": 9, "baseline_sha256": u.digest(b"id\n001\n"), "year": None}
        manifest = {"pack": "test", "files": [{"format": "ORIGINAL", "path": self.item["baseline_path"], "table": "payments", "sourceUrl": self.item["url"], "sha256": self.item["baseline_sha256"]}]}
        canonical = json.dumps(manifest).encode()
        signed = {"manifest": manifest, "manifestCanonicalBase64": base64.b64encode(canonical).decode(), "manifestSha256": u.digest(canonical), "signature": {"algorithm": "Ed25519", "publicKeyHex": self.public, "signerKeyId": u.digest(bytes.fromhex(self.public)), "signatureHex": self.key.sign(canonical).hex()}}
        self.baseline = u.json_bytes(signed)
        (self.root / "baseline.json").write_bytes(self.baseline)
        self.config = {"hosts": ["source.test"], "limits": {"seconds": 10, "run_bytes": 4096, "file_bytes": 2048, "repo_added_bytes": 8192}, "packs": [{"repo": "Writerslogic/onrecord-test", "baseline_commit": "a" * 40, "baseline_manifest": "baseline.json", "sources": [self.item]}]}
        self.hub = FakeHub(self.baseline, b"id\n001\n")
        self.patches = [patch.object(u, "__file__", str(self.root / "updater.py")), patch.dict(u.PUBLIC_KEYS, {self.public: False})]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.temp.cleanup()

    def execute(self, raw):
        return u.run(self.config, FakeNetwork({self.item["url"]: raw}), self.hub, self.root / "out")

    def test_changed_source_is_atomic_and_rerun_is_idempotent(self):
        raw = b"id\n001\n002\n"
        first = self.execute(raw)
        self.assertEqual(first["packs"][0]["status"], "published")
        self.assertEqual(len(self.hub.commits), 1)
        paths = set(self.hub.commits[0][2])
        self.assertNotIn("manifest.json", paths)
        self.assertTrue(all(p == "README.md" or p.startswith("auto-updates/") for p in paths))
        self.assertEqual(self.execute(raw)["sources"][0]["status"], "bytes_unchanged")
        self.assertEqual(len(self.hub.commits), 1)

    def test_unchanged_baseline_creates_no_commit(self):
        self.assertEqual(self.execute(b"id\n001\n")["packs"][0]["status"], "no_updates")
        self.assertEqual(self.hub.commits, [])

    def test_schema_failure_preserves_baseline_and_publishes_nothing(self):
        status = self.execute(b"other\n001\n")
        self.assertEqual(status["sources"][0]["status"], "held")
        self.assertEqual(self.hub.commits, [])

    def test_publication_failure_is_sanitized_and_leaves_staged_files(self):
        self.hub.fail = True
        status = self.execute(b"id\n001\n002\n")
        self.assertEqual(status["packs"][0]["status"], "held")
        self.assertNotIn("credential", status["packs"][0]["reason"])
        self.assertTrue((self.root / "out/onrecord-test/auto-updates/index.json").is_file())

    def test_growth_budget_refuses_upload(self):
        self.config["limits"]["repo_added_bytes"] = 10
        status = self.execute(b"id\n001\n002\n")
        self.assertEqual(status["sources"][0]["status"], "budget_deferred")
        self.assertEqual(self.hub.commits, [])

    def test_reversion_uses_retained_version_and_does_not_upload_it_again(self):
        first = b"id\n001\n002\n"
        self.execute(first)
        self.execute(b"id\n001\n002\n003\n")
        status = self.execute(first)
        self.assertEqual(status["sources"][0]["status"], "returned_to_prior_version")
        self.assertEqual(set(self.hub.commits[-1][2]), {u.INDEX_PATH, "README.md"})

    def test_modified_curated_release_is_held(self):
        self.hub.baseline = self.baseline.replace(b'"test"', b'"other"')
        self.assertEqual(self.execute(b"id\n001\n002\n")["packs"][0]["status"], "held")
        self.assertEqual(self.hub.commits, [])

    def test_unknown_destination_does_not_silently_succeed(self):
        with self.assertRaises(u.Refusal):
            u.run(self.config, FakeNetwork({}), self.hub, self.root / "out", selected={"Other/repo"})

    def test_mutated_growth_accounting_is_rejected(self):
        self.execute(b"id\n001\n002\n")
        index = json.loads(self.hub.index)
        index["added_bytes"] -= 1
        self.hub.index = u.json_bytes(index)
        status = self.execute(b"id\n001\n002\n003\n")
        self.assertEqual(status["packs"][0]["status"], "held")
        self.assertEqual(len(self.hub.commits), 1)

    def test_mutated_supplemental_path_cannot_overwrite_curated_files(self):
        self.execute(b"id\n001\n002\n")
        index = json.loads(self.hub.index)
        index["history"][0]["original_path"] = "auto-updates/../manifest.json"
        self.hub.index = u.json_bytes(index)
        self.assertEqual(self.execute(b"id\n001\n002\n003\n")["packs"][0]["status"], "held")
        self.assertEqual(len(self.hub.commits), 1)


if __name__ == "__main__":
    unittest.main()
