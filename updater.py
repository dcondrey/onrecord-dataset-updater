from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

USER_AGENT = "OnRecordDatasetUpdater/1.0"
UPDATE_ROOT = "auto-updates"
INDEX_PATH = UPDATE_ROOT + "/index.json"
START = "<!-- onrecord-auto-updates:start -->"
END = "<!-- onrecord-auto-updates:end -->"
PUBLIC_KEYS = {
    "b42202850cd9ecda4ab2b96548891d3a2a8275f74dde76bba2153826089ca8ff": False,
    "3049662bc87c61409d8b8a515d60adf1420a32504bd4f6215ac0c121550a318f": True,
}
MAX_METADATA = 32 * 1024 * 1024
MAX_HEADER = 64 * 1024
MAX_ROWS = 2_000_000
MAX_COLUMNS = 512
MAX_CELL = 1024 * 1024
MAX_ROW = 2 * 1024 * 1024
HEX = re.compile(r"[a-f0-9]{64}\Z")
NAME = re.compile(r"[a-z][a-z0-9_-]{0,100}\Z")
REPO = re.compile(r"Writerslogic/onrecord-[a-z0-9-]+\Z")


class Refusal(Exception):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def integer(value, low: int, high: int, field: str) -> int:
    if type(value) is not int or not low <= value <= high:
        raise Refusal(f"Invalid {field}")
    return value


def safe_path(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 400:
        raise Refusal("Invalid repository path")
    path = PurePosixPath(value)
    if path.is_absolute() or "\\" in value or any(p in ("", ".", "..") for p in value.split("/")):
        raise Refusal("Repository path escapes its root")
    return value


def allowed_url(url: str, hosts: list[str]) -> str:
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 32 for c in url):
        raise Refusal("Invalid source URL")
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise Refusal("Invalid URL port") from None
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https" or port not in (None, 443) or parsed.username
        or parsed.password or parsed.fragment or not host
        or not any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in hosts)
    ):
        raise Refusal("URL is outside the approved HTTPS hosts")
    return url


def public_url(url):
    parsed = urllib.parse.urlsplit(url)
    query = [(k, v) for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
             if not re.search(r"token|signature|credential|secret|x-amz-|x-goog-", k, re.I)]
    return urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts, policy=None):
        self.hosts = hosts
        self.policy = policy

    def redirect_request(self, request, fp, code, message, headers, newurl):
        allowed_url(newurl, self.hosts)
        source = getattr(request, "onrecord_source", False)
        if source and self.policy is not None:
            self.policy(newurl)
        redirected = super().redirect_request(request, fp, code, message, headers, newurl)
        if redirected is not None:
            redirected.onrecord_source = source
        return redirected


class Network:
    def __init__(self, hosts: list[str], timeout: int = 20, *, max_bytes=None, seconds=None):
        self.hosts = hosts
        self.timeout = timeout
        self.opener = urllib.request.build_opener(Redirects(hosts, self.check_robots))
        self.robots = {}
        self.paused_hosts = set()
        self.bytes_read = 0
        self.max_bytes = max_bytes
        self.deadline = time.monotonic() + seconds if seconds else None

    def read(self, url, limit, *, prefix=False, source=False):
        allowed_url(url, self.hosts)
        host = urllib.parse.urlsplit(url).hostname
        if host in self.paused_hosts:
            raise Refusal("Publisher rate limit or outage; deferred until the next run")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise Refusal("Run time budget reached")
        if source:
            self.check_robots(url)
        if self.max_bytes is not None:
            remaining = self.max_bytes - self.bytes_read
            if remaining <= 0:
                raise Refusal("Run byte budget reached")
            limit = min(limit, remaining)
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if prefix:
            headers["Range"] = f"bytes=0-{limit - 1}"
        request = urllib.request.Request(url, headers=headers)
        request.onrecord_source = source
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                if response.status not in (200, 206) or (response.status == 206 and not prefix):
                    raise Refusal("Unexpected or partial HTTP response")
                length = response.headers.get("Content-Length")
                if length and not prefix and int(length) > limit:
                    raise Refusal("Response exceeds the byte limit")
                data = response.read(limit)
                self.bytes_read += len(data)
                if not prefix and response.read(1):
                    raise Refusal("Response exceeds the byte limit")
                if not prefix and length and len(data) != int(length):
                    raise Refusal("Response is truncated")
                return data
        except urllib.error.HTTPError as error:
            if error.code in (429, 503):
                self.paused_hosts.add(host)
            raise Refusal(f"HTTP {error.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise Refusal("Network request failed") from None

    def check_robots(self, url):
        parsed = urllib.parse.urlsplit(url)
        origin = f"https://{parsed.netloc}"
        if origin not in self.robots:
            try:
                raw = self.read(origin + "/robots.txt", MAX_HEADER)
                parser = urllib.robotparser.RobotFileParser()
                parser.parse(raw.decode("utf-8", errors="replace").splitlines())
                self.robots[origin] = parser
            except Refusal as error:
                unavailable = re.fullmatch(r"HTTP (4\d\d)", str(error))
                if not unavailable or unavailable.group(1) == "429":
                    raise Refusal("Cannot verify publisher crawling policy") from None
                self.robots[origin] = None
        parser = self.robots[origin]
        if parser is not None and not parser.can_fetch(USER_AGENT, url):
            raise Refusal("Publisher crawling policy disallows retrieval")


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text())
    limits = config["limits"]
    integer(limits["file_bytes"], 1024, 128 * 1024 * 1024, "file byte limit")
    integer(limits["run_bytes"], limits["file_bytes"], 1024 * 1024 * 1024, "run byte limit")
    integer(limits["repo_added_bytes"], 1024, 2 * 1024 * 1024 * 1024, "repository growth limit")
    integer(limits["seconds"], 10, 1200, "run time limit")
    seen = set()
    for pack in config["packs"]:
        if not REPO.fullmatch(pack["repo"]) or pack["repo"] in seen:
            raise Refusal("Invalid or repeated destination")
        seen.add(pack["repo"])
        if not re.fullmatch(r"[a-f0-9]{40}", pack["baseline_commit"]):
            raise Refusal("Invalid baseline commit")
        safe_path(pack["baseline_manifest"])
        for item in pack["sources"]:
            if not NAME.fullmatch(item["table"]) or not HEX.fullmatch(item["baseline_sha256"]):
                raise Refusal("Invalid source identity")
            allowed_url(item["url"], config["hosts"])
            safe_path(item["baseline_path"])
            integer(item["baseline_rows"], 0, 100_000_000, "baseline row count")
            integer(item["baseline_bytes"], 0, 10**12, "baseline bytes")
    return config


def verify_baseline(signed: dict, repo: str) -> dict:
    canonical = base64.b64decode(signed["manifestCanonicalBase64"], validate=True)
    signature = signed["signature"]
    public = signature["publicKeyHex"]
    pack = repo.split("onrecord-", 1)[1]
    if public not in PUBLIC_KEYS or PUBLIC_KEYS[public] != (pack == "san-diego-snapshots"):
        raise Refusal("Baseline manifest uses an untrusted key or key scope")
    if signature["algorithm"] != "Ed25519" or digest(canonical) != signed["manifestSha256"]:
        raise Refusal("Baseline manifest hash or algorithm mismatch")
    if json.loads(canonical) != signed["manifest"] or signed["manifest"]["pack"] != pack:
        raise Refusal("Baseline manifest differs from its signed bytes")
    if digest(bytes.fromhex(public)) != signature["signerKeyId"]:
        raise Refusal("Baseline signer ID mismatch")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            bytes.fromhex(signature["signatureHex"]), canonical
        )
    except Exception:
        raise Refusal("Baseline signature verification failed") from None
    return signed["manifest"]


def source_id(item: dict) -> str:
    return digest((item["table"] + "\n" + item.get("identity_url", item["url"])).encode())[:24]


def csv_header(raw: bytes) -> list[str]:
    csv.field_size_limit(MAX_CELL)
    try:
        header_line = raw.split(b"\n", 1)[0].decode("utf-8-sig")
        header = next(csv.reader(io.StringIO(header_line), strict=True))
    except (UnicodeError, StopIteration, csv.Error):
        raise Refusal("Cannot read a UTF-8 CSV header") from None
    if not header or len(header) > MAX_COLUMNS or any(not h.strip() for h in header) or len(set(header)) != len(header):
        raise Refusal("CSV has empty, repeated or excessive columns")
    if any(len(h) > 512 or any(ord(c) < 32 for c in h) for h in header):
        raise Refusal("Invalid CSV header")
    return header


def convert_csv(raw: bytes, expected: list[str], item: dict, retrieved: str, max_output: int):
    header = csv_header(raw)
    if any(h not in header for h in expected):
        raise Refusal("Publisher removed or renamed columns; review required")
    output = io.BytesIO()
    sha = digest(raw)
    count = 0
    try:
        reader = csv.reader(io.StringIO(raw.decode("utf-8-sig")), strict=True)
        next(reader)
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as zipped:
            for row in reader:
                if len(row) != len(header) or sum(map(len, row)) > MAX_ROW:
                    raise Refusal("Malformed or oversized CSV record")
                count += 1
                if count > MAX_ROWS:
                    raise Refusal("CSV exceeds the row limit")
                value = {
                    "source_id": source_id(item), "source_url": public_url(item["url"]),
                    "source_sha256": sha, "source_row": count,
                    "retrieved_at": retrieved, "table": item["table"],
                    "record_json": json.dumps(dict(zip(header, row)), ensure_ascii=False),
                }
                zipped.write((json.dumps(value, ensure_ascii=False) + "\n").encode())
                if output.tell() > max_output:
                    raise Refusal("Converted data exceeds the growth limit")
        if not count:
            raise Refusal("CSV is empty")
    except (UnicodeError, csv.Error):
        raise Refusal("Malformed UTF-8 CSV") from None
    baseline = item["baseline_rows"]
    if baseline and count < baseline * 0.8:
        raise Refusal("Row count fell more than 20%; review required")
    if output.tell() > max_output:
        raise Refusal("Converted data exceeds the growth limit")
    return output.getvalue(), count, header


def discover_years(sources: list[dict], year: int) -> list[dict]:
    result = list(sources)
    urls = {s["url"] for s in sources}
    for item in sources:
        old = item.get("year")
        if not isinstance(old, int) or "seshat.datasd.org" != urllib.parse.urlsplit(item["url"]).hostname:
            continue
        if not re.search(rf"(?<!\d){old}(?!\d)", item["url"]):
            continue
        # One template per series, chosen from its latest baseline year.
        template = re.sub(rf"(?<!\d){old}(?!\d)", "{year}", item["url"])
        if any(other.get("year", 0) > old and re.sub(rf"(?<!\d){other.get('year')}(?!\d)", "{year}", other["url"]) == template for other in sources if isinstance(other.get("year"), int)):
            continue
        for new in range(old + 1, min(year, old + 10) + 1):
            url = re.sub(rf"(?<!\d){old}(?!\d)", str(new), item["url"])
            if url not in urls:
                result.append({**item, "url": url, "year": new, "new_year": True, "baseline_rows": 0})
                urls.add(url)
    return result


def discover_ckan(sources, network, hosts):
    packages = {}
    resolved = []
    for item in sources:
        match = re.search(r"/dataset/([^/]+)/resource/([^/]+)/", item["url"])
        if not match or urllib.parse.urlsplit(item["url"]).hostname not in ("data.ca.gov", "publish.data.ca.gov"):
            resolved.append(item)
            continue
        package, resource = match.groups()
        if package not in packages:
            url = "https://data.ca.gov/api/3/action/package_show?" + urllib.parse.urlencode({"id": package})
            data = json.loads(network.read(url, 2 * 1024 * 1024, source=True))
            if data.get("success") is not True or not isinstance(data.get("result", {}).get("resources"), list):
                raise Refusal("Invalid publisher resource listing")
            packages[package] = data["result"]
        listing = packages[package]
        existing = next((r for r in listing["resources"] if r.get("id") == resource), None)
        if not existing:
            raise Refusal("Publisher removed an approved resource")
        url = allowed_url(existing["url"], hosts)
        resolved.append({**item, "url": url, "identity_url": item["url"]})
    return resolved


def review_upstreams(config, network):
    results = []
    for candidate in config.get("upstream_candidates", []):
        repo = candidate["repo"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise Refusal("Invalid upstream repository")
        item = {"repo": repo, "action": "review_for_reuse_or_contribution", "fit": candidate["fit"]}
        try:
            info = json.loads(network.read("https://huggingface.co/api/datasets/" + repo, MAX_METADATA))
            item.update(commit=info.get("sha"), last_modified=info.get("lastModified"),
                        licence_tags=[t for t in info.get("tags", []) if t.startswith("license:")])
        except (Refusal, KeyError, TypeError, ValueError) as error:
            item["reason"] = str(error) if isinstance(error, Refusal) else "Invalid upstream metadata"
        results.append(item)
    return results


def update_card(card: bytes, entries: dict) -> bytes:
    text = card.decode("utf-8")
    match = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n", text, re.S)
    if not match:
        raise Refusal("Dataset card has no YAML metadata")
    metadata = yaml.safe_load(match.group(1))
    if not isinstance(metadata, dict) or not isinstance(metadata.get("configs", []), list):
        raise Refusal("Invalid dataset card metadata")
    configs = metadata.setdefault("configs", [])
    if any(c.get("config_name") == "auto_updates" for c in configs) and START not in text:
        raise Refusal("Dataset already uses the reserved auto_updates configuration")
    paths = sorted(e["rows_path"] for e in entries.values())
    if any(c.get("config_name") == "auto_updates" and c.get("data_files") != paths for c in configs):
        configs[:] = [c for c in configs if c.get("config_name") != "auto_updates"]
    if not any(c.get("config_name") == "auto_updates" for c in configs):
        configs.append({"config_name": "auto_updates", "data_files": paths})
    body = text[match.end():]
    if (START in body) != (END in body) or body.count(START) > 1 or body.count(END) > 1:
        raise Refusal("Invalid automated dataset card section")
    body = re.sub(re.escape(START) + r".*?" + re.escape(END) + r"\n?", "", body, flags=re.S).rstrip()
    section = f"""{START}
## Automated source updates

The `auto_updates` configuration contains the latest supplemental raw CSV records for sources
that changed after the curated baseline. Unchanged baseline sources remain in the curated
configurations. `record_json` preserves every publisher column as text; adjacent columns
identify the source URL, source SHA-256, row and retrieval time. These rows are supplemental raw
records, not the curated conformed tables above. Compare sources and time periods before joining
them; snapshots of the same source are not independent corroboration.

[`auto-updates/index.json`](auto-updates/index.json) identifies the current files, their history,
checksums, row counts and the signed baseline revision. Earlier source versions are retained.
The original signed `manifest.json` and curated release are preserved. The supplemental index is
not signed by the curated pack's publisher key, and the app does not import this layer as a signed
pack. Existing DOI registrations and published report editions are unchanged.

Coverage is bounded by source availability, CSV support, schema validation and the collection
budgets. A missing update does not mean that a publisher's data stayed unchanged. Run outcomes and
skipped sources are recorded in the automation repository's `status/latest.json`.
{END}
"""
    return ("---\n" + yaml.safe_dump(metadata, sort_keys=False, allow_unicode=True) + "---\n" + body + "\n\n" + section).encode()


class Hub:
    def __init__(self, network: Network, publish: bool):
        self.network = network
        self.publish = publish
        self.api = None
        if publish:
            from huggingface_hub import HfApi
            token = os.environ.get("HF_TOKEN")
            if not token:
                raise Refusal("HF_TOKEN is required for publication")
            self.api = HfApi(token=token)

    def info(self, repo):
        data = json.loads(self.network.read("https://huggingface.co/api/datasets/" + repo, MAX_METADATA))
        if data.get("private") is not False or data.get("gated") not in (False, None) or data.get("disabled"):
            raise Refusal("Destination is not an available public dataset")
        if not re.fullmatch(r"[a-f0-9]{40}", data.get("sha", "")):
            raise Refusal("Dataset has no valid head commit")
        return data

    def read(self, repo, commit, path, *, optional=False, prefix=False):
        safe_path(path)
        url = f"https://huggingface.co/datasets/{repo}/resolve/{commit}/{path}"
        try:
            return self.network.read(url, MAX_HEADER if prefix else MAX_METADATA, prefix=prefix)
        except Refusal as error:
            if optional and str(error) == "HTTP 404":
                return None
            raise

    def commit(self, repo, parent, files):
        if not self.publish:
            return None
        from huggingface_hub import CommitOperationAdd
        if any(path != "README.md" and not path.startswith(UPDATE_ROOT + "/") for path in files):
            raise Refusal("Upload includes a protected path")
        result = self.api.create_commit(
            repo_id=repo, repo_type="dataset", parent_commit=parent,
            operations=[CommitOperationAdd(path_in_repo=p, path_or_fileobj=data) for p, data in files.items()],
            commit_message="Extend validated source records and provenance",
        )
        return result.oid


def validate_index(index, repo, baseline):
    if index.get("version") != 1 or index.get("repo") != repo or index.get("baseline_commit") != baseline:
        raise Refusal("Unexpected supplemental index identity")
    integer(index["added_bytes"], 0, 2 * 1024**3, "published growth")
    if not isinstance(index["current"], dict) or not isinstance(index["history"], list):
        raise Refusal("Invalid supplemental index")
    for entry in [*index["current"].values(), *index["history"]]:
        if not HEX.fullmatch(entry["sha256"]):
            raise Refusal("Invalid supplemental hash")
        if not re.fullmatch(r"[a-f0-9]{24}", entry["source_id"]):
            raise Refusal("Invalid supplemental source ID")
        for key in ("original_path", "rows_path"):
            path = safe_path(entry[key])
            if not path.startswith(UPDATE_ROOT + "/"):
                raise Refusal("Supplemental file escapes its directory")
        root = f"{UPDATE_ROOT}/files/{entry['source_id']}/{entry['sha256']}"
        if entry["original_path"] != root + "/original.csv" or entry["rows_path"] != root + "/rows.jsonl.gz":
            raise Refusal("Supplemental content paths differ from their hashes")
        integer(entry["bytes"], 1, 128 * 1024**2, "original bytes")
        integer(entry["rows_bytes"], 1, 2 * 1024**3, "converted bytes")
        integer(entry["rows"], 1, MAX_ROWS, "source rows")
        if not HEX.fullmatch(entry["rows_sha256"]):
            raise Refusal("Invalid converted file hash")
    if sum(e["bytes"] + e["rows_bytes"] for e in index["history"]) != index["added_bytes"]:
        raise Refusal("Supplemental growth accounting differs from its history")
    history = {e["original_path"]: e for e in index["history"]}
    if len(history) != len(index["history"]) or any(history.get(e["original_path"]) != e for e in index["current"].values()):
        raise Refusal("Supplemental current versions do not match their history")
    if any(key != entry["source_id"] for key, entry in index["current"].items()):
        raise Refusal("Supplemental current source IDs differ from their entries")


def run(config: dict, network, hub, output: Path, *, selected=None):
    if selected and not selected.issubset({p["repo"] for p in config["packs"]}):
        raise Refusal("Unknown selected destination dataset")
    started = time.monotonic()
    now = datetime.now(timezone.utc)
    retrieved = now.isoformat().replace("+00:00", "Z")
    status = {"checked_at": retrieved, "publication_requested": hub.publish, "packs": [], "sources": [],
              "upstream_candidates": review_upstreams(config, network)}
    output.mkdir(parents=True, exist_ok=True)
    cache = {}
    limits = config["limits"]
    for pack in config["packs"]:
        repo = pack["repo"]
        if selected and repo not in selected:
            continue
        pack_status = {"repo": repo, "updated_sources": 0, "commit": None}
        status["packs"].append(pack_status)
        try:
            info = hub.info(repo)
            head = info["sha"]
            baseline_raw = (Path(__file__).parent / pack["baseline_manifest"]).read_bytes()
            baseline = verify_baseline(json.loads(baseline_raw), repo)
            baseline_files = {f["path"]: f for f in baseline["files"] if f["format"] == "ORIGINAL"}
            for item in pack["sources"]:
                original = baseline_files.get(item["baseline_path"])
                if not original or original["sha256"] != item["baseline_sha256"] or original["sourceUrl"] != item["url"] or original["table"] != item["table"]:
                    raise Refusal("Source configuration does not match its signed baseline")
            # A changed curated baseline needs review; supplemental updates use their own directory.
            current_baseline = hub.read(repo, head, "manifest.json")
            if json.loads(current_baseline) != json.loads(baseline_raw):
                if repo.endswith("onrecord-san-diego-snapshots"):
                    live = verify_baseline(json.loads(current_baseline), repo)
                    pack_status.update(status="maintained_by_signed_snapshot_pipeline", built_at=live["builtAt"])
                    continue
                raise Refusal("Curated baseline changed; refresh the source configuration")
            remote_index = hub.read(repo, head, INDEX_PATH, optional=True)
            index = json.loads(remote_index) if remote_index else {
                "version": 1, "repo": repo, "baseline_commit": pack["baseline_commit"],
                "added_bytes": 0, "current": {}, "history": [],
            }
            validate_index(index, repo, pack["baseline_commit"])
            files = {}
            items = discover_years(pack["sources"], now.year)
            try:
                items = discover_ckan(items, network, config["hosts"])
            except (Refusal, KeyError, TypeError, ValueError) as error:
                pack_status["discovery_warning"] = str(error) if isinstance(error, Refusal) else "Invalid publisher discovery metadata"
            for item in items:
                item_status = {"repo": repo, "table": item["table"], "url": public_url(item["url"]), "status": "pending"}
                status["sources"].append(item_status)
                try:
                    if time.monotonic() - started >= limits["seconds"] or network.bytes_read >= limits["run_bytes"]:
                        raise Refusal("Run budget reached")
                    if item.get("archival"):
                        item_status["status"] = "archival_baseline_preserved"
                        continue
                    if isinstance(item.get("year"), int) and item["year"] < now.year and now.day > 7:
                        item_status["status"] = "historical_recheck_next_month"
                        continue
                    if not item["baseline_path"].lower().endswith(".csv"):
                        raise Refusal("Unsupported non-CSV source; baseline preserved")
                    if item["baseline_bytes"] > limits["file_bytes"]:
                        raise Refusal("Source exceeds the file budget")
                    if index["added_bytes"] >= limits["repo_added_bytes"]:
                        raise Refusal("Repository growth budget reached")
                    url = allowed_url(item["url"], config["hosts"])
                    sid = source_id(item)
                    previous = index["current"].get(sid)
                    if url not in cache:
                        remaining = limits["run_bytes"] - network.bytes_read
                        cache[url] = network.read(url, min(limits["file_bytes"], remaining), source=True)
                    raw = cache[url]
                    sha = digest(raw)
                    item_status.update(sha256=sha, bytes=len(raw))
                    old_sha = previous["sha256"] if previous else item["baseline_sha256"]
                    if sha == old_sha and not item.get("new_year"):
                        item_status["status"] = "bytes_unchanged"
                        continue
                    header_raw = hub.read(repo, pack["baseline_commit"], item["baseline_path"], prefix=True)
                    expected = csv_header(header_raw)
                    comparison = {**item, "baseline_rows": previous["rows"] if previous else item["baseline_rows"]}
                    available = limits["repo_added_bytes"] - index["added_bytes"] - len(raw)
                    if available <= 0:
                        raise Refusal("Repository growth budget reached")
                    root = f"{UPDATE_ROOT}/files/{sid}/{sha}"
                    original_path = root + "/original.csv"
                    rows_path = root + "/rows.jsonl.gz"
                    if any(e["original_path"] == original_path for e in index["history"]):
                        old = next(e for e in index["history"] if e["original_path"] == original_path)
                        index["current"][sid] = old
                        item_status["status"] = "returned_to_prior_version"
                    else:
                        rows_data, count, header = convert_csv(raw, expected, comparison, retrieved, available)
                        existing = {f["rfilename"] for f in info.get("siblings", [])}
                        if original_path in existing or rows_path in existing:
                            raise Refusal("Content path already exists outside the update history")
                        entry = {
                            "source_id": sid, "table": item["table"], "source_url": public_url(url),
                            "publisher_file_year": item.get("year"),
                            "retrieved_at": retrieved, "sha256": sha, "bytes": len(raw),
                            "rows_sha256": digest(rows_data), "rows_bytes": len(rows_data), "rows": count, "headers": header,
                            "original_path": original_path, "rows_path": rows_path,
                            "licence": baseline_files[item["baseline_path"]].get("licence") or baseline.get("licence"),
                        }
                        files[original_path] = raw
                        files[rows_path] = rows_data
                        index["history"].append(entry)
                        index["current"][sid] = entry
                        index["added_bytes"] += len(raw) + len(rows_data)
                        item_status["status"] = "validated_update"
                    pack_status["updated_sources"] += 1
                except Refusal as error:
                    reason = str(error)
                    if "budget" in reason:
                        item_status["status"] = "budget_deferred"
                    elif reason.startswith("Unsupported non-CSV"):
                        item_status["status"] = "unsupported_format"
                    elif item.get("new_year") and reason == "HTTP 404":
                        item_status["status"] = "not_yet_published"
                    else:
                        item_status["status"] = "held"
                    item_status["reason"] = reason
            if pack_status["updated_sources"]:
                card = hub.read(repo, head, "README.md")
                files["README.md"] = update_card(card, index["current"])
                files[INDEX_PATH] = json_bytes(index)
                directory = output / repo.split("/", 1)[1]
                for path, data in files.items():
                    destination = directory / safe_path(path)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                try:
                    pack_status["commit"] = hub.commit(repo, head, files)
                except Exception as error:
                    raise Refusal(f"Publication failed ({type(error).__name__}); staged files retained") from None
                pack_status["status"] = "published" if hub.publish else "validated_dry_run"
            else:
                pack_status["status"] = "no_updates"
        except (Refusal, KeyError, TypeError, ValueError) as error:
            reason = str(error) if isinstance(error, Refusal) else f"Invalid publisher metadata ({type(error).__name__})"
            pack_status.update(status="held", reason=reason)
    status["downloaded_bytes"] = network.bytes_read
    status["elapsed_seconds"] = round(time.monotonic() - started, 2)
    (output / "status.json").write_bytes(json_bytes(status))
    return status


def checkpoint(status: dict, repository: str, token: str, network: Network):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise Refusal("Invalid automation repository")
    # Credentials go only to api.github.com; this opener refuses every redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise Refusal("GitHub checkpoint unexpectedly redirected")

    opener = urllib.request.build_opener(NoRedirect())
    url = f"https://api.github.com/repos/{repository}/contents/status/latest.json"
    headers = {"Authorization": "Bearer " + token, "User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    sha = None
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=20) as response:
            sha = json.loads(response.read(MAX_METADATA))["sha"]
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise Refusal("Cannot read the GitHub health checkpoint") from None
    payload = {"message": "chore: record dataset collection results", "content": base64.b64encode(json_bytes(status)).decode()}
    if sha:
        payload["sha"] = sha
    try:
        with opener.open(urllib.request.Request(url, data=json_bytes(payload), headers=headers, method="PUT"), timeout=20) as response:
            if response.status not in (200, 201):
                raise Refusal("Cannot store the GitHub health checkpoint")
    except (urllib.error.URLError, OSError):
        raise Refusal("Cannot store the GitHub health checkpoint") from None


def main():
    parser = argparse.ArgumentParser(description="Extend existing public datasets; dry run unless --publish is supplied")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("sources.json"))
    parser.add_argument("--output", type=Path, default=Path(".run"))
    parser.add_argument("--repo", action="append")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--checkpoint", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    if args.publish and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("ONRECORD_PUBLIC_RUNNER") != "true":
        raise Refusal("Automatic publication requires the public-repository workflow gate")
    network = Network(config["hosts"], max_bytes=config["limits"]["run_bytes"], seconds=config["limits"]["seconds"])
    hub = Hub(network, args.publish)
    status = run(config, network, hub, args.output, selected=set(args.repo or []))
    if args.checkpoint:
        checkpoint(status, os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"], network)
    summary = {"packs": status["packs"], "downloaded_bytes": status["downloaded_bytes"], "held_sources": sum(s["status"] == "held" for s in status["sources"])}
    print(json.dumps(summary, indent=2))
    if any(p["status"] == "held" for p in status["packs"]) or any(s["status"] == "held" for s in status["sources"]):
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        raise SystemExit(str(error)) from None
