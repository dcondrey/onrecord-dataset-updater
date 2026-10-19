from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPOSITORY_NAME = "onrecord-dataset-updater"
MARKER = {"project": "onrecord-source-refresh", "version": 1}
FILES = (
    ".github/workflows/refresh.yml", ".gitignore", ".python-version", "README.md",
    "UPSTREAMS.md", "pyproject.toml", "uv.lock", "updater.py", "deploy.py",
    "summarize.py", "sources.json", "tests/test_updater.py", "tests/test_deploy.py",
)


class DeploymentError(Exception):
    pass


def export_files(root=ROOT):
    paths = [*FILES, *(p.relative_to(root).as_posix() for p in sorted((root / "baselines").glob("*-manifest.json")))]
    files = {}
    for path in paths:
        local = root / path
        if local.is_symlink() or not local.is_file() or root.resolve() not in local.resolve().parents:
            raise DeploymentError(f"Missing or unsafe deployment file: {path}")
        if local.stat().st_size > 2 * 1024**2:
            raise DeploymentError(f"Deployment file is unexpectedly large: {path}")
        files[path] = local.read_bytes()
    files[".onrecord-updater.json"] = (json.dumps(MARKER) + "\n").encode()
    return files


def github_token():
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
        token = result.stdout.strip() if result.returncode == 0 else None
    if not token:
        path = Path.home() / ".config/gh/onrecord-updater-token"
        if path.is_file():
            if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
                raise DeploymentError("Temporary GitHub token file must have mode 0600")
            token = path.read_text().strip()
    if not token:
        raise DeploymentError("Run this helper in the terminal where gh auth login succeeded")
    return token


def hf_token():
    from huggingface_hub import get_token
    token = os.environ.get("HF_TOKEN") or get_token()
    if not token:
        path = Path.home() / ".env"
        if path.is_file():
            for line in path.read_text().splitlines():
                if line.startswith("HF_TOKEN="):
                    token = line.split("=", 1)[1].strip().strip("\"'")
                    break
    if not token:
        raise DeploymentError("Set HF_TOKEN or log in with the Hugging Face CLI before deploying")
    return token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise DeploymentError("Authenticated GitHub request unexpectedly redirected")


class GitHub:
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, payload=None, *, absent=False):
        if not path.startswith("/") or path.startswith("//") or "\n" in path:
            raise DeploymentError("Invalid GitHub API path")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "User-Agent": "OnRecordDatasetUpdater/1.0"}
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request("https://api.github.com" + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(8 * 1024**2)
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            if absent and error.code == 404:
                return None
            raise DeploymentError(f"GitHub API refused {method} {path} (HTTP {error.code})") from None
        except urllib.error.URLError:
            raise DeploymentError("Cannot connect to GitHub from this terminal") from None


def set_hf_secret(github, repository, value):
    from nacl.public import PublicKey, SealedBox
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 4096:
        raise DeploymentError("Invalid Hugging Face token length")
    key = github.request("GET", "/repos/" + repository + "/actions/secrets/public-key")
    try:
        public = PublicKey(base64.b64decode(key["key"], validate=True))
        encrypted = SealedBox(public).encrypt(value.encode())
    except (ValueError, KeyError, TypeError):
        raise DeploymentError("Invalid GitHub Actions encryption key") from None
    github.request("PUT", "/repos/" + repository + "/actions/secrets/HF_TOKEN", {
        "key_id": key["key_id"], "encrypted_value": base64.b64encode(encrypted).decode(),
    })


def deploy(github, files, secret, *, set_secret, state=None, save_state=lambda value: None):
    state = state if state is not None else {}
    account = github.request("GET", "/user")["login"]
    if not re.fullmatch(r"[A-Za-z0-9-]+", account):
        raise DeploymentError("Unexpected GitHub account name")
    repository = account + "/" + REPOSITORY_NAME
    prefix = "/repos/" + repository
    info = github.request("GET", prefix, absent=True)
    if info is None:
        info = github.request("POST", "/user/repos", {
            "name": REPOSITORY_NAME, "private": False, "auto_init": True,
            "description": "Bounded public-source updates for existing OnRecord datasets",
            "has_issues": False, "has_wiki": False,
        })
        state.update(repository=repository, repository_id=info["id"])
        save_state(state)
    else:
        marker = github.request("GET", prefix + "/contents/.onrecord-updater.json", absent=True)
        owned_attempt = (type(state.get("repository_id")) is int and state.get("repository_id") == info.get("id") and state.get("repository") == repository)
        if (marker is None and not owned_attempt) or (marker is not None and json.loads(base64.b64decode(marker["content"])) != MARKER):
            raise DeploymentError("An unrelated repository already uses the deployment name")
    if info.get("private") is not False:
        raise DeploymentError("Deployment requires a public repository for free runner minutes")
    set_secret(repository, secret)
    branch = info["default_branch"]
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        raise DeploymentError("Unexpected default branch")
    ref = github.request("GET", prefix + "/git/ref/heads/" + branch)
    parent = ref["object"]["sha"]
    commit = github.request("GET", prefix + "/git/commits/" + parent)
    tree = []
    for path, content in files.items():
        blob = github.request("POST", prefix + "/git/blobs", {"content": base64.b64encode(content).decode(), "encoding": "base64"})
        tree.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    new_tree = github.request("POST", prefix + "/git/trees", {"base_tree": commit["tree"]["sha"], "tree": tree})
    if new_tree["sha"] != commit["tree"]["sha"]:
        new_commit = github.request("POST", prefix + "/git/commits", {"message": "feat: Add autonomous public dataset refresh", "tree": new_tree["sha"], "parents": [parent]})
        github.request("PATCH", prefix + "/git/refs/heads/" + branch, {"sha": new_commit["sha"], "force": False})
        parent = new_commit["sha"]
    workflow = None
    for attempt in range(10):
        workflow = github.request("GET", prefix + "/actions/workflows/refresh.yml", absent=True)
        if workflow is not None:
            break
        if attempt < 9:
            time.sleep(2)
    if workflow is None or type(workflow.get("id")) is not int or workflow.get("state") != "active":
        raise DeploymentError("Workflow registration is not ready; retry deployment")
    github.request("POST", prefix + f"/actions/workflows/{workflow['id']}/dispatches", {"ref": branch})
    return {"repository": repository, "url": "https://github.com/" + repository, "commit": parent, "workflow": "https://github.com/" + repository + "/actions/workflows/refresh.yml"}


def main():
    subprocess.run(["uv", "run", "--locked", "python", "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=True)
    files = export_files()
    token = github_token()
    secret = hf_token()
    from huggingface_hub import HfApi
    api = HfApi(token=secret)
    try:
        api.whoami()
        config = json.loads((ROOT / "sources.json").read_text())
        for pack in config["packs"]:
            info = api.dataset_info(pack["repo"])
            if info.private:
                raise DeploymentError("A destination dataset is private")
    except DeploymentError:
        raise
    except Exception:
        raise DeploymentError("Hugging Face authentication or dataset access failed") from None

    directory = ROOT / ".run"
    directory.mkdir(exist_ok=True)
    intent = directory / "deployment-intent.json"
    state = json.loads(intent.read_text()) if intent.exists() else {}

    def save_state(value):
        staged = intent.with_suffix(".json.new")
        staged.write_text(json.dumps(value, indent=2) + "\n")
        staged.replace(intent)

    github = GitHub(token)
    result = deploy(github, files, secret, set_secret=lambda repo, value: set_hf_secret(github, repo, value), state=state, save_state=save_state)
    (directory / "deployment.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except DeploymentError as error:
        raise SystemExit(str(error)) from None
