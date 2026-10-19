# OnRecord dataset updates

Maintain the existing public `Writerslogic/onrecord-*` datasets with bounded, validated source
updates. This repository contains the collector and public source manifests, independently of
the OnRecord Studio application. It does not update investigation reports.

## What runs

The GitHub workflow runs weekly on Monday at 12:41 UTC and can be started manually. Historical
annual files are rechecked in the first week of each month. Current-year and unsplit files are
checked each run. Recognized City annual filename series are checked for newly available years;
California CKAN resource URLs are resolved from approved resource IDs when the publisher allows
access to that listing.

Between monthly full checks, sources with an ETag use conditional requests. A publisher's HTTP
304 is recorded as `publisher_not_modified`, separately from a freshly downloaded file whose
bytes were hash-checked. Missing or changed markers cause a full download within the budgets.

The initial catalogue contains nine existing datasets and 159 source originals. Ten Wayback
captures are preserved as archival records. Two Excel originals are outside this version's CSV
support. Large sources can be deferred by the byte budgets; this is not a promise that every
table is current. `status/latest.json` records each run's coverage, failures and deferrals.

For a changed CSV, the collector:

1. Verifies the signed baseline against the existing pinned Ed25519 keys and scopes.
2. Checks that known publisher columns remain present. Additional columns are retained. Empty,
   malformed or substantially shortened files are held for review.
3. Retains the exact original and a compressed JSONL raw table under content-addressed paths in
   the same dataset. `record_json` preserves all publisher columns as text. Provenance columns
   name the source, retrieval time, original hash and record number.
4. Updates `auto-updates/index.json`, retaining previous versions. The dataset card's
   `auto_updates` configuration points only to the current version of each updated source, so
   previous snapshots are not silently counted as additional current records.
5. Publishes that dataset's files, index and card in one commit conditional on its previous head.
   Conflicting updates fail instead of overwriting one another.

Unchanged bytes create no Hugging Face commit. Actual check outcomes are checkpointed in this
repository. These health records also provide real repository activity between code changes;
GitHub disables schedules on inactive public repositories after 60 days.

## Existing releases and research

The original signed `manifest.json`, curated originals and conformed tables stay intact. The
automated layer is a supplemental raw dataset configuration, not a replacement signed app pack.
It contains changed sources; unchanged baseline sources remain in the curated configurations.
Its index contains hashes but does not claim the curated publisher's signature. App import of
this layer would require a separate, reviewed integration. A changed signed snapshot manifest
is recognized as activity by the existing snapshot pipeline; other changed curated baselines
pause their supplemental collector for reconciliation.

Existing DOI registrations are preserved. Published report editions and their cited revisions
are frozen. A dataset mirror and its original publisher are not independent corroboration.

Prefer extending suitable existing datasets, including datasets maintained by others, before
creating new datasets. [UPSTREAMS.md](UPSTREAMS.md) records the first contribution candidates.
The scheduled job monitors their revisions but does not send unsolicited submissions or change
third-party repositories. There is no automatic dataset-creation operation.

## Cost and operating limits

- GitHub uses a standard Linux runner and the entire job is skipped in a private repository.
  The workflow uses no Actions artifacts, persistent caches, larger runners or paid compute.
- Storage uses the existing public Hugging Face repositories. Xet stays enabled. No Space,
  receiver, model API, GPU, subscription or storage add-on is provisioned.
- Default limits: 128 MiB per source, 384 MiB downloaded per run, 14 minutes collecting, a
  20-minute job timeout, and 512 MiB of supplemental originals plus converted files per dataset.
  Growth accounting is conservative logical file size, not an estimate of Xet's deduplication.
- At a limit or unavailable service the job defers work; it does not purchase capacity. Public
  Hugging Face storage is best effort, not an unlimited storage guarantee. Provider policies,
  source changes and credentials can still require occasional intervention.
- Robots prohibitions and rate limits are honored. A missing robots file reported with a 4xx
  response is distinguished from a server outage under RFC 9309; 429 and 503 pause that host.
  Bot challenges and access controls are not bypassed.

Free service terms: [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions),
[Hugging Face storage](https://huggingface.co/docs/hub/storage-limits),
[GitHub schedules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule),
[robots unavailable status](https://www.rfc-editor.org/rfc/rfc9309.html#section-2.3.1.3).

## Run locally

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
uv run --locked python updater.py
```

The default is a dry run. It writes staged changes and `status.json` under `.run/` without
publishing. To limit collection, add `--repo Writerslogic/onrecord-san-diego-money`.
`--publish` requires `HF_TOKEN`; use a fine-grained token scoped to the intended existing
datasets. The scheduled job receives it from the repository secret, never from a committed file.

## Activate once

From a terminal whose GitHub CLI login works, with a Hugging Face token available:

```sh
uv run --locked python deploy.py
```

The deployment helper verifies credentials, uploads only this standalone project's allowlisted
files to a new public `onrecord-dataset-updater` repository, sets its HF secret, and starts the
first run. It never publishes the application repository, creates datasets, changes billing, or
prints tokens. Review the first run and `status/latest.json` to distinguish successful refreshes
from held or unsupported sources. Routine failures use GitHub's normal Actions notifications.
If a temporary credential file was used for agent setup, remove it after the first run has been
verified; it is not needed by the deployed workflow.
