# Existing datasets before new datasets

Reviewed 2026-10-19 UTC. A metadata and documentation review identifies contribution targets;
it does not establish defects in their data or permission to merge changes. No maintainer has
been contacted and no third-party pull request has been submitted.

| Priority | Existing dataset | Verified fit | Useful contribution to assess |
|---|---|---|---|
| 1 | [chrissoria/ca-city-councils](https://huggingface.co/datasets/chrissoria/ca-city-councils) | Current successor to `san-diego-council`; common city/meeting/item/vote tables, CC0 compilation. Its card explains that San Diego votes come from Clerk results summaries joined to district rosters. | Source-backed identifier corrections, document links, coverage repairs and optional links to approved minutes. Check the primary records and existing columns first; results summaries and approved minutes have different evidentiary status. |
| 1 | [chrissoria/ca-county-boards](https://huggingface.co/datasets/chrissoria/ca-county-boards) | Statewide county-board tables include San Diego and use a CC0 compilation licence. The card says San Diego's tables are copied from `sd-county-ordinances` daily. | Assess County grant and agreement identifier links against the original San Diego reader and existing table columns. Trace the upstream source rather than treat the statewide copy as another independent record. |
| 2 | [chrissoria/san-diego-ordinances](https://huggingface.co/datasets/chrissoria/san-diego-ordinances) | Card lists document numbers, dates, PDF URLs, text source, pages and OCR confidence. | Evidence-backed document-number and OCR corrections, missing source links and coverage checks. The dataset card does not declare a dataset licence; clarify it before redistribution. |
| 3 | [paddybearsf/california-homeless-services](https://huggingface.co/datasets/paddybearsf/california-homeless-services) | CC0 card and a service-provider CSV; latest observed repository modification June 2024. Its card gives little provenance. | Establish original source, geography and record identifiers before proposing verified provider corrections or additions. A broad title alone does not establish compatibility with our financial or shelter-performance tables. |

The retired [San Diego council dataset](https://huggingface.co/datasets/chrissoria/san-diego-council)
explicitly points to the statewide successor. Contribute to the maintained successor rather than
adding a competing council corpus or sending updates to the retired repository.

For the council data, the public builder repository is
[chrissoria/cat-pol-datasets](https://github.com/chrissoria/cat-pol-datasets).
Its README identifies the San Diego reader and statewide harmonizer; code changes should target
that source pipeline rather than hand-edit generated Parquet. The builder code's GPL licence is
separate from the council compilation's CC0 licence. No dedicated CONTRIBUTING file was found in
the reviewed root listing; read applicable instructions before preparing an actual patch.

The supplied California search produced 166 repository matches at review time, many of them
machine-learning benchmarks or unrelated subject matter. Searching `sandiego` also finds
non-geographic material. Search rank and name overlap do not establish dataset fit.

Before creating a dataset, record: candidate repositories and pinned revisions; actual table
scope and grain; overlap and new coverage; source and compilation licences; provenance and
identifier compatibility; maintainer instructions; and why extension or an upstream contribution
would or would not work. Preserve attribution and avoid presenting a mirror as new evidence.

Hugging Face supports [dataset pull requests](https://huggingface.co/docs/hub/repositories-pull-requests-discussions).
Prepare narrow changes that maintainers can validate. Automated collection in our repositories
does not imply authority to merge into someone else's repository.
