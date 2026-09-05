# Contributing

Install the source with `python -m pip install -e '.[dev]'` and run `python -m pytest`. Use Python 3.11-compatible syntax. New adapter or lifecycle changes need both positive and negative tests. Preserve the rule that approximate/ambiguous matches never suppress findings and that edited targets/evidence cannot retain approval.

Discuss changes in an issue, keep pull requests focused, and include the exact validation commands and results. Synthetic fixtures must be labeled. Do not contribute customer chip data, foundry rule decks, proprietary binaries, credentials or undocumented waiver syntax presented as authoritative. Describe compatibility limits and cite official specifications.

Source contributions are under Apache-2.0. Do not promise vendor qualification or universal superiority without reproducible evidence. For potentially exploitable vulnerabilities, follow SECURITY.md rather than posting sensitive details publicly.
