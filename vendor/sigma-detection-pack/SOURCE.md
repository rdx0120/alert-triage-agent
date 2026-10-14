# Vendored from sigma-detection-pack

- Repo: https://github.com/rdx0120/sigma-detection-pack
- Commit: e3becabe7b9057981eefb527382c54b27e381d36
- Copied: `rules/*/*.yml`, `tests/fixtures/*.json`, and the seven per-rule runbooks.
- Not copied: `runbooks/wazuh-deployment-notes.md` (deployment notes, not a per-rule runbook).

Copied rather than used as a git submodule so the repo clones and runs the same
on Windows without extra steps. To update: re-copy from a newer commit and change
the hash above.
