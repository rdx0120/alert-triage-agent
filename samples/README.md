# Sample alerts

Synthetic alerts used as inputs to `triage/ingest.py`. They exercise the
normalizers and the later pipeline stages; they are not evaluation data and
carry no labels. All hostnames, users, IP addresses (documentation ranges) and
URLs (`.test` domains) are fictional.

## Formats

| Folder | Format | Origin |
|---|---|---|
| `alerts/wazuh/` | Wazuh 4.x alert JSON | Hand-written |
| `alerts/sigma/` | Sigma rule match (format in the `triage/ingest.py` docstring) | Generated |

The caller always states the format; there is no auto-detection:

```python
from pathlib import Path
from triage.ingest import load_alert

alert = load_alert(Path("samples/alerts/wazuh/encoded_powershell.json").read_text(), fmt="wazuh")
alert = load_alert(Path("samples/alerts/sigma/password_spray.json").read_text(), fmt="sigma")
```

## Generated Sigma samples

The Sigma samples are built from the vendored rules and their `true_positive`
fixtures in `vendor/sigma-detection-pack/`. Do not edit them by hand:

```bash
python scripts/build_sample_alerts.py           # regenerate
python scripts/build_sample_alerts.py --check   # fail if the committed files differ
```

Rules without a fixture (`impossible_travel_workspace_login`) have no sample.
When a fixture holds several matching events (`password_spray`), the sample
keeps the first event and adds an `aggregate` block with the match count, the
first and last timestamps and distinct-value counts.

## Hand-written Wazuh samples

The Wazuh samples follow the Wazuh 4.x alert structure. Their rule IDs and
levels are illustrative, not Wazuh defaults.

Two samples are deliberate edge cases:

- `edr_tampering.json` carries the technique ID `T1562.001`, which ATT&CK
  v20.0 revoked and replaced with `T1685`. Ingestion keeps it as given, so
  later stages must handle a stale technique ID.
- `unknown_host_powershell.json` comes from `WS-UNMANAGED-07`, a valid
  hostname that is not in `data/assets.json`, to exercise the missing-asset
  path.
