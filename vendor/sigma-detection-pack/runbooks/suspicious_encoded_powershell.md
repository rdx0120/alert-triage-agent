# Runbook: Suspicious Encoded PowerShell Command Execution

**Rule:** `rules/endpoint/suspicious_encoded_powershell.yml`
**Severity:** High
**ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

## What this means

PowerShell was invoked with a base64-encoded command (`-enc` /
`-EncodedCommand`) or a common download-cradle pattern
(`IEX`, `Invoke-Expression`, `DownloadString`, `Net.WebClient`,
`Invoke-WebRequest`). These patterns are heavily used both by
commodity malware and legitimate RMM/admin tooling, so triage focuses
on *decoding and reading* the actual command before deciding severity.

## Triage steps

1. **Decode the base64 payload** if `-enc`/`-EncodedCommand` was used
   (`[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("..."))`)
   and read what it actually does.
2. **Check the parent process.** Spawned from `winword.exe`,
   `excel.exe`, `outlook.exe`, or a browser is a strong phishing/macro
   indicator. Spawned from `AteraAgent.exe` or a known RMM binary is
   expected admin behavior.
3. **Check the destination** if a download cradle is present — is the
   URL a known-good internal/vendor location, or an unknown external
   host?
4. **Check EDR (GravityZone) for a correlated verdict** on the same
   endpoint around the same time.

## Response actions

- **Malicious/unknown parent + suspicious payload:** Isolate the
  endpoint in GravityZone. Preserve the process tree and decoded
  command for the incident record. Begin containment per the IR plan.
- **Expected RMM/admin tooling:** Document and close; consider adding
  the specific script path or Atera agent process to a future
  allowlist if this becomes a recurring false positive.

## Known false positives

- Legitimate admin scripts and RMM tooling (Atera) that use encoded
  commands for reliability across PowerShell versions/quoting issues.
- Software deployment tools that wrap installers in PowerShell
  download cradles as part of normal patch management.

## Tuning notes

This is a signature-based rule and will not catch every obfuscation
technique. It is a first-pass tripwire, not a comprehensive PowerShell
security control — pair with PowerShell Script Block Logging
(Event ID 4104) for deeper visibility if the environment's logging
budget allows it.
