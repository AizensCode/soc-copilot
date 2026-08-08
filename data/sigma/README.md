# Curated Sigma rules

Unmodified community detection rules from [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
(`rules/windows/process_creation/`), redistributed under the
[Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
Each file keeps its original `id`, `author`, `references`, and `date` fields —
that is the attribution trail.

The copilot's matcher (`soc_copilot/sigma.py`) evaluates these directly against an
alert's `raw_log` and injects any matches into the investigation as grounded
detection-logic context ("this behavior is what community rule X detects").

Curation criteria: a rule earns its place here only if its detection logic is
expressible against event-shaped alert data. Aggregation-based behaviors
(SSH brute-force thresholds, DNS query-rate tunneling) are deliberately absent —
SigmaHQ itself parks those under `unsupported/` because event-level Sigma cannot
express them; those alerts are covered by the detection pipeline's own
threshold logic instead.

| File | Detects | ATT&CK |
|---|---|---|
| `proc_creation_win_powershell_encode.yml` | PowerShell launched with a Base64-encoded command | T1059.001 |
| `proc_creation_win_office_susp_child_processes.yml` | Office applications spawning script hosts / LOLBins | T1204.002, T1047, T1218.010 |
| `proc_creation_win_office_outlook_execution_from_temp.yml` | Executables running from Outlook's secure temp folder | T1566.001 |
| `proc_creation_win_schtasks_creation.yml` | Scheduled task created via schtasks.exe (SYSTEM-context tasks filtered out) | T1053.005 |
| `proc_creation_win_wmic_remote_execution.yml` | WMIC invoked against a remote node (`/node:`), localhost excluded | T1047 |
