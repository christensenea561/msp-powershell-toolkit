# MSP PowerShell Toolkit

Interactive troubleshooting and administration scripts for multi-tenant Microsoft 365 and Windows estates, plus a WPF launcher that builds a form for any script automatically.

Each script covers a whole problem in one run. It checks every likely cause, prints a ranked findings table to the console, and writes the bulky data to CSV. You don't have to iterate one cmdlet at a time.

![Lint](https://github.com/christensenea561/msp-powershell-toolkit/actions/workflows/lint.yml/badge.svg)

## Contents

| Script | Scope | What it answers |
| --- | --- | --- |
| `scripts/tenant/Invoke-MailFlowTriage.ps1` | Exchange Online | Why didn't this message arrive, or where did it go? Covers message trace and hop detail, transport rules, connectors, recipient forwarding/rules/junk/quota, group restrictions, restricted senders, quarantine, allow/block lists, and SPF/DKIM/DMARC/MX. |
| `scripts/tenant/Invoke-CompromiseInvestigation.ps1` | Entra ID + EXO | Is this account compromised, and what did the attacker touch? Covers sign-ins (countries, legacy auth, tooling user agents, risk), new MFA methods, directory audits, OAuth grants, inbox rules, forwarding, delegates, unified audit, send spikes, phish lure recipients and purge, and guided containment. |
| `scripts/tenant/Get-PrivilegedAccessAudit.ps1` | Entra ID | Who holds admin roles, and how well are they protected? Covers active and PIM roles, admin MFA strength (phishing-resistant vs SMS-only vs none), stale/disabled/guest/synced admins, Global Admin count, tenant MFA registration, auth methods policy, CA coverage, app/SP credential changes, and IOC IP sign-in hunting. |
| `scripts/tenant/Test-DynamicGroupMembership.ps1` | Entra ID + EXO | Why is (or isn't) this user in the group, and what would a new rule change? Gives a per-clause rule evaluation with the actual attribute values, plus a full WouldAdd/WouldRemove preview. Supports Entra dynamic groups and Exchange DDGs. |
| `scripts/tenant/Get-SharePointPermissionReport.ps1` | SharePoint (PS7) | Who can see this site, library or folder? Covers site groups, broken inheritance, sharing links, guests, and Everyone grants. |
| `scripts/tenant/Invoke-UserLifecycle.ps1` | Entra ID + EXO + OneDrive | Onboard copies a template user's groups and licenses, checks seats, and handles DLs. Offboard takes a snapshot, then blocks sign-in, revokes sessions, sets up forwarding/delegates, converts to shared, removes groups/DLs, grants OneDrive access, and removes licenses only when it's safe. |
| `scripts/endpoint/Invoke-PatchTriage.ps1` | Windows (RMM) | Why is patching failing? Covers pending reboots, services, WSUS policy conflicts, HRESULTs decoded to causes, KB presence, and component store health, with an optional WU component reset and DISM/SFC. |
| `scripts/endpoint/Get-DefenderHealth.ps1` | Windows (RMM) | Is Defender actually protecting the device, and what is Intune seeing? Covers Defender vs Security Center mismatches, third-party AV, policy overrides, MDE onboarding, and events. |
| `scripts/endpoint/Remove-StrandedAgent.ps1` | Windows (RMM) | Removes a stranded agent silently. Handles MSI, Inno and NSIS uninstallers plus vendor profiles, kills hung msiexec, and reports or cleans up leftovers. |
| `scripts/endpoint/Get-ServerUsageAudit.ps1` | Windows Server (RMM) | Can this server be decommissioned? Covers interactive/RDP usage and weekly trend, network logon dependencies, shares and file activity, custom service accounts, inbound connections, and hosted roles. |
| `scripts/endpoint/Get-HyperVRdsHealth.ps1` | Hyper-V / RDS (RMM) | What happened during the outage or hang? Covers VM memory pressure, VHD growth vs free space, old checkpoints, replica health and cert expiry, perf snapshot, events around the incident time, memory by user, and RDS licensing/CALs/disconnect reasons. |
| `Start-ToolkitGui.ps1` / `.cmd` | Launcher | Pick a script, fill in the auto-generated form, and run it in its own console. |
| `Install-ToolkitPrereqs.ps1` | Setup | Installs the few modules required, for the current user. |
| `tests/Test-ToolkitSyntax.ps1` | CI | Parse errors, PS7-only syntax in 5.1 scripts, non-ASCII characters, and `exit` statements. |

## Design principles

- **Windows PowerShell 5.1 first.** There's no PS7-only syntax unless the script declares `#Requires -Version 7`, and CI enforces this.
- **Standalone files.** Every script carries its own helpers, so it works pasted into an untitled VS Code tab, uploaded to an RMM, or launched from the GUI.
- **Never kills the host.** There are no `exit` statements, and every section is wrapped so that one failure never stops the run or closes the session.
- **Triage at a glance.** Findings are ranked High/Medium/Low/Info in the console. Large output goes to `C:\Users\Public\Documents\MspToolkit\<Script>\<timestamp>\` as CSV, and the path is printed at the end. Endpoint scripts keep only the last 5 runs.
- **Tenant agnostic and safe for multi-tenant work.** There are no tenant names, IDs or app registrations in the code. The tenant comes from the admin UPN you sign in with. An existing Exchange session for a different account is disconnected first, and the connected tenant is printed so you can confirm it before any output is trusted.
- **Light dependencies.** All Graph calls are raw `Invoke-MgGraphRequest`, so only `Microsoft.Graph.Authentication` is needed. This avoids the full Graph SDK and the 5.1 function-count limit.
- **Read-only by default.** Changes need an explicit switch (`-Remediate`, `-PurgeLure`, `-ForceCleanup`) or a typed confirmation, and every destructive step asks first or snapshots state first.

## Quick start

```powershell
git clone https://github.com/christensenea561/msp-powershell-toolkit.git
cd msp-powershell-toolkit
Unblock-File -Path .\*.ps1, .\scripts\*\*.ps1
.\Install-ToolkitPrereqs.ps1
.\Start-ToolkitGui.cmd          # or run any script directly
```

Run a script directly. Any value you leave out is prompted for:

```powershell
.\scripts\tenant\Invoke-MailFlowTriage.ps1 -AdminUpn admin@contoso.onmicrosoft.com -RecipientAddress user@contoso.com -DaysBack 3
```

## Using endpoint scripts in NinjaOne (or another RMM)

1. Add the script as-is and set it to run as **SYSTEM**.
2. Optionally create script variables named the same as the parameters (for example `remediate`, `kbList`, `daysBack`). NinjaOne passes script variables to PowerShell as environment variables, and the scripts read them when the parameter isn't supplied. Checkbox values `true`/`1`/`yes` are treated as on. Check the variable naming against your NinjaOne version.
3. Console output is a compact findings table. Full CSVs stay on the device under `C:\Users\Public\Documents\MspToolkit`.

## Requirements

| Need | Used by |
| --- | --- |
| Windows PowerShell 5.1 | Everything except the SharePoint report |
| PowerShell 7.2+ and PnP.PowerShell | `Get-SharePointPermissionReport.ps1` (PnP 3.x needs PS 7.4) |
| ExchangeOnlineManagement 3.x | Mail flow, compromise, dynamic groups (DDG), lifecycle |
| Microsoft.Graph.Authentication 2.x | All Entra ID checks |
| Microsoft.Online.SharePoint.PowerShell | OneDrive step of offboarding (5.1 only) |
| Your own Entra app registration per tenant | PnP.PowerShell interactive sign-in (`-ClientId`) |
| Entra ID P1 / P2 | Sign-in logs, CA, registration reports (P1); risky users and PIM (P2). Scripts degrade gracefully without them. |

Delegated Graph scopes are listed in each script's help (`Get-Help .\scripts\tenant\<name>.ps1 -Full`). The first sign-in to a tenant may ask an admin to consent to the Microsoft Graph Command Line Tools app.

## Known caveats

- In Windows PowerShell 5.1, loading ExchangeOnlineManagement and Microsoft.Graph in the same session can occasionally fail with `Microsoft.Identity.Client` assembly errors when module versions disagree. If that happens, update both modules (`Install-ToolkitPrereqs.ps1 -UpdateExisting`) and start a fresh session. The GUI already runs every script in its own process.
- `Test-DynamicGroupMembership.ps1` uses the Graph **beta** `evaluateDynamicMembership` action.
- Message trace (`Get-MessageTraceV2`) returns at most 5000 rows per 10-day slice. The script reports when a slice is capped.

## License

MIT
