🧩 Part 1: Setting Up My Azure Subscription

I started by creating a  Microsoft Azure subscription

Once my subscription was set up, I logged into the portal via portal.azure.com.

🛠️ Part 2: Creating the Honeypot (Virtual Machine)

Launched a Windows 10 Virtual Machine within Azure.

Selected a lightweight size (keeping billing in mind).

Important: I remembered the username and password as these would be used to simulate failed logins.

Went to Network Security Group and:

Created an Inbound Rule allowing all incoming traffic (purposefully exposing the machine).

Then:

Logged into the VM

Disabled the Windows Defender Firewall:

Start → Run wf.msc → Properties → Disabled all profiles (Domain, Private, Public)

🔍 Part 3: Simulating Attacks & Inspecting Logs

Attempted 3 failed logins as a fake user (e.g., employee).

Successfully logged into the VM.

Opened Event Viewer → Windows Logs → Security.

Found Event ID 4625 for failed login attempts.

This showed real-time audit logging was functional.

📊 Part 4: Forwarding Logs to Sentinel + Using KQL

Created a Log Analytics Workspace (LAW)

Provisioned a Microsoft Sentinel SIEM instance connected to that LAW.

Enabled the Windows Security Events via AMA connector

Created a Data Collection Rule (DCR) for Windows logs

Verified logs in Log Analytics using this simple KQL query:

SecurityEvent
| where EventId == 4625

🎯 Learned: KQL is very similar to SQL. For SOC jobs, knowing KQL/SQL/SPL is essential.

🌍 Part 5: Log Enrichment with GeoIP Data

Realized the logs only showed IP Addresses, no location data

To enrich:

Downloaded the GeoIP summarized CSV

In Microsoft Sentinel → Watchlist, created:

Name: geoip

Source Type: Local File

Search Key: network

Rows Loaded: ~55,000

Used KQL to join Security Logs with GeoIP data:

let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "<attacker IP>"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents

🌐 Part 6: Creating an Interactive Global Attack Map

In Sentinel Workbooks, created a new workbook

Deleted pre-populated elements → Added new Query Element

Opened Advanced Editor → Pasted JSON code from map.json

Observed the global attack locations on the map, based on enriched IP data

🔁 Next Steps & Learning Goals

Monitor bot attempts and develop custom detection rules

Set up alerts and automations (SOAR)

Explore Sentinel’s anomaly detection

Simulate malware or lateral movement in a safe range

