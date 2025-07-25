
# 🛡️ Cybersecurity Honeypot Project on Azure

This project demonstrates how I built a cloud-based honeypot, simulated brute force attacks, and monitored them using Microsoft Sentinel.

---

## 🧩 Part 1: Setting Up My Azure Subscription

- Created a **Microsoft Azure** subscription.
- Logged into the Azure portal: [https://portal.azure.com](https://portal.azure.com)

---

## 🛠️ Part 2: Creating the Honeypot (Virtual Machine)

- Create a VM in Microsoft Azure
- Launched a **Windows 10 Virtual Machine** in Azure.
- Selected a **lightweight VM size** to optimize for cost.
- **Saved** the VM’s **username and password** for future login attempts.

<img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/Set%20up%20a%20Vulnerable%20VM%20in%20Azure.png?raw=true"/>

### 🔒 Network Security Group Configuration:

- Created an **Inbound Rule**:
  - **Allowed all incoming traffic** (intentionally exposing the VM to threats).
 
  <img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/Changing_Inbound_rules.png?raw=true"/>

### 🔧 Inside the VM:

- **Logged in to the VM**
- **Disabled Windows Defender Firewall**:
  - `Start` → `Run` → `wf.msc`
  - Disabled all profiles: **Domain**, **Private**, and **Public**

<img src="https://i.imgur.com/D4uFicX.png" height="100%" width="100%" alt="FIREWALL-OFF"/>

---

## 🔍 Part 3: Simulating Attacks & Inspecting Logs

- Simulated **3 failed login attempts** as a fake user (e.g., `employee`)
- Successfully logged in afterward
- Opened **Event Viewer** → `Windows Logs` → `Security`
- Found **Event ID 4625** indicating failed login attempts

✅ Confirmed that real-time audit logging was functional.

<img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/Logs%20(%20Got%20Attacked%20all%20over%20the%20world%20in%20mintues%20).png?raw=true"/>
---

## 📊 Part 4: Forwarding Logs to Sentinel + Using KQL

1. **Created a Log Analytics Workspace (LAW)**
2. **Provisioned Microsoft Sentinel** connected to that LAW
3. **Enabled Windows Security Events** using the AMA connector
4. **Created a Data Collection Rule (DCR)** to collect Windows logs

### 🔎 Verified with KQL:

```kql
SecurityEvent
| where EventId == 4625
```

> 💡 **KQL** (Kusto Query Language) is similar to SQL. Essential for SOC analysts!

---

## 🌍 Part 5: Log Enrichment with GeoIP Data

### 🔎 Problem:
Security logs only showed **IP addresses**, but lacked **geolocation data**.

### ✅ Solution:
- Downloaded a **GeoIP summarized CSV**
- In **Microsoft Sentinel → Watchlist**, created:

  | Field         | Value         |
  |---------------|---------------|
  | Name          | `geoip`       |
  | Source Type   | Local File    |
  | Search Key    | `network`     |
  | Rows Loaded   | ~55,000       |

<img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/Watchlist_Overview.png?raw=true">
### 🧠 Used KQL to Join Security Logs with GeoIP:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
| where IpAddress == ""
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

<img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/KQL_Query_Results.png?raw=true">
---

## 🌐 Part 6: Creating an Interactive Global Attack Map

1. Opened **Microsoft Sentinel → Workbooks**
2. Created a **new workbook**
3. Deleted all **default visuals**
4. Added a new **Query Element**
5. Opened the **Advanced Editor**
6. Pasted JSON code from `map.json`
7. Visualized **global attack sources** using enriched IP geolocation data

<img src="https://github.com/codehamza936/azure-cybersecurity-home-lab/blob/main/Screenshots/VM_Attack_Map_final.png?raw=true">

---

## 🔁 Next Steps & Learning Goals

- 🛡️ **Monitor** bot attacks and brute force login attempts
- 🔔 **Set up alerts** and automated playbooks using SOAR
- 📈 **Explore anomaly detection** features in Sentinel
- 🧪 **Simulate malware/lateral movement** in a controlled test lab

---

> 🚀 **Goal**: Build real-world SOC (Security Operations Center) skills using **Microsoft Sentinel**, **KQL**, and cloud-native threat detection tools.
