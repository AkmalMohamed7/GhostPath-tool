<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════╗
║   _______    _  ____  _____ _______  _____          _______ _    _    ║
║  / ____| |  | |/ __ \ / ____|__   __|  __ \    /\  |__   __| |  | |   ║
║ | |  __| |__| | |  | | (___    | |  | |__) |  /  \    | |  | |__| |   ║
║ | | |_ |  __  | |  | |\___ \   | |  |  ___/  / /\ \   | |  |  __  |   ║
║ | |__| | |  | | |__| |____) |  | |  | |     / ____ \  | |  | |  | |   ║
║  \_____|_|  |_|\____/|_____/   |_|  |_|    /_/    \_\ |_|  |_|  |_|   ║
║                                                                       ║
║              👻 GHOSTPATH — Active Directory Enumeration Tool          ║
║                          Version 2.0 · Team E                         ║
╚═══════════════════════════════════════════════════════════════════════╝
```

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?style=flat-square&logo=windows)
![Category](https://img.shields.io/badge/Category-AD%20Enumeration-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-success?style=flat-square)

> **A professional Active Directory enumeration tool for red teamers and security professionals.**  
> Identifies users, machines, and groups — including high-value targets like Kerberoastable accounts, AS-REP Roastable users, and privileged groups.

</div>

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Parameters](#-parameters)
- [Examples](#-examples)
- [Sample Output](#-sample-output)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

**GhostPath** is a PowerShell-based Active Directory enumeration tool built for offensive security engagements. It queries AD via LDAP and presents the results in a clean, color-coded terminal interface — making it easy to spot high-value targets quickly.

It is designed to run from a domain-joined machine or with valid domain credentials, requiring no third-party dependencies.

---

## ✨ Features

| Category | What GhostPath Does |
|---|---|
| 👤 **User Enumeration** | Lists all domain users, flags AS-REP Roastable accounts and Kerberoastable (SPN) users |
| 🖥️ **Machine Enumeration** | Lists all domain computers grouped by Operating System with DNS hostnames |
| 🔐 **Group Enumeration** | Separates built-in groups from custom groups, highlights privileged groups (Domain Admins, Enterprise Admins, etc.) |
| 🎯 **Targeted Queries** | Drill into a specific object by name and retrieve any or all of its LDAP properties |
| 🎨 **Clean Output** | Color-coded terminal output with structured sections for fast triage |

---

## ⚙️ Requirements

- Windows PowerShell 5.1 or later
- Must be run from a **domain-joined machine** or with domain credentials
- No external modules or dependencies required

---

## 📦 Installation

```powershell
# Clone the repository
git clone https://github.com/TeamE/GhostPath-tool.git

# Navigate to the directory
cd GhostPath-tool

# If execution policy blocks the script, allow it for the current session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

---

## 🚀 Usage

```powershell
.\GhostPath.ps1 [-ObjType <type>] [-Name <name>] [-Propertie <property>] [-PDC <server>] [-DN <dn>] [-Help]
```

---

## 📋 Parameters

| Parameter | Type | Description |
|---|---|---|
| `-ObjType` | String | Object type: `U` (Users), `M` (Machines), `G` (Groups). Omit to enumerate all. |
| `-Name` | String | Name of a specific object to query (e.g., `"jdoe"`, `"DC01"`) |
| `-Propertie` | String | A specific LDAP property to retrieve, or `*` to retrieve all properties |
| `-PDC` | String | Override the Primary Domain Controller (default: auto-detected) |
| `-DN` | String | Override the Distinguished Name (default: current domain) |
| `-Help` | Switch | Display the help menu |

---

## 💡 Examples

**Enumerate everything (Users, Machines, Groups):**
```powershell
.\GhostPath.ps1
```

**Enumerate only Users:**
```powershell
.\GhostPath.ps1 -ObjType U
```

**Enumerate only Machines:**
```powershell
.\GhostPath.ps1 -ObjType M
```

**Enumerate only Groups:**
```powershell
.\GhostPath.ps1 -ObjType G
```

**Get all LDAP properties for a specific user:**
```powershell
.\GhostPath.ps1 -ObjType U -Name "jdoe" -Propertie *
```

**Get a specific property for a user:**
```powershell
.\GhostPath.ps1 -ObjType U -Name "jdoe" -Propertie "memberof"
```

**Get all properties for a specific machine:**
```powershell
.\GhostPath.ps1 -ObjType M -Name "DC01" -Propertie *
```

**Target a specific Domain Controller and Distinguished Name:**
```powershell
.\GhostPath.ps1 -PDC "DC01.corp.local" -DN "DC=corp,DC=local"
```

---

## 📸 Sample Output

```text
╔═══════════════════════════════════════════════════════════════════════╗
║              👻 GHOSTPATH - AD ENUMERATION TOOL 👻                   ║
║                       Version 2.0 - Professional                      ║
╚═══════════════════════════════════════════════════════════════════════╝

  [+] Target Domain: DC=CONTOSO,DC=LOCAL
  [+] Primary DC   : DC01.CONTOSO.LOCAL
  [+] LDAP Path    : LDAP://DC01.CONTOSO.LOCAL/DC=CONTOSO,DC=LOCAL

══════════════════════════════════════════════════════════════════════════
                           USERS ENUMERATION
══════════════════════════════════════════════════════════════════════════

[+] Found 154 user accounts

┌─ ⚠ VULNERABLE USERS (AS-REP Roasting)
└──────────────────────────────────────────────────────────────────────
  [!] svc_backup
      Description: Backup service - preauthentication disabled

┌─ [KEY] SERVICE ACCOUNTS (Kerberoasting Target)
└──────────────────────────────────────────────────────────────────────
  [SPN] MSSQL_SVC
        SPN: MSSQLSvc/sqlserver.contoso.local:1433
        MemberOf: Domain Users

┌─ [USER] REGULAR USER ACCOUNTS
└──────────────────────────────────────────────────────────────────────
  [1] Administrator
  [2] jdoe
      └─ Description: John Doe - IT Department
  [3] asmith

══════════════════════════════════════════════════════════════════════════
                        ⚠ PRIVILEGED GROUPS
══════════════════════════════════════════════════════════════════════════
[!] These groups have special privileges - worth investigating!

  [!] Domain Admins
      └─ Designated administrators of the domain
  [!] Enterprise Admins

┌─ [LIST] BUILT-IN GROUPS
└──────────────────────────────────────────────────────────────────────
  [B] Users
  [B] Guests
  [B] Remote Desktop Users

┌─ [+] CUSTOM GROUPS
└──────────────────────────────────────────────────────────────────────
  [C] IT_HelpDesk  <- Custom Group
      ├─ Members: 5 member(s)
      │  └─ CN=Alice,OU=Users,DC=contoso,DC=local
      │  └─ CN=Bob,OU=Users,DC=contoso,DC=local
      │  └─ ... and 3 more
      └─ MemberOf: Remote Desktop Users

────────────────────────────────────────────────────────────────────────
  [GHOST] GhostPath Enumeration Complete
  [+] Scan finished at 2024-06-01 14:30:22
────────────────────────────────────────────────────────────────────────
```

---

## ⚠️ Disclaimer

> **GhostPath is intended for authorized security assessments only.**  
> Use of this tool against systems without explicit written permission is illegal and unethical.  
> The authors assume no responsibility for misuse or damage caused by this tool.  
> Always obtain proper authorization before conducting any security testing.

---

<div align="center">

Made with ☕ by **Team E** · Version 2.0

</div>
