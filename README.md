
# GhostPath - Active Directory Enumeration Tool

GhostPath is a professional Active Directory enumeration tool designed for red teamers and security professionals. It enumerates Users, Machines, and Groups from Active Directory with a clean, high-contrast interface.

## 👻 The Tool Shape

When you run GhostPath, you are greeted with the following banner and connection status:

```text
╔═══════════════════════════════════════════════════════════════════════╗
║   _______    _  ____  _____ _______  _____          _______ _    _    ║
║  / ____| |  | |/ __ \ / ____|__   __|  __ \    /\  |__   __| |  | |   ║
║ | |  __| |__| | |  | | (___    | |  | |__) |  /  \    | |  | |__| |   ║
║ | | |_ |  __  | |  | |\___ \   | |  |  ___/  / /\ \   | |  |  __  |   ║
║ | |__| | |  | | |__| |____) |  | |  | |     / ____ \  | |  | |  | |   ║
║  \_____|_|  |_|\____/|_____/   |_|  |_|    /_/    \_\ |_|  |_|  |_|   ║
║                                                                       ║
║                 👻 GHOSTPATH - AD ENUMERATION TOOL 👻                ║
║                       Version 2.0 - Professional                      ║
╚═══════════════════════════════════════════════════════════════════════╝

  [+] Target Domain: CONTOSO.LOCAL
  [+] Primary DC   : DC01.CONTOSO.LOCAL
  [+] LDAP Path   : LDAP://DC01.CONTOSO.LOCAL/DC=CONTOSO,DC=LOCAL

────────────────────────────────────────────────────────────────────────────
```

## 🚀 Features

- **User Enumeration**: Identifies regular users, AS-REP roastable users, and Kerberoastable (SPN) users.
- **Machine Enumeration**: Lists domain computers grouped by Operating System.
- **Group Enumeration**: Smartly distinguishes between Built-in/Default groups and Custom groups, with special highlighting for Privileged Groups (e.g., Domain Admins).
- **Detailed Inspection**: Ability to drill down into specific objects to view all properties.

## 📋 Usage

```powershell
.\GhostPath.ps1 [-ObjType <type>] [-Name <name>] [-Propertie <property>]
```

### Parameters

- `-ObjType <type>`: Object type to enumerate
  - `U`: Users
  - `M`: Machines/Computers
  - `G`: Groups
- `-Name <name>`: Specific object name to query (e.g., "admin")
- `-Propertie <prop>`: Specific property to retrieve (use `*` for all)
- `-PDC <server>`: Specify a Primary Domain Controller
- `-DN <distinguishedName>`: Specify the Distinguished Name
- `-Help`: Show the help menu

### Examples

```powershell
# Enumerate everything (Users, Machines, Groups)
.\GhostPath.ps1

# Enumerate only Users
.\GhostPath.ps1 -ObjType U

# Enumerate only Machines
.\GhostPath.ps1 -ObjType M

# Get all properties for a specific user "jdoe"
.\GhostPath.ps1 -ObjType U -Name "jdoe" -Propertie *
```

## 📸 Sample Output

Here is what a typical enumeration scan looks like:

```text
==========================================================================
                             USERS ENUMERATION                            
==========================================================================

┌─ 🔍 STATISTICS
└──────────────────────────────────────────────────────────────────────
  [+] Total Users Found: 154
  [+] AS-REP Roastable : 0
  [+] Kerberoastable   : 2

┌─ 🔥 KERBEROASTABLE USERS (SPN)
└──────────────────────────────────────────────────────────────────────
  [!] Found 2 accounts with Service Principal Names
  
  [U] MSSQL_SVC
      └─ Description: SQL Server Service Account
  [U] IIS_Service
      └─ Description: Web Server Identity

==========================================================================
                           MACHINES ENUMERATION                           
==========================================================================

┌─ 💻 OPERATING SYSTEMS
└──────────────────────────────────────────────────────────────────────
  [+] Windows Server 2019 Datacenter (2)
      ├─ DC01.contoso.local
      └─ FILE01.contoso.local

  [+] Windows 10 Enterprise (15)
      ├─ HR-PC01.contoso.local
      ├─ DEV-WRK01.contoso.local
      └─ ...

==========================================================================
                            GROUPS ENUMERATION                            
==========================================================================

==========================================================================
                          ⚠ PRIVILEGED GROUPS                             
==========================================================================
[!] These groups have special privileges - worth investigating!

  [!] Domain Admins
      └─ Designated administrators of the domain
  [!] Enterprise Admins
      └─ Designated administrators of the enterprise

┌─ 📋 BUILT-IN GROUPS
└──────────────────────────────────────────────────────────────────────
[*] Found 42 default/built-in groups
  [B] Users
  [B] Guests
  ...

┌─ ➕ CUSTOM GROUPS
└──────────────────────────────────────────────────────────────────────
[*] Found 3 custom groups

  [C] IT_HelpDesk ← Custom Group
      ├─ Members: 5 member(s)
      │  └─ CN=Alice,OU=Users,DC=contoso,DC=local
      │  └─ CN=Bob,OU=Users,DC=contoso,DC=local
      │  └─ ... and 2 more
      └─ MemberOf: Remote Desktop Users

────────────────────────────────────────────────────────────────────────────
  👻 GhostPath Enumeration Complete
  [+] Scan finished at 2023-11-15 14:30:22
────────────────────────────────────────────────────────────────────────────
```

## 📝 Author & Version

- **Author**: Team E
- **Version**: 2.0
