<#
.SYNOPSIS
    GhostPath - Active Directory Enumeration Tool
    
.DESCRIPTION
    A professional Active Directory enumeration tool for red teamers and security professionals.
    Enumerates Users, Machines, and Groups from Active Directory.
    
.PARAMETER ObjType
    Type of object to enumerate: U (Users), M (Machines), G (Groups)
    
.PARAMETER PDC
    Primary Domain Controller (default: current domain PDC)
    
.PARAMETER DN
    Distinguished Name (default: current domain)
    
.PARAMETER Propertie
    Specific property to retrieve from objects
    
.PARAMETER Name
    Specific object name to query
    
.PARAMETER Help
    Show this help message
    
.EXAMPLE
    .\GhostPath.ps1              # Enumerate all (Users, Machines, Groups)
    
.EXAMPLE
    .\GhostPath.ps1 -ObjType U   # Enumerate only Users
    
.EXAMPLE
    .\GhostPath.ps1 -ObjType M   # Enumerate only Machines
    
.EXAMPLE
    .\GhostPath.ps1 -ObjType G   # Enumerate only Groups
    
.EXAMPLE
    .\GhostPath.ps1 -ObjType U -Name "admin" -Propertie *  # Get all properties for user "admin"

.NOTES
    Author: Team E
    Version: 2.0 (GhostPath Redesign)
    Category: Active Directory Enumeration
#>

Param(
    [string]$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.name,
    [string]$DN = ([adsi]'').distinguishedName,
    [string]$ObjType = '',
    [string]$Propertie = '',
    [string]$Name = '',
    [switch]$Help
)

# ============================================
# COLOR PALETTE - Professional Cybersecurity Theme
# ============================================
$Colors = @{
    # Primary Colors
    'Banner'          = 'Cyan'
    'Section'        = 'Magenta'
    'SubSection'     = 'Yellow'
    
    # Status Colors
    'Success'        = 'Green'
    'Warning'        = 'Yellow'
    'Danger'         = 'Red'
    'Info'           = 'Cyan'
    
    # Data Colors
    'Key'            = 'White'
    'Value'          = 'Green'
    'Highlight'      = 'Yellow'
    'Separator'      = 'DarkGray'
}

# Helper function to write colored output
function Write-Color {
    param(
        [string]$Text,
        [string]$Color = 'White',
        [switch]$NoNewLine = $false
    )
    if ($NoNewLine) {
        Write-Host -ForegroundColor $Color $Text -NoNewline
    } else {
        Write-Host -ForegroundColor $Color $Text
    }
}

# ============================================
# PROFESSIONAL BANNER
# ============================================
function Show-Banner {
    Write-Host ""
    Write-Color "╔═══════════════════════════════════════════════════════════════════════╗" $Colors.Banner
    Write-Color "║   _______    _  ____  _____ _______  _____          _______ _    _    ║" $Colors.Banner
    Write-Color "║  / ____| |  | |/ __ \ / ____|__   __|  __ \    /\  |__   __| |  | |   ║" $Colors.Banner
    Write-Color "║ | |  __| |__| | |  | | (___    | |  | |__) |  /  \    | |  | |__| |   ║" $Colors.Banner
    Write-Color "║ | | |_ |  __  | |  | |\___ \   | |  |  ___/  / /\ \   | |  |  __  |   ║" $Colors.Banner
    Write-Color "║ | |__| | |  | | |__| |____) |  | |  | |     / ____ \  | |  | |  | |   ║" $Colors.Banner
    Write-Color "║  \_____|_|  |_|\____/|_____/   |_|  |_|    /_/    \_\ |_|  |_|  |_|   ║" $Colors.Banner
    Write-Color "║                                                                       ║" $Colors.Banner
    Write-Color "║                 👻 GHOSTPATH - AD ENUMERATION TOOL 👻                ║" $Colors.Banner
    Write-Color "║                       Version 2.0 - Professional                      ║" $Colors.Banner
    Write-Color "╚═══════════════════════════════════════════════════════════════════════╝" $Colors.Banner
    Write-Host ""
    Write-Color "  [+]" $Colors.Success -NoNewLine; Write-Host " Target Domain: $DN" $Colors.Key
    Write-Color "  [+]" $Colors.Success -NoNewLine; Write-Host " Primary DC   : $PDC" $Colors.Key
    Write-Color "  [+]" $Colors.Success -NoNewLine; Write-Host " LDAP Path   : LDAP://$PDC/$DN" $Colors.Key
    Write-Host ""
    Write-Host ("─" * 76) $Colors.Separator
    Write-Host ""
}

# ============================================
# HELP FUNCTION
# ============================================
function Show-Help {
    Show-Banner
    Write-Color "USAGE:" $Colors.Section
    Write-Host ""
    Write-Host "  .\GhostPath.ps1 [-ObjType <type>] [-Name <name>] [-Propertie <property>]" $Colors.Key
    Write-Host ""
    Write-Color "PARAMETERS:" $Colors.Section
    Write-Host ""
    Write-Host "  -ObjType <type>    Object type to enumerate:" $Colors.Key
    Write-Host "                     U - Users" $Colors.Value
    Write-Host "                     M - Machines/Computers" $Colors.Value
    Write-Host "                     G - Groups" $Colors.Value
    Write-Host ""
    Write-Host "  -Name <name>       Specific object name to query" $Colors.Key
    Write-Host ""
    Write-Host "  -Propertie <prop>  Specific property to retrieve (use * for all)" $Colors.Key
    Write-Host ""
    Write-Host "  -Help              Show this help message" $Colors.Key
    Write-Host ""
    Write-Color "EXAMPLES:" $Colors.Section
    Write-Host ""
    Write-Host "  Enumerate all objects:" $Colors.Warning
    Write-Host "    .\GhostPath.ps1" $Colors.Key
    Write-Host ""
    Write-Host "  Enumerate only users:" $Colors.Warning
    Write-Host "    .\GhostPath.ps1 -ObjType U" $Colors.Key
    Write-Host ""
    Write-Host "  Enumerate only machines:" $Colors.Warning
    Write-Host "    .\GhostPath.ps1 -ObjType M" $Colors.Key
    Write-Host ""
    Write-Host "  Enumerate only groups:" $Colors.Warning
    Write-Host "    .\GhostPath.ps1 -ObjType G" $Colors.Key
    Write-Host ""
    Write-Host "  Get specific user properties:" $Colors.Warning
    Write-Host "    .\GhostPath.ps1 -ObjType U -Name \"admin\" -Propertie *" $Colors.Key
    Write-Host ""
    Write-Host ("─" * 76) $Colors.Separator
    Write-Host ""
    exit
}

# ============================================
# SECTION SEPARATOR
# ============================================
function Write-SectionHeader {
    param([string]$Title, [string]$Symbol = "=")
    $width = 74
    $padding = ($width - $Title.Length - 2) / 2
    $border = $Symbol * $width
    Write-Host ""
    Write-Color $border $Colors.Section
    Write-Color (" " * [int]$padding + $Title + " " * [int]$padding) $Colors.Section
    Write-Color $border $Colors.Section
    Write-Host ""
}

function Write-Subsection {
    param([string]$Title)
    Write-Host ""
    Write-Color "┌─ $Title" $Colors.SubSection
    Write-Color "└" $Colors.SubSection -NoNewLine
    Write-Host ("─" * 70) $Colors.Separator
}

# ============================================
# MAIN LDAP CONNECTION
# ============================================
$LDAPpath = "LDAP://$PDC/$DN"
try {
    $Entry = New-Object System.DirectoryServices.DirectoryEntry("$LDAPpath")
} catch {
    Write-Color "[ERROR] Failed to connect to LDAP: $_" $Colors.Danger
    exit 1
}

# ============================================
# USERS ENUMERATION
# ============================================
function Users-S {
    Write-SectionHeader "USERS ENUMERATION" "═"
    Write-Color "[*] Scanning Active Directory users..." $Colors.Info
    Write-Host ""
    
    $DirSerUsers = New-Object System.DirectoryServices.DirectorySearcher($Entry, "(&(objectCategory=User)(objectClass=User)(samAccountType=805306368))")
    $Users = $DirSerUsers.FindAll()
    
    Write-Color "[+] Found $($Users.Count) user accounts" $Colors.Success
    Write-Host ""
    
    # Handle specific property query
    if ($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne '') {
        $Obj = $Users | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] Property '$Propertie' for user '$Name':" $Colors.Info
            $Obj.Properties["$Propertie"]
        }
        return
    }
    
    if ($Propertie -eq "*" -and $Name -ne '') {
        $Obj = $Users | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] All properties for user '$Name':" $Colors.Info
            $Obj.Properties
        }
        return
    }
    
    # Separate users by category
    $SPNUsers = @()
    $ASREPRoastable = @()
    $RegularUsers = @()
    
    foreach ($User in $Users) {
        $userAccountControl = [int]$User.Properties["userAccountControl"][0]
        
        if ($User.Properties["serviceprincipalname"] -ne $null) {
            $SPNUsers += $User
        } elseif (($userAccountControl -band 0x400000) -eq 0x400000) {
            $ASREPRoastable += $User
        } else {
            $RegularUsers += $User
        }
    }
    
    # Display AS-REP Roasting Vulnerable Users (CRITICAL)
    if ($ASREPRoastable.Count -gt 0) {
        Write-Subsection "⚠ VULNERABLE USERS (AS-REP Roasting)"
        Write-Color "[!] Found $($ASREPRoastable.Count) users vulnerable to AS-REP Roasting!" $Colors.Danger
        Write-Host ""
        foreach ($User in $ASREPRoastable) {
            Write-Color "  [!] " $Colors.Danger -NoNewLine
            Write-Color $User.Properties["sAMAccountName"] $Colors.Danger
            if ($User.Properties["description"] -ne $null) {
                Write-Color "      Description: " $Colors.Warning -NoNewLine
                Write-Host $User.Properties["description"] $Colors.Key
            }
        }
        Write-Host ""
    }
    
    # Display Service Account Users (SPN)
    if ($SPNUsers.Count -gt 0) {
        Write-Subsection "🔑 SERVICE ACCOUNTS (Kerberoasting Target)"
        Write-Color "[*] Found $($SPNUsers.Count) users with SPN (Potential Kerberoasting)" $Colors.Warning
        Write-Host ""
        foreach ($SPN in $SPNUsers) {
            Write-Color "  [SPN] " $Colors.Info -NoNewLine
            Write-Color $SPN.Properties["sAMAccountName"] $Colors.Key
            Write-Color "      SPN: " $Colors.SubSection -NoNewLine
            Write-Host $SPN.Properties["serviceprincipalname"] $Colors.Value
            if ($SPN.Properties["description"] -ne $null) {
                Write-Color "      Description: " $Colors.Warning -NoNewLine
                Write-Host $SPN.Properties["description"] $Colors.Key
            }
            Write-Color "      MemberOf: " $Colors.Section -NoNewLine
            Write-Host ($SPN.Properties["memberof"] -join ", ") $Colors.Key
            Write-Host ""
        }
    }
    
    # Display Regular Users
    Write-Subsection "👤 REGULAR USER ACCOUNTS"
    Write-Color "[*] Found $($RegularUsers.Count) regular user accounts" $Colors.Success
    Write-Host ""
    
    $userNum = 1
    foreach ($User in $RegularUsers) {
        Write-Color "  [$userNum] " $Colors.Success -NoNewLine
        Write-Color $User.Properties["sAMAccountName"] $Colors.Key
        if ($User.Properties["description"] -ne $null) {
            Write-Color "      └─ Description: " $Colors.Warning -NoNewLine
            Write-Host $User.Properties["description"] $Colors.Separator
        }
        $userNum++
    }
    
    Write-Host ""
    Write-Color "[+] Users enumeration complete" $Colors.Success
}

# ============================================
# MACHINES ENUMERATION
# ============================================
function Machines-S {
    Write-SectionHeader "MACHINES ENUMERATION" "═"
    Write-Color "[*] Scanning Active Directory machines..." $Colors.Info
    Write-Host ""
    
    $DirSerMachines = New-Object System.DirectoryServices.DirectorySearcher($Entry, "(&(objectCategory=computer)(objectClass=computer)(samAccountType=805306369))")
    $Machines = $DirSerMachines.FindAll()
    
    Write-Color "[+] Found $($Machines.Count) machine accounts" $Colors.Success
    Write-Host ""
    
    # Handle specific property query
    if ($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne '') {
        $Obj = $Machines | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] Property '$Propertie' for machine '$Name':" $Colors.Info
            $Obj.Properties["$Propertie"]
        }
        return
    }
    
    if ($Propertie -eq "*" -and $Name -ne '') {
        $Obj = $Machines | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] All properties for machine '$Name':" $Colors.Info
            $Obj.Properties
        }
        return
    }
    
    Write-Subsection "🖥 DOMAIN COMPUTERS"
    Write-Host ""
    
    # Group machines by OS for better readability
    $OSGroups = @{}
    foreach ($Machine in $Machines) {
        $OS = $Machine.Properties["operatingsystem"]
        if ($OS -eq $null) { $OS = "Unknown OS" }
        if (-not $OSGroups.ContainsKey($OS)) {
            $OSGroups[$OS] = @()
        }
        $OSGroups[$OS] += $Machine
    }
    
    # Display by OS
    foreach ($OS in $OSGroups.Keys | Sort-Object) {
        $machinesInGroup = $OSGroups[$OS]
        Write-Color "  ┌─ $OS ($($machinesInGroup.Count))" $Colors.SubSection
        Write-Color "  │" $Colors.Separator
        
        foreach ($Machine in $machinesInGroup) {
            $compName = $Machine.Properties["sAMAccountName"] -replace '\$', ''
            $dnsName = $Machine.Properties["dnshostname"]
            $osVer = $Machine.Properties["operatingsystemversion"]
            
            Write-Color "  ├─ " $Colors.Info -NoNewLine
            Write-Color $compName $Colors.Key
            if ($dnsName) {
                Write-Color "    └─ DNS: " $Colors.Warning -NoNewLine
                Write-Host $dnsName $Colors.Value
            }
            if ($osVer) {
                Write-Color "         OS Ver: " $Colors.Separator -NoNewLine
                Write-Host $osVer $Colors.Key
            }
        }
        Write-Host "  │" $Colors.Separator
    }
    
    Write-Host ""
    Write-Color "[+] Machines enumeration complete" $Colors.Success
}

# ============================================
# GROUPS ENUMERATION
# ============================================
function Groups-S {
    Write-SectionHeader "GROUPS ENUMERATION" "═"
    Write-Color "[*] Scanning Active Directory groups..." $Colors.Info
    Write-Host ""
    
    $DirSerGroups = New-Object System.DirectoryServices.DirectorySearcher($Entry, "(&(objectCategory=group)(objectClass=group))")
    $Groups = $DirSerGroups.FindAll()
    
    Write-Color "[+] Found $($Groups.Count) group accounts" $Colors.Success
    Write-Host ""
    
    # Handle specific property query
    if ($Propertie -ne '' -and $Propertie -ne "*" -and $Name -ne '') {
        $Obj = $Groups | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] Property '$Propertie' for group '$Name':" $Colors.Info
            $Obj.Properties["$Propertie"]
        }
        return
    }
    
    if ($Propertie -eq "*" -and $Name -ne '') {
        $Obj = $Groups | Where-Object { $_.Properties["sAMAccountName"] -eq "$Name" -or $_.Properties["cn"] -eq "$Name" }
        if ($Obj) {
            Write-Color "[*] All properties for group '$Name':" $Colors.Info
            $Obj.Properties
        }
        return
    }
    
    # Separate default vs custom groups
    $DefaultGroups = @()
    $CustomGroups = @()
    
    foreach ($Group in $Groups) {
        $isDefault = $false
        foreach ($DefaultGroup in $GroupList) {
            if ($Group.Properties["sAMAccountName"] -eq $DefaultGroup) {
                $isDefault = $true
                break
            }
        }
        if ($isDefault) {
            $DefaultGroups += $Group
        } else {
            $CustomGroups += $Group
        }
    }
    
    # Display High-Value/Privileged Groups First
    $PrivilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
                          "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
                          "Remote Desktop Users", "Network Configuration Operators", "DNS Admins")
    
    Write-SectionHeader "⚠ PRIVILEGED GROUPS" "═"
    Write-Color "[!] These groups have special privileges - worth investigating!" $Colors.Danger
    Write-Host ""
    
    foreach ($Group in $Groups) {
        $gName = $Group.Properties["sAMAccountName"]
        if ($PrivilegedGroups -contains $gName) {
            Write-Color "  [!] " $Colors.Danger -NoNewLine
            Write-Color $gName $Colors.Danger
            if ($Group.Properties["description"] -ne $null) {
                Write-Color "      └─ " $Colors.Warning -NoNewLine
                Write-Host $Group.Properties["description"] $Colors.Separator
            }
        }
    }
    Write-Host ""
    
    # Display Default Groups
    Write-Subsection "📋 BUILT-IN GROUPS"
    Write-Color "[*] Found $($DefaultGroups.Count) default/built-in groups" $Colors.Info
    Write-Host ""
    
    foreach ($Group in $DefaultGroups) {
        Write-Color "  [B] " $Colors.Section -NoNewLine
        Write-Color $Group.Properties["sAMAccountName"] $Colors.Key
        if ($Group.Properties["description"] -ne $null) {
            Write-Color "      └─ " $Colors.Warning -NoNewLine
            Write-Host $Group.Properties["description"] $Colors.Separator
        }
    }
    Write-Host ""
    
    # Display Custom Groups
    Write-Subsection "➕ CUSTOM GROUPS"
    Write-Color "[*] Found $($CustomGroups.Count) custom groups" $Colors.Success
    Write-Host ""
    
    foreach ($Group in $CustomGroups) {
        Write-Color "  [C] " $Colors.Success -NoNewLine
        Write-Color $Group.Properties["sAMAccountName"] $Colors.Key
        Write-Color " ← Custom Group" $Colors.SubSection
        
        $members = $Group.Properties["member"]
        if ($members -and $members.Count -gt 0) {
            Write-Color "      ├─ Members: " $Colors.Info -NoNewLine
            Write-Host "$($members.Count) member(s)" $Colors.Value
            foreach ($member in $members | Select-Object -First 3) {
                Write-Color "      │  └─ " $Colors.Separator -NoNewLine
                Write-Host $member $Colors.Key
            }
            if ($members.Count -gt 3) {
                Write-Color "      │  └─ ... and $($members.Count - 3) more" $Colors.Warning
            }
        }
        
        $memberof = $Group.Properties["memberof"]
        if ($memberof -and $memberof.Count -gt 0) {
            Write-Color "      └─ MemberOf: " $Colors.Section -NoNewLine
            Write-Host ($memberof[0..2] -join ", ") $Colors.Key
        }
        Write-Host ""
    }
    
    Write-Color "[+] Groups enumeration complete" $Colors.Success
}

# ============================================
# GROUP LIST (Built-in AD Groups)
# ============================================
$GroupList = @(
    "Access Control Assistance Operators",
    "Account Operators",
    "Administrators",
    "Allowed RODC Password Replication",
    "Backup Operators",
    "Certificate Service DCOM Access",
    "Cert Publishers",
    "Cloneable Domain Controllers",
    "Cryptographic Operators",
    "Denied RODC Password Replication",
    "Device Owners",
    "DHCP Administrators",
    "DHCP Users",
    "Distributed COM Users",
    "DnsUpdateProxy",
    "DnsAdmins",
    "Domain Admins",
    "Domain Computers",
    "Domain Controllers",
    "Domain Guests",
    "Domain Users",
    "Enterprise Admins",
    "Enterprise Key Admins",
    "Enterprise Read-only Domain Controllers",
    "Event Log Readers",
    "Group Policy Creator Owners",
    "Guests",
    "Hyper-V Administrators",
    "IIS_IUSRS",
    "Incoming Forest Trust Builders",
    "Key Admins",
    "Network Configuration Operators",
    "Performance Log Users",
    "Performance Monitor Users",
    "Print Operators",
    "Protected Users",
    "RAS and IAS Servers",
    "RDS Endpoint Servers",
    "RDS Management Servers",
    "RDS Remote Access Servers",
    "Read-only Domain Controllers",
    "Remote Desktop Users",
    "Remote Management Users",
    "Replicator",
    "Schema Admins",
    "Server Operators",
    "Storage Replica Administrators",
    "System Managed Accounts",
    "System Managed Accounts Group",
    "Terminal Server License Servers",
    "Users",
    "Windows Authorization Access",
    "WinRMRemoteWMIUsers_",
    "Allowed RODC Password Replication Group",
    "Denied RODC Password Replication Group",
    "Windows Authorization Access Group",
    "Pre-Windows 2000 Compatible Access"
)

# ============================================
# MAIN EXECUTION
# ============================================

# Show help if requested
if ($Help) {
    Show-Help
}

# Show banner
Show-Banner

# Execute based on ObjType
switch ($ObjType) {
    "U" {
        Users-S
    }
    "M" {
        Machines-S
    }
    "G" {
        Groups-S
    }
    Default {
        # Enumerate all if no type specified
        Users-S
        Machines-S
        Groups-S
    }
}

# Footer
Write-Host ""
Write-Host ("─" * 76) $Colors.Separator
Write-Color "  👻 GhostPath Enumeration Complete" $Colors.Banner
Write-Color "  [+]" $Colors.Success -NoNewLine; Write-Host " Scan finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" $Colors.Key
Write-Host ("─" * 76) $Colors.Separator
Write-Host ""
