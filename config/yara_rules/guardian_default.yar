/*
    Guardian SIEM — Sample YARA Rules
    Detects common malicious patterns in files.
*/

rule Suspicious_PowerShell_Script
{
    meta:
        description = "Detects PowerShell scripts with suspicious download/execution patterns"
        severity = "HIGH"
        mitre_id = "T1059.001"
        mitre_tactic = "Execution"
        author = "Guardian SIEM"

    strings:
        $ps1 = "Invoke-Expression" ascii nocase
        $ps2 = "IEX(" ascii nocase
        $ps3 = "DownloadString" ascii nocase
        $ps4 = "Net.WebClient" ascii nocase
        $ps5 = "-EncodedCommand" ascii nocase
        $ps6 = "FromBase64String" ascii nocase
        $ps7 = "Invoke-Mimikatz" ascii nocase

    condition:
        2 of ($ps*)
}

rule Webshell_Generic
{
    meta:
        description = "Detects generic webshell patterns"
        severity = "CRITICAL"
        mitre_id = "T1505.003"
        mitre_tactic = "Persistence"
        author = "Guardian SIEM"

    strings:
        $php1 = "eval($_" ascii nocase
        $php2 = "system($_" ascii nocase
        $php3 = "passthru(" ascii nocase
        $php4 = "shell_exec(" ascii nocase
        $asp1 = "eval(Request" ascii nocase
        $asp2 = "Execute(Request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii

    condition:
        any of them
}

rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz password dumping tool strings"
        severity = "CRITICAL"
        mitre_id = "T1003"
        mitre_tactic = "Credential Access"
        author = "Guardian SIEM"

    strings:
        $a1 = "sekurlsa::" ascii
        $a2 = "kerberos::" ascii
        $a3 = "lsadump::" ascii
        $a4 = "gentilkiwi" ascii
        $a5 = "mimikatz" ascii nocase

    condition:
        2 of ($a*)
}

rule Ransomware_Note_Patterns
{
    meta:
        description = "Detects common ransomware note text patterns"
        severity = "CRITICAL"
        mitre_id = "T1486"
        mitre_tactic = "Impact"
        author = "Guardian SIEM"

    strings:
        $r1 = "your files have been encrypted" ascii nocase
        $r2 = "bitcoin wallet" ascii nocase
        $r3 = "pay the ransom" ascii nocase
        $r4 = "decrypt your files" ascii nocase
        $r5 = ".onion" ascii

    condition:
        2 of ($r*)
}

rule Suspicious_PE_Packer
{
    meta:
        description = "Detects PE files that may be packed or obfuscated"
        severity = "MEDIUM"
        mitre_id = "T1027.002"
        mitre_tactic = "Defense Evasion"
        author = "Guardian SIEM"

    strings:
        $mz = { 4D 5A }
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $themida = ".themida" ascii

    condition:
        $mz at 0 and any of ($upx, $aspack, $themida)
}