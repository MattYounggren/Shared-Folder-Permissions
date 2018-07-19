<#
.SYNOPSIS
This script searches for shares on a ComputerName or Array of ComputerNames.

.DESCRIPTION
This script will search for and document any shares on a given server or servers and output the results
to the console or email.
Edit the smtpsettings table and imput your values.
Edit the sensitiveGroups array and enter your values.

.PARAMETER ComputerName
This is either the Computer Name, or Computer Names you wish to scan.

.PARAMETER SensitiveGroupsOnly
Use this switch to only discover shares where sensitive groups have permissions.

.PARAMETER ReportFile
Use this to set a different HTML file name than the default of SharedFolderPermissions.html

.PARAMETER EmailAddress
This will set the EmailAddress to a non default value.

.PARAMETER ExcludeInherited
Use this switch to exclude inherited permissions from the report.

.EXAMPLE
Get-SharedFolderPermissions -ComputerName "computer"
This example runs against one server named computer.

.EXAMPLE
Get-SharedFolderPermissions -ComputerName $serverArray -EmailAddress "test@abc.com"
This example runs against an array of servers held in the $serverArray variable.
It will send the report to an email address of test@abc.com

.EXAMPLE
Get-ADComputer "Computer" | Select @{N='ComputerName'; E={$_.Name}} | .\Get-SharedFolderPermissions.ps1
This example takes a ComputerName Value from the Pipeline and runes the Script against it.

.NOTES
Author: Matt Younggren
Date: 7/11/2018
#>


[CmdletBinding()]
Param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $True)]
    [string[]]$ComputerName,

    [Parameter(Position = 1, Mandatory = $False)]
    [switch]$SensitiveGroupsOnly,

    [Parameter(Position = 2, Mandatory = $False)]
    [string]$ReportFile = "SharedFolderPermissions.html",

    [Parameter(Position = 4, Mandatory = $False)]
    [switch]$ExcludeInherited
)


#region Variables
$smtpsettings = @{
    To         = "your email address here"
    From       = "from email address here"
    Subject    = "Shared Folder Report $((get-date).ToShortDateString())"
    SmtpServer = "mail server here"
}
$csvFile = "SharedFolderPermissions.csv"

#classify what groups are sensitive. The SensitiveGroupsOnly PARAMETER will key off this information.
$sensitiveGroups = @("domainname\Domain Users", "Everyone")

#html code
$htmlhead = "<html>
				<style>
				BODY{font-family: Times New Roman, Times, serif; font-size: 18pt;}
                H1{font-size: 22px; font-family: Times New Roman, Times, serif;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 12pt; border-width:2px;}
				TH{border: 1px solid #969595; background-color: Indigo; padding: 5px; color: white;}
				TD{border: 1px solid; padding: 5px; }
                tr:nth-child(even) {background-color: lightgrey;}
				.alert{background: #FF2626; color: #ffffff;}
				</style>
				<body>
                <p>Shared Folder Information</p>"

$htmltail = "</body></html>"
#endregion

#region Main Script
$serverShares = @()

ForEach ($Computer in $ComputerName) {

    Write-Host "Processing: $Computer" -ForegroundColor Yellow
    $shares = Get-WmiObject -Class win32_share -ComputerName $Computer | Select-Object -ExpandProperty Name

    foreach ($share in $shares) {
        If (!($share.EndsWith("$"))) {

            #Get Shared Folder Permissions on the share
            $acl = $null
            Write-Host $share -ForegroundColor Green
            Write-Host $('-' * $share.Length) -ForegroundColor Green
            $objShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $Computer
            try {
                $SD = $objShareSec.GetSecurityDescriptor().Descriptor
                foreach ($ace in $SD.DACL) {
                    $UserName = $ace.Trustee.Name
                    If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}
                    If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString }
                    [Array]$ACL += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType)
                } #end foreach ACE
            } # end try
            catch {
                Write-Host "Unable to obtain share permissions for $share"
            }

            ForEach ($permission in $ACL) {
                $perm = [ordered]@{
                    "Server"              = $Computer.toUpper()
                    "Share Name"          = $share
                    "File System Rights"  = $permission.FileSystemRights
                    "User/Group"          = $permission.IdentityReference
                    "Type"                = "Share"
                    "Inherited"           = $permission.IsInherited
                }
                If ($SensitiveGroupsOnly -and $ExcludeInherited) {
                    If ($sensitiveGroups.Contains([string]$permission.IdentityReference)) {
                        If (!($permission.IsInherited)) {
                            $serverShares += [pscustomobject]$perm
                        }
                    }
                }
                ElseIf ($SensitiveGroupsOnly) {
                    If ($sensitiveGroups.Contains([string]$permission.IdentityReference)) {
                        $serverShares += [pscustomobject]$perm
                    }
                }
                ElseIf ($ExcludeInherited) {
                    If (!($perm.Inherited)) {
                        $serverShares += [pscustomobject]$perm
                    }
                }
                Else {
                    $serverShares += [pscustomobject]$perm
                }
            }
            #Get NTFS Permissions Per Share
            $acl = $null
            Try {
                $acl = Get-ACL -Path ("\\" + $Computer + "\" + $share) -ErrorAction "Stop"
            }
            Catch {
                Write-Host "Unable to obtain NTFS permissions for $share"
            }
            ForEach ($a in $acl.access) {
                $perm = [ordered]@{
                    "Server"              = $Computer.toUpper()
                    "Share Name"          = $share
                    "File System Rights"  = $a.FileSystemRights
                    "User/Group"          = $a.IdentityReference
                    "Type"                = "NTFS"
                    "Inherited"           = $a.IsInherited
                }

                If ($SensitiveGroupsOnly -and $ExcludeInherited) {
                    If ($sensitiveGroups.Contains([string]$permission.IdentityReference)) {
                        If (!($permission.IsInherited)) {
                            $serverShares += [pscustomobject]$perm
                        }
                    }
                }
                ElseIf ($SensitiveGroupsOnly) {
                    If ($sensitiveGroups.Contains([string]$permission.IdentityReference)) {
                        $serverShares += [pscustomobject]$perm
                    }
                }
                ElseIf ($ExcludeInherited) {
                    If (!($perm.Inherited)) {
                        $serverShares += [pscustomobject]$perm
                    }
                }
                Else {
                    $serverShares += [pscustomobject]$perm
                }
            }
        }
    }
    Write-Host $('=' * 50)
}

[xml]$html = $serverShares | ConvertTo-Html -Fragment

#loop through the data and look for sensetive groups. Color the cell Red when one is found.
for ($i = 1; $i -le $html.table.tr.count - 1; $i++) {
    if ($sensitiveGroups.Contains($html.table.tr[$i].td[3])) {
        $class = $html.CreateAttribute("class")
        $class.value = 'alert'
        $html.table.tr[$i].childnodes[3].attributes.append($class) | out-null
    }
}

$serverReportHTML = $html.InnerXml
$serverSharesReport = $htmlhead + $serverReportHTML + $htmltail

$serverSharesReport | Out-File $ReportFile -Encoding UTF8
$serverShares | Export-CSV $csvFile
Send-MailMessage @smtpsettings -Encoding ([System.Text.Encoding]::UTF8) -Attachments $ReportFile,$csvFile
#endregion