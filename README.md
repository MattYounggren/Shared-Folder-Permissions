# Shared Folder Permissions
This script will email you a html and csv file documenting shared and NTFS permissions for shares on a given server/servers.
Note: It's set to disreguard shares ending in $ (common shares).

Edit the following in the script prior to running.

$smtpsettings = @{
    To         = "your email address here"
    From       = "from email address here"
    Subject    = "Shared Folder Report $((get-date).ToShortDateString())"
    SmtpServer = "mail server here"
}

$sensitiveGroups = @("domainname\Domain Users", "Everyone")

