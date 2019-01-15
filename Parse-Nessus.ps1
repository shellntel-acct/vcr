<#
.SYNOPSIS
Parse-Nessus produces a directory of standalone html reports from a .nessus file.

.DESCRIPTION
The Parse-Nessus script parses a .nessus file into collections in memory, then makes a copy of a preexisting html
template and substitutes variables in the template with data from the .nessus file. In addition to a dashboard
of statistics and navigation, a report for each IP address is produced - containing the vulnerabilities for that IP. A
report is also produced that contains all the vulnerabilities in the .nessus file, grouped by IP.

It also supports CIS benchmark reports for the following Windows operating systems

	Operating System	Benchmark Version
	- Windows 7		 2.1.0
	- Windows 2003	  2.0
	- Windows 2008	  2.1.0
	- Windows 2008R2	2.1.0
	- Windows 2012	  1.0
	- Windows 2012R2	2.1.0

IMPORTANT: By default the script assumes you are parsing a Nessus "Basic Network Scan". To process a CIS Benchmark scan, you MUST specify
the -OperatingSystem parameter as well as the -CIS switch. Run Get-Help with -examples for more info.

All output is sent to the current working directory with the format "CUSTOMERNAME-DATE". Simply find and open index.html to see the report.
Note the ONLY browsers that are supported are Chrome, Firefox, and IE11 (non-compatibility mode).

Regarding the template: There are two html template directories that come with this script, one for a Basic Network Scan, and one for
the CIS benchmark scan. They are *REQUIRED* for this script to operate. If the -TemplatePath parameter is not specified, the script
will look for the template directory in the current working directory based on the type of nessus file you specify. The template directories
are named "template-networkscan" and "template-cisbenchmark". Do not rename them or stuff will break.

There is nothing special about the template itself. I downloaded it from html5up.net (free for personal/commercial use). If you wish
to use your own template, simply look through the temlate*.html files in the template directory and pull out the substitution variables (they
all look like |SOMEVARIABLE|) and put them into your own template. You'll also want to search for "SynerComm" and substitute your own company info.

.PARAMETER NessusFilePath
[REQUIRED] This is the path to the exported .nessus file

.PARAMETER CustomerName
[REQUIRED] This is the name of the organization for whom the report was run against. The name is used in the dashboard page.

.PARAMETER TemplatePath
[OPTIONAL] The full path to the directory containing the template files. If this parameter
is not specified, the script will look for a "template" direcotry in the current working directory.

.PARAMETER OperatingSystem
[OPTIONAL] Note this parameter is mandatory if using the -CIS switch. The following strings are accepted for this parameter

	- Windows2003
	- Windows7
	- Windows2008
	- Windows2008r2
	- Windows2012
	- Windows2012r2
.PARAMETER DisplayHostName
[OPTIONAL] If supplied, report hostname instead of IP address

.PARAMETER CIS
[OPTIONAL] This parameter indicates to the script that you are targeting a CIS benchmark nessus report.

.PARAMETER DebugMode
[OPTIONAL] Spits out a crap ton of extra information. Mainly used for troubleshooting purposes and those who enjoy roller coasters.

.EXAMPLE
Parse-Nessus.ps1 -NessusFilePath C:\temp\export.nessus -CustomerName "ACME Products"
Parses a routine Basic Network Scan.

.EXAMPLE
Parse-Nessus.ps1 -NessusFilePath C:\temp\export.nessus -CustomerName "ACME Products" -Template "C:\temp\mytemplatedirectory"
Parses a Basic Network Scan but with a custom template. Useful if you plan to roll your own template.

.EXAMPLE
Parse-Nessus.ps1 -NessusFilePath c:\temp\exportwin7.nessus -CustomerName "Acme Products" -OperatingSystem "Windows7" -CIS
Parses a CIS Benchmark Scan which targeted Windows 7 machines.

.NOTES
Author: 		Jason Lang (@curi0usJack)
Last Modified:	03/16/2015

Contributions:  lansalot
Last Modified:  11/05/2018 (Added Hostname per https://github.com/Shellntel/vcr/issues/8 and code-repetition cleanup)
#>

#Requires -Version 3.0

Param
(
  [Parameter(Mandatory=$true)]
  [string]$NessusFilePath,

  [Parameter(Mandatory=$true)]
  [string]$CustomerName,

  [Parameter(Mandatory=$false)]
  [string]$TemplatePath,

  [Parameter(Mandatory=$false)]
  [string]$OperatingSystem,

  [Parameter(Mandatory=$false)]
  [switch]$CIS,

  [Parameter(Mandatory=$false)]
  [switch]$DebugMode,

  [Parameter(Mandatory=$false)]
  [switch]$DisplayHostName
)

# Configure a debug switch param
if ($DebugMode -eq $true)
	{ $DebugPreference = "Continue" }
else
	{ $DebugPreference = "SilentlyContinue" }

$currentdir = pwd
$vulnnames = @{}
$chartstats = @{}
$createreportsbyhost = $true
$ipsbyvuln = @{}

#region CIS Category Info

# CIS Categories. These are used to format the HTML output and provide cleaner visibility into the data.

#http://benchmarks.cisecurity.org/tools2/windows/CIS_Win2003_MS_Benchmark_v2.0.pdf
# Windows 2003 CIS Benchmark 2.0
$cat_win2003 =
@{
	"1.1"	= "Major Service Packs";
	"1.2"		= "Minor Service Packs";
	"2.1"		= "Password Policy";
	"2.2.1"		= "Audit Policy";
	"2.2.2"		= "Account Policy";
	"2.2.3"		= "Account Lockout Policy";
	"2.2.4"		= "Event Log Settings";
	"3.1"		= "Major Security Settings";
	"3.2"		= "Minor Security Settings";
	"4.1"		= "System Services";
	"4.2"		= "User Rights Assignment";
	"4.3"		= "System Requirements";
	"4.4"		= "File and Registry Permissions";
}

# Windows 2008 CIS Benchmark 2.1.0
$cat_win2008 =
@{
	"1.1.1.1"= "System Services";
	"1.1.1.2.1" = "Security Options";
	"1.1.1.2.2" = "User Rights Assignment";
	"1.1.1.3.1" = "Audit Policies";
	"1.1.1.4.1" = "Windows Firewall";
	"1.1.1.5.1" = "Kerberos Policy";
	"1.1.1.5.2" = "Account Lockout Policy";
	"1.1.1.5.3" = "Password Policy";
	"1.2.1.1" 	= "Internet Communication Management";
	"1.2.1.2" 	= "Group Policy";
	"1.2.1.3" 	= "Logon";
	"1.2.1.4" 	= "Remote Procedure Call";
	"1.2.1.5" 	= "Remote Assistance";
	"1.2.2.1" 	= "Event Log Service";
	"1.2.2.2" 	= "Remote Desktop Services";
	"1.2.2.3" 	= "Windows Update";
	"1.2.2.4" 	= "AutoPlay Policies";
	"1.2.2.5" 	= "Windows Installer";
	"1.2.2.6" 	= "Credential User Interface";
	"1.2.2.7" 	= "Windows Messenger";
	"1.2.2.8" 	= "NetMeeting"
}

# Windows 2008R2 CIS Benchmark 2.1.0
$cat_win2008r2 =
@{
	"1.1.1.1"= "Windows Services";
	"1.1.1.2" 	= "User Rights Assignment";
	"1.1.1.3" 	= "Audit Policies";
	"1.1.1.4" 	= "Windows Firewall";
	"1.1.1.5" 	= "Account Policies";
	"1.2.1.1" 	= "Event Log";
	"1.2.1.2" 	= "Remote Desktop Services";
	"1.2.1.3" 	= "Autoplay Services";
	"1.2.1.4" 	= "Windows Installer"
}

# Windows 7 CIS Benchmark 2.1.0
$cat_win7 =
@{
	"1.1.1.1"= "Bitlocker Drive Encryption";
	"1.1.1.2" 	= "Autoplay Policies";
	"1.1.1.3" 	= "Event Log";
	"1.1.1.4" 	= "Windows Remote Shell";
	"1.1.1.5" 	= "Windows Explorer";
	"1.1.1.6" 	= "Windows Update";
	"1.1.1.7" 	= "Credential User Interface";
	"1.1.1.8" 	= "Remote Desktop Services";
	"1.1.1.9" 	= "HomeGroup";
	"1.1.2.1" 	= "Power Management";
	"1.1.2.2" 	= "Internet Communication Management";
	"1.1.2.3" 	= "Remote Procedure Call";
	"1.1.2.4" 	= "Remote Assistance";
	"1.1.2.5" 	= "Group Policy";
	"1.1.2.6" 	= "Logon";
	"1.2.1.1" 	= "Local Policies";
	"1.2.1.2" 	= "Audit Policies";
	"1.2.1.3" 	= "Windows Firewall";
	"1.2.1.4" 	= "Account Policies";
	"2.1.1.1" 	= "Attachment Manager";
	"2.1.2.1" 	= "Personalization"
}

# Windows 2012 CIS Benchmark 1.0.0
$cat_win2012 =
@{
	"1.1.1"	= "Account Policies";
	"1.1.2.1"	= "Account Access";
	"1.1.3.11"	= "Network Access";
	"1.1.3.12"	= "Network Security";
	"1.1.3.18"	= "User Access Control";
	"1.1.3.2"	= "Configure System Audit Capabilities";
	"1.1.3.3"	= "Configure System DCOM Capabilities";
	"1.1.3.4"	= "Configure System Device Capabilities";
	"1.1.3.6"	= "Configure System Domain Member Capabilities";
	"1.1.3.7"	= "Configure System Interactive Login Capabilities";
	"1.1.3.8"	= "Configure System Network Client Capabilities";
	"1.1.3.9"	= "Configure System Network Server Capabilities";
	"1.1.4.10"	= "Backup Files and Directories";
	"1.1.4.4"	= "Access Computer From Network";
	"1.1.5"		= "Windows Firewall";
	"1.2.1.1"	= "AutoPlay Policies";
	"1.2.1.2"	= "Event Log Service";
	"1.2.1.3"	= "Terminal Services";
	"1.2.1.4"	= "Windows Installer"
}

$cat_win2012r2 =
@{
	"1.1"		= "Password Policy";
	"1.2"		= "Account Lockout Policy";
	"2.1"		= "Audit Policy";
	"2.2"		= "User Rights Assignment";
	"2.3"		= "Security Options";
	"3"			= "Event Log";
	"4"			= "Restricted Groups";
	"5"			= "System Services";
	"6"			= "Registry"
	"7"			= "File System";
	"8"			= "Wired Network";
	"9.1"		= "Windows Firewall - Domain";
	"9.2"		= "Windows Firewall - Private";
	"9.3"		= "Windows Firewall - Public";
	"10"		= "Network List Manager";
	"11"		= "Wireless Network";
	"12"		= "Public Key Policies";
	"13"		= "Software Restriction Policies";
	"14"		= "Network Access Protection";
	"15"		= "Application Control Policies";
	"16"		= "IP Security Policies";
	"17"		= "Advanced Audit Policies";
	"18.1"		= "ADM Comp - Control Panel";
	"18.2"		= "ADM Comp - LAPS";
	"18.3"		= "ADM Comp - MSS (Legacy)";
	"18.4"		= "ADM Comp - Network";
	"18.5"		= "ADM Comp - Printers";
	"18.6"		= "ADM Comp - SCM: Pass The Hash";
	"18.7"		= "ADM Comp - SCM: Wi-Fi Sense";
	"18.8"		= "ADM Comp - Start Menu";
	"18.9"		= "ADM Comp - System";
	"18.10"		= "ADM Comp - Windows Components";
	"19.1"		= "ADM User - Control Panel";
	"19.2"		= "ADM User - Desktop";
	"19.3"		= "ADM User - Network";
	"19.4"		= "ADM User - Shared Folders";
	"19.5"		= "ADM User - Start Menu";
	"19.6"		= "ADM User - System";
	"19.7"		= "ADM User - Windows Components";
}
#endregion

# Set variables for saving data
$date = Get-Date -Format yyyyMMddhhmmss
if ($CIS -eq $true)
{
	if ($OperatingSystem -eq $null)
	{
		Write-Host "[!] ERROR: The -OperatingSystem parameter cannot be null when the -CIS switch is used."
		exit
	}
	$osstring = $OperatingSystem.ToUpper()
	$newfolder = "$currentdir\$customername-$OperatingSystem-$date"
	switch ($osstring)
	{
		"WINDOWS7"		{ $oscategory = $cat_win7.Clone(); break; }
		"WINDOWS2008"	{ $oscategory = $cat_win2008.Clone(); break; }
		"WINDOWS2008R2"	{ $oscategory = $cat_win2008r2.Clone(); break; }
		"WINDOWS2003"	{ $oscategory = $cat_win2003.Clone(); break; }
		"WINDOWS2012"	{ $oscategory = $cat_win2012.Clone(); break; }
		"WINDOWS2012R2"	{ $oscategory = $cat_win2012r2.Clone(); break; }
		default			{ $oscategory = @{}; } #throw [System.Exception] "Operating System string - $osstring - not understood. See help for supported operating systems." }
	}
}
else
{
	$newfolder = "$currentdir\$customername-$date"
}

$extraspath = "$newfolder\extras"
$reportsbyhostfolder = "$newfolder\reportsbyhost"
$reportbyvulnfolder = "$newfolder\reportsbyvuln"
$chartpath = "$newfolder\images\highlevel.png"

if ($TemplatePath -eq "")
{
	if ($CIS -eq $true)
	{
		$htmltemplatedir = "$currentdir\template-cisbenchmark"
	}
	else
	{
		$htmltemplatedir = "$currentdir\template-networkscan"
	}
}
else
{
	$htmltemplatedir = $TemplatePath
}

Write-Debug "NessusFilePath: $NessusFilePath"
Write-Debug "CustomerName: $CustomerName"
Write-Debug "Current Dir: $currentdir"
Write-Debug "TemplatePath: $htmltemplatedir"
Write-Debug "NewFolderPath: $newfolder"

#______________________________________ SUPPORTING FUNCTIONS ______________________________________

# PreRequsite Checks. Specifically ensure the html template exists
function Do-PreReqs() {
	if (-Not (Test-Path $htmltemplatedir))
	{
		Write-Host "[!] ERROR: Missing template directory. Ensure template directory is found in the script root directory. You may also use the -TemplatePath parameter to specify the path to the template."
		exit
	}


	if (-Not (Test-Path $NessusFilePath))
	{
		Write-Host "[!] ERROR: Could not find nessus file at $NessusFilePath. Please verify the path is correct."
		exit
	}
}

#region DASHBOARD

# Create the html for each host report td element
function Format-DashboardHtmlItem($ipaddress, $reportsbyhostfolder, $cssclass)
{
	$linkpath = $ipaddress.Replace(".", "-")
	$html = "<td class=""$cssclass""><a href="".\reportsbyhost\$linkpath.html"">$ipaddress</a></td>"
	return $html
}
function Format-DashboardHtmlItemWithAlternate($hostname, $ipaddress, $reportsbyhostfolder, $cssclass)
{
	$linkpath = $ipaddress.Replace(".", "-")
	if ($hostname -eq 'Unknown')
	{
		$html = "<td class=""$cssclass""><a href="".\reportsbyhost\$linkpath.html"">$ipaddress</a></td>"
	}
	else
	{
		if ($DisplayHostName)
		{
			$html = "<td class=""$cssclass""><a href="".\reportsbyhost\$linkpath.html"">$hostname</a></td>"
		} else
		{
			$html = "<td class=""$cssclass""><a href="".\reportsbyhost\$linkpath.html"">$ipaddress</a></td>"
		}
	}
	return $html
}

# Generate the correct html to use for the dashboard. I don't like this function. There must be a better way to do this...
function Format-DashboardHtmlReport($allhosts, $reportsbyhostfolder)
{
	$crits = $allhosts | ?{$_.NumberCriticals -gt 0} | sort NumberCriticals -Descending
	$highs = $allhosts | ?{$_.NumberHighs -gt 0 -and $_.NumberCriticals -eq 0} | sort NumberHighs -Descending
	$meds = $allhosts | ?{$_.NumberMediums -gt 0 -and ($_.NumberCriticals -eq 0 -and $_.NumberHighs -eq 0)} | sort NumberMediums -Descending
	$lows = $allhosts | ?{$_.NumberLows -gt 0  -and ($_.NumberCriticals -eq 0 -and $_.NumberHighs -eq 0 -and $_.NumberMediums -eq 0)} | sort NumberLows -Descending
	$infos = $allhosts | ?{$_.NumberInfos -gt 0 -and ($_.NumberCriticals -eq 0 -and $_.NumberHighs -eq 0 -and $_.NumberMediums -eq 0 -and $_.NumberLows -eq 0)} | sort NumberInfos -Descending
	$unsures = $allhosts | ?{$_.NumberUnsures -gt 0 -and ($_.NumberCriticals -eq 0 -and $_.NumberHighs -eq 0 -and $_.NumberMediums -eq 0 -and $_.NumberLows -eq 0 -and $_.NumberInfos -eq 0)} | sort NumberUnsures -Descending

	$html = "<table id=""tabips"">"
	$i = 0
	$rowmax = 6
	if ($DisplayHostName) {
		$rowmax = 5
	}
	foreach ($c in $crits)
	{
		if ($c.IPAddress -ne $null)
		{
			if ($i -eq 0)
				{ $html += "<tr>" }

			$html += Format-DashboardHtmlItemWithAlternate $c.hostname  $c.IPAddress $reportsbyhostfolder "critbg"
			$i += 1

			if ($i -eq $rowmax)
				{$html += "</tr>"; $i = 0 }
		}
	}

	$Categories = @(
		"highs:highbg"
		"meds:medbg"
		"lows:lowbg"
		"infos:infobg"
		"unsures:dunnobg"
	)
	ForEach ($Category in $Categories) {
		foreach ($c in ((Get-Variable $Category.Split(":")[0]).value ) )
		{
			if ($c.IPAddress -ne $null)
			{
				if ($i -eq 0)
					{ $html += "<tr>" }

				$html += Format-DashboardHtmlItemWithAlternate $c.hostname $c.IPAddress $reportsbyhostfolder $Category.Split(":")[1]
				$i += 1

				if ($i -eq $rowmax)
					{$html += "</tr>"; $i = 0 }
			}
		}

	}
	$html += "</table>"
	return $html
}

# Similar to Create-HostReport, this function simply creates a dashboard file - index.html
function Create-DashboardReport($allhostinfo, $hostreportlisthtml, $foldername, $companyname, $reportsbyhostfolder)
{
	$dashboardtemplate = "$htmltemplatedir\templateDashboard.html"
	$dashboardsavepath = "$foldername\index.html"
	$dashboarddata = Get-Content $dashboardtemplate

	$totalcrit = 0
	$totalhigh = 0
	$totalmed = 0
	$totallow = 0
	$totalinfo = 0
	$totalall = 0

	foreach ($hostinfo in $allhostinfo)
	{
		$totalcrit += ($hostinfo.Vulnerabilities | ?{$_.RiskFactor -eq "Critical"} | measure).Count
		$totalhigh += ($hostinfo.Vulnerabilities | ?{$_.RiskFactor -eq "High"} | measure).Count
		$totalmed += ($hostinfo.Vulnerabilities | ?{$_.RiskFactor -eq "Medium"} | measure).Count
		$totallow += ($hostinfo.Vulnerabilities | ?{$_.RiskFactor -eq "Low"} | measure).Count
		$totalinfo += ($hostinfo.Vulnerabilities | ?{$_.RiskFactor -eq "Info"} | measure).Count
	}

	$totalall = ($totalcrit + $totalhigh + $totalmed + $totallow + $totalinfo)

	$vulnstats =
	@{
		"TOTALCRITICAL" = $totalcrit
		"TOTALHIGH" = $totalhigh
		"TOTALMEDIUM" = $totalmed
		"TOTALLOW" = $totallow
		"TOTALINFO" = $totalinfo
		"TOTALFINDINGS" = $totalall
	}

	$script:chartstats =
	@{
		"Critical" = $totalcrit
		"High" = $totalhigh
		"Medium" = $totalmed
		"Low" = $totallow
	}

	$reportlinks = Format-DashboardHtmlReport $allhostinfo $reportsbyhostfolder

	Write-Debug "Create-DashboardReport: Total Findings - $totalall"
	Write-Debug "Create-DashboardReport: Total Critical - $totalcrit"
	Write-Debug "Create-DashboardReport: Total High - $totalhigh"
	Write-Debug "Create-DashboardReport: Total Medium - $totalmed"
	Write-Debug "Create-DashboardReport: Total Low - $totallow"
	Write-Debug "Create-DashboardReport: Total Info - $totalinfo"

	$data = $dashboarddata.Clone()

	foreach ($cat in $vulnstats.Keys)
	{
		$data = $data | %{$_.Replace("|" + $cat + "|", $vulnstats[$cat])}
	}

	$data = $data | %{$_.Replace("|GENERATEDDATE|", (Get-Date -Format G))}
	$data = $data | %{$_.Replace("|REPORTINFO|", $reportlinks)}
	$data = $data | %{$_.Replace("|COMPANYNAME|", $companyname)}
	New-Item -Path $dashboardsavepath -ItemType File -Force | Out-Null
	$data | Set-Content -Path $dashboardsavepath

	return $vulnstats
}

#endregion

#region HTML FUNCTIONS

# This region contains the functions which write out the html which is then later substituted into the report template.
# *Strongly* resist the urge to mess with these. It will only bring you heartache and pain. You've been warned.

# Nessus files can contain html tags which can screw up html rendering. This function simply replaces those tags.
function CleanString($s)
{
	$r = $s.Replace("<", "LT")
	$r = $r.Replace(">", "GT")
	$r = $r.Replace("`n", "<br />")
	return $r
}

# Each vulnerability section in the accordion is broken up into two sections, the Synopsis section (created here), and
# the host/output section, created by Get-VulnHtmlTable below. There is only one Synopsis section, but each vuln can have
# multiple hosts associated to it.
function Get-VulnHtmlSynopsis($vulnitem)
{
	if ($vuln.Solution -eq $null)
		{ $vuln.Solution = "N/A" }

	$html = ""
	$html += "<div>"
	$html += "<strong>Summary Information</strong><br /><br />"
	$html += "<table><tr>"
	$html += "<td>Synopsis</td>"
	$html += "<td>" + $vuln.Synopsis + "</td></tr>"
	$html += "<tr><td>Solution</td>"
	$html += "<td>" + (CleanString $vuln.Solution) + "</td></tr>"
	$html += "</table>"
	$html += "<br /><br /><strong>Details By Port</strong><br /><br />"

	return $html
}

# Creates the host/output section for each vulnerability
function Get-VulnHtmlTable($vulnitem, $ipaddress, $showipintable)
{
	if ($vulnitem.Output -eq $null)
	{
		$vulnitem.Output = "N/A"
	}

	$class = ""
	if ($showipintable -eq $true)
		{ $class = "showme" }
	else
		{ $class = "hideme" }

	$h = ""
	$h += "<table>"
	$h += "<tr class=""$class"">"
	$h += "<td>IP Address</td>"
	$h += "<td>" + $ipaddress + "</td></tr>"
	$h += "<tr><td>Port/Protocol</td>"
	$h += "<td>" + $vulnitem.Port + "/" + $vulnitem.Protocol + "/" + $vulnitem.ServiceName + "</td></tr>"
	$h += "<tr><td>Description</td>"
	$h += "<td class=""tddesc""><div class=""divtoggle"">" + (CleanString $vulnitem.Description) + "</div><div class=""link toggle"" /></td></tr>"
	$h += "<tr><td>Output</td>"
	$h += "<td class=""tdoutput""><div class=""divtoggle"">" + (CleanString $vulnitem.Output) + "</div><div class=""link toggle"" /></td></tr>"
	$h += "</table><br /><br />"

	return $h
}
#endregion

#region REPORTS BY HOST
# This function does the ugly work of formatting the vulns into friendly html, accounting
# for the way Nessus has duplicate findings by port in their xml.
#
# This funciton is used when generating indvidual host reports, as well as generating the main
# vulnerability report. The $showipintable variable simply indicated whether or not to show the IP address
# in the vulnerability drop down information (helpful in the vulnerability report, but redundant in the host report)
function Format-HostHtml($nessushost, $showipintable)
{
	$completed = @{}
	foreach ($vuln in $nessushost.Vulnerabilities)
	{
		if ($completed.ContainsKey($vuln.VulnerabilityName) -eq $true)
		{
			#This is not the first instance of this vulnerability in the collection. Append results to it:
			$html = $completed[$vuln.VulnerabilityName]
			$html += Get-VulnHtmlTable $vuln
			$completed[$vuln.VulnerabilityName] = $html
		}
		else
		{
			#This is the first instance of this vulnerability
			$html = Get-VulnHtmlSynopsis $vuln
			$html += Get-VulnHtmlTable $vuln $nessushost.IPAddress $showipintable
			$completed.Add($vuln.VulnerabilityName, $html)
		}
	}
	return $completed
}

# This function takes a target host from the collection and creates an
# html report page for it.
function Create-HostReport($targethost, $foldername, $hosthtml)
{
	$hostsavename = $targethost.IPAddress.Replace(".", "-")
	$findingstemplate = "$htmltemplatedir\templateFindings.html"
	$findingfilename = "$hostsavename.html"
	$findingssavepath = "$foldername\$findingfilename"
	$findingsdata_master = Get-Content $findingstemplate

	### Write Findings HTML ###
	Write-Host "[*] Creating html report for $($targethost.hostname) ($($targethost.IPAddress))"
	$strhtml = ""
	$completedvulns = @()

	foreach ($item in $targethost.Vulnerabilities)
	{
		if ($completedvulns -notcontains $item.VulnerabilityName)
		{
			$strhtml += "<h6><span class=""vulnlabel " + $item.RiskFactor.ToLower() + """>" + $item.RiskFactor.ToUpper() + "</span>&nbsp;" + $item.VulnerabilityName + "</h6>"
			$strhtml += $hosthtml[$item.VulnerabilityName]
			$strhtml += "</div>"
			$completedvulns += $item.VulnerabilityName
		}
	}

	### Calculate Summary Data ###
	$totalcrit = ($targethost.Vulnerabilities | ?{$_.RiskFactor -eq "Critical"} | measure).Count
	$totalhigh = ($targethost.Vulnerabilities | ?{$_.RiskFactor -eq "High"} | measure).Count
	$totalmed = ($targethost.Vulnerabilities | ?{$_.RiskFactor -eq "Medium"} | measure).Count
	$totallow = ($targethost.Vulnerabilities | ?{$_.RiskFactor -eq "Low"} | measure).Count
	$totalinfo = ($targethost.Vulnerabilities | ?{$_.RiskFactor -eq "Info"} | measure).Count
	$totalfindings = $totalcrit + $totalhigh + $totalmed + $totallow + $totalinfo

	### Substitute Data in Template ###
	$findingsdata = $findingsdata_master.Clone()
	$data = $findingsdata | %{$_.Replace("|TOTALFINDINGS|", $totalfindings)}
	$data = $data | %{$_.Replace("|TOTALCRITICAL|", $totalcrit)}
	$data = $data | %{$_.Replace("|TOTALHIGH|", $totalhigh)}
	$data = $data | %{$_.Replace("|TOTALMEDIUM|", $totalmed)}
	$data = $data | %{$_.Replace("|TOTALLOW|", $totallow)}
	$data = $data | %{$_.Replace("|TOTALINFORMATIONAL|", $totalinfo)}
	$data = $data | %{$_.Replace("|REPORTINFO|", $strhtml)}
	$data = $data | %{$_.Replace("|HOST|", $targethost.HostName + " (" + $targethost.IPAddress + ")")}
	New-Item -Path $findingssavepath -ItemType File -Force | Out-Null
	$data | Set-Content -Path $findingssavepath

	return $findingfilename
}

#endregion

#region REPORT BY VULNERABILITY

# Simple function to change criticality number for friendly name
function Get-VulnCriticality($vulnname)
{
	$i = $vulnnames[$vulnname]
	switch ($i)
	{
		1		{ return "Critical" }
		2		{ return "High" }
		3		{ return "Medium" }
		4		{ return "Low" }
		5		{ return "Info" }
		default	{ return "Unknown" }
	}
}

# Create the main vulnerability report
function Create-VulnReport($uniqvulns, $vulnhtml, $foldername, $vulnstats)
{
	$savename = "allvulns"
	$template = "$htmltemplatedir\templateByVuln.html"
	$filename = "$savename.html"
	$savepath = "$foldername\$filename"
	$data_master = Get-Content $template

	### Write Findings HTML ###
	$strhtml = ""

	foreach ($vuln in ($vulnnames.GetEnumerator() | sort Value, Name))
	{
		$criticality = Get-VulnCriticality $vuln.Name
		if ($criticality -eq "Low"){
		Write-Debug "here"
	}
		if ($vulnnames[$vuln.Name] -lt 5) #Omit Info class of vulns. Report is way too huge if they are included.
		{
			$strhtml += "<h6><span class=""vulnlabel " + $criticality.ToLower() + """>" + $criticality.ToUpper() + "</span>&nbsp;" + $vuln.Name + "</h6>"
			$strhtml += $vulnhtml[$vuln.Name]
			$strhtml += "</div>"
		}
	}

	### Substitute Data in Template ###
	$data = $data_master.Clone()

	foreach ($cat in $vulnstats.Keys)
	{
		$data = $data | %{$_.Replace("|" + $cat + "|", $vulnstats[$cat])}
	}

	$data = $data | %{$_.Replace("|REPORTINFO|", $strhtml)}
	New-Item -Path $savepath -ItemType File -Force | Out-Null
	$data | Set-Content -Path $savepath
}

# Nessus breaks down the xml by IP, which each IP containing it's own vulnerabilities. This function effectively reverses
# that, grouping IPs by vulnerability. It is used to make the vulnerability report.
function Get-VulnsByHost($allhostinfo)
{
	$completedvulns = @{}
	foreach ($h in $allhostinfo)
	{
		foreach ($vuln in $h.Vulnerabilities)
		{
			$vulnname = $vuln.VulnerabilityName
			if ($completedvulns.ContainsKey($vulnname))
			{
				$htm = $completedvulns[$vulnname]
				$htm += Get-VulnHtmlTable $vuln $h.IPAddress $true
				$completedvulns[$vulnname] = $htm
			}
			else
			{
				$htm = Get-VulnHtmlSynopsis $vuln
				$htm += Get-VulnHtmlTable $vuln $h.IPAddress $true
				$completedvulns.Add($vulnname, $htm)
				Write-Debug "Get-VulnsByHost: Added new vuln to collection: $vulnname"
			}

			# Save ips by vulnerability. This info is later used to create extras\ipsbyvuln.txt to assist with reporting.
			if ($script:ipsbyvuln.ContainsKey($vulnname))
			{
				$ips = $script:ipsbyvuln[$vulnname]
				$s = [string]::Format("{0}:{1}",$h.IPAddress, $vuln.Port)
				$ips += $s
				$script:ipsbyvuln[$vulnname] = $ips
			}
			else
			{
				$ips = @()
				$s = [string]::Format("{0}:{1}",$h.IPAddress, $vuln.Port)
				$ips += $s
				$script:ipsbyvuln.Add($vulnname, $ips)
			}
		}
	}
	return $completedvulns
}

#endregion

#region CIS SPECIFIC FUNCTIONS

function Get-OSCategory($osstring)
{
	$osstring = $osstring.ToUpper()
	switch ($osstring)
	{
		"WINDOWS7"		{ return $cat_win7 }
		"WINDOWS2008"	{ return $cat_win2008 }
		"WINDOWS2008R2"	{ return $cat_win2008r2 }
		"WINDOWS2003"	{ return $cat_win2003 }
		"WINDOWS2012"	{ return $cat_win2012 }
		"WINDOWS2012R2"	{ return $cat_win2012r2 }
		default			{ return @{} } #throw [System.Exception] "Operating System string - $osstring - not understood. See help for supported operating systems." }
	}
}

function GetCategory($cats, $str)
{
	$returnstring = $str
	foreach ($i in $cats.Keys)
	{
		if ($str -match "^$i")
		{
			$returnstring = $cats[$i]
			break
		}
	}
	return $returnstring
}

function CleanName($category, $str)
{
	$repstr = "[" + $category + "]"
	$s = $str -replace "(\d+\.?)+",$repstr
	return $s
}

function Get-CISResultHTML($checkresult, $policyvalue, $actualvalue)
{
	$resulthtml = ""
	$cssclass = ""
	if ($checkresult -eq "ERROR" -or $checkresult -eq "INFO" -or $checkresult -eq "WARNING")
	{
		# If the check errored out, simply return nothing
		return $resulthtml
	}
	elseif ($checkresult -eq "FAILED")
		{ $cssclass = "actualvaluefailed" }
	elseif ($checkresult -eq "PASSED")
		{ $cssclass = "actualvaluepassed" }
	else
		{ throw [System.Exception] "CheckResult type not understood: $checkresult" }

	$resulthtml = "<div class=""ui-corner-all policyvalue"">"
	$resulthtml += "<b>Policy Value: </b>" + $policyvalue
	$resulthtml += "</div>"
	$resulthtml += "<div class=""ui-corner-all " + $cssclass + """>"
	$resulthtml += "<b>Actual Value: </b>" + $actualvalue
	$resulthtml += "</div>"

	return $resulthtml
}

function Create-CISFinding($targethost, $foldername)
{
	$hostsavename = $targethost.IPAddress.Replace(".", "-")
	$findingstemplate = "$htmltemplatedir\templateFindings.html"
	$findingfilename = "$hostsavename.html"
	$findingssavepath = "$foldername\$findingfilename"
	$findingsdata_master = Get-Content $findingstemplate

	### Copy The Template ###

	### Write Findings HTML ###
	Write-Host "[*] Creating html report data for" $targethost.IPAddress
	$strhtml = ""
	foreach ($item in $targethost.ReportItems)
	{
		$resulthtml = Get-CISResultHTML $item.CheckResult $item.CheckPolicyValue $item.CheckActualValue

		$strhtml += "<h6 class=""" + $item.CheckResult.ToLower() + """>" + $item.CheckName + "</h6>"
		$strhtml += "<div>"
		$strhtml += $resulthtml
		$strhtml += "<br /><br /><p>"
		$strhtml += (CleanString $item.CheckDescription)
		$strhtml += "</p>"
		$strhtml += "</div>"
	}

	### Calculate Summary Data ###
	#Write-Host "[-] Calculating check totals"
	$totalerror = ($targethost.ReportItems | ?{$_.CheckResult -eq "ERROR"} | measure).Count
	$totalpassed = ($targethost.ReportItems | ?{$_.CheckResult -eq "PASSED"} | measure).Count
	$totalfailed = ($targethost.ReportItems | ?{$_.CheckResult -eq "FAILED"} | measure).Count
	$totalchecks = $totalpassed + $totalerror + $totalfailed

	if ($strhtml -eq "")
		{ $strhtml = "No audit data was generated for this host." }

	### Substitute Data in Template ###
	#Write-Host "[-] Adding html data to report and saving"
	$findingsdata = $findingsdata_master.Clone()
	$data = $findingsdata | %{$_.Replace("|TOTALPASSED|", $totalpassed)}
	$data = $data | %{$_.Replace("|TOTALFAILED|", $totalfailed)}
	$data = $data | %{$_.Replace("|TOTALERRORS|", $totalerror)}
	$data = $data | %{$_.Replace("|TOTALCHECKS|", $totalchecks)}
	$data = $data | %{$_.Replace("|REPORTINFO|", $strhtml)}
	$data = $data | %{$_.Replace("|HOST|", $targethost.HostName + " (" + $targethost.IPAddress + ")")}
	New-Item -Path $findingssavepath -ItemType File -Force | Out-Null
	$data | Set-Content -Path $findingssavepath

	return $findingfilename
}

function Create-CISDashboard($allhostinfo, $hostreportlisthtml, $foldername, $companyname, $operatingsystem)
{
	$dashboardtemplate = "$htmltemplatedir\templateDashboard.html"
	$dashboardsavepath = "$foldername\index.html"
	$dashboarddata = Get-Content $dashboardtemplate

	$totalpassedchecks = 0
	$totalfailedchecks = 0
	$totalerrorchecks = 0
	$totalchecks = 0

	$html = "<table id=""tabips"">"
	$i = 0
	$rowmax = 6

	foreach ($hostinfo in $allhostinfo)
	{
		$totalerrorchecks += ($hostinfo.ReportItems | ?{$_.CheckResult -eq "ERROR"} | measure).Count
		$totalpassedchecks += ($hostinfo.ReportItems | ?{$_.CheckResult -eq "PASSED"} | measure).Count
		$totalfailedchecks += ($hostinfo.ReportItems | ?{$_.CheckResult -eq "FAILED"} | measure).Count


		if ($i -eq 0)
			{ $html += "<tr>" }

		$html += Format-DashboardHtmlItem $hostinfo.IPAddress $reportsbyhostfolder ""
		$i += 1
		if ($i -eq $rowmax)
			{$html += "</tr>"; $i = 0 }
	}

	$html += "</table>"

	$totalchecks = $totalerrorchecks + $totalpassedchecks + $totalfailedchecks

	$script:chartstats =
	@{
		"Passed" = $totalpassedchecks
		"Failed" = $totalfailedchecks
		"Error"	 = $totalerrorchecks
	}

	$data = $dashboarddata | %{$_.Replace("|TOTALPASSED|", $totalpassedchecks)}
	$data = $data | %{$_.Replace("|TOTALFAILED|", $totalfailedchecks)}
	$data = $data | %{$_.Replace("|TOTALERRORS|", $totalerrorchecks)}
	$data = $data | %{$_.Replace("|TOTALCHECKS|", $totalchecks)}
	$data = $data | %{$_.Replace("|GENERATEDDATE|", (Get-Date -Format G))}
	$data = $data | %{$_.Replace("|REPORTINFO|", $html)}
	$data = $data | %{$_.Replace("|COMPANYNAME|", $companyname)}
	$data = $data | %{$_.Replace("|OPERATINGSYSTEM|", $operatingsystem)}
	New-Item -Path $dashboardsavepath -ItemType File -Force | Out-Null
	$data | Set-Content -Path $dashboardsavepath
}

#endregion

#region NESSUS FILE PARSING

function Update-UniqueVulns($vulnname, $criticality)
{
	if ($vulnnames.ContainsKey($vulnname) -eq $false)
	{
		$script:vulnnames.Add($vulnname, $criticality)
		Write-Debug "Update-UniqueVulns: Added uniqe vulnn to $ vulnnames: $vulnname"
	}
}

# Parse out the nessus file into powershell friendly objects
function Parse-NessusFile($path)
{
	Write-Debug "Parse-NessusFile: Entered Parse-NessusFile"
	$Xml=New-Object Xml
	$Xml.Load((Convert-Path $path))
	$xreportitems = Select-Xml -Xml $Xml -XPath "/NessusClientData_v2/Report/ReportHost"
	Write-Debug "Parse-NessusFile: Successfully loaded xml into memory"
	$allhosts = @()

	foreach ($xhost in $xreportitems)
	{
		$hostinfo = New-Object -TypeName PSObject
		$vulns = @()

		$hostinfo | Add-Member –MemberType NoteProperty -Name HostName -Value "Unknown"
		$hostinfo | Add-Member –MemberType NoteProperty -Name OpenTCPPorts -Value "Unknown"
		$hostinfo | Add-Member –MemberType NoteProperty -Name OpenUDPPorts -Value "Unknown"
		$hostinfo | Add-Member –MemberType NoteProperty -Name OperatingSystem -Value "Unknown"

		$ip = "Unknown"
		foreach ($prop in $xhost.Node.HostProperties.tag)
		{
				if ($prop.name -eq "HOST_START")
					{ $hostinfo | Add-Member –MemberType NoteProperty -Name ScanStarted -Value $prop.'#text' }

				if ($prop.name -eq "HOST_END")
					{ $hostinfo | Add-Member –MemberType NoteProperty -Name ScanCompleted -Value $prop.'#text' }

				if ($prop.name -eq "host-ip")
				{
					$hostinfo | Add-Member –MemberType NoteProperty -Name IPAddress -Value $prop.'#text'
					$ip = $prop.'#text'
				}
				if ($prop.name -eq "hostname")
				{
					$Hostinfo.Hostname = $prop.'#text'
				}
				if ($prop.name -eq "operating-system")
					{ $hostinfo.OperatingSystem = $prop.'#text' }
		}

		$numcrits = 0
		$numhighs = 0
		$nummeds = 0
		$numlows = 0
		$numinfos = 0
		$numunsure = 0
		$opentcpports = ""
		$openudpports = ""

		foreach ($ri in $xhost.Node.ReportItem)
		{
			# Tenable Support confirmed that the default scanner for TCP ports is 'Nessus SYN Scanner' and the
			# default UDP scanner is the Nessus SNMP Scanner. Unless otherwise disabled, both of these run by default with the Basic Network Scan

			# Get Open TCP Ports
            if ($ri.plugin_name -eq "Nessus SYN Scanner")
			{
                if ($ri.plugin_output -ne $null)
				{
					$port = $ri.plugin_output.split(' ')[1].Split('/')[0]
                    $opentcpports += "$port;"
                }
            }

			# Get Open UDP Ports
            if ($ri.plugin_name -eq "Nessus SNMP Scanner")
			{
                if ($ri.plugin_output -ne $null)
				{
					$port = $ri.plugin_output.split(' ')[1].Split('/')[0]
					$proto = $ri.plugin_output.split(' ')[1].Split('/')[1]
                    if ($proto -ne $null -and $proto.ToLower() -eq "udp" )
						{ $openudpports += "$port;" }
                }
            }

			#Check for Hostname
			if ($ri.plugin_name -eq "Host Fully Qualified Domain Name (FQDN) Resolution")
				{ $hostinfo.HostName = $ri.plugin_output.Split(' ')[3].Trim('.') }

			#if ($ri.plugin_name -eq "HTTP Server Type and Version") {
			#	Write-Debug $ri.plugin_name
			#}

			$object = New-Object –TypeName PSObject
			$object | Add-Member –MemberType NoteProperty –Name VulnerabilityName –Value $ri.plugin_name
			$object | Add-Member –MemberType NoteProperty –Name Description –Value $ri.description
			$object | Add-Member –MemberType NoteProperty –Name Synopsis –Value $ri.synopsis
			$object | Add-Member –MemberType NoteProperty –Name RiskFactor –Value $ri.risk_factor
			$object | Add-Member –MemberType NoteProperty –Name Output –Value $ri.plugin_output
			$object | Add-Member –MemberType NoteProperty –Name Solution –Value $ri.solution
			$object | Add-Member –MemberType NoteProperty –Name Port –Value $ri.port
			$object | Add-Member –MemberType NoteProperty –Name ServiceName –Value $ri.svc_name
			$object | Add-Member –MemberType NoteProperty –Name Protocol –Value $ri.protocol
			$object | Add-Member -MemberType NoteProperty -Name Exploitable -Value $ri.exploit_available
			$object | Add-Member -MemberType NoteProperty -Name Metasploitable -Value $ri.exploit_framework_metasploit
			$object | Add-Member -MemberType NoteProperty -Name MetasploitName -Value $ri.metasploit_name

			if ($object.RiskFactor -eq "None")
				{ $object.RiskFactor = "Info" }

			# Note, do not criticality (i.e. make Criticals 5 instead of 1). It's needed this way to
			# accommodate Powershell's sorting mechanism
			switch ($ri.risk_factor)
			{
				"Critical"
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 1
					Update-UniqueVulns $ri.plugin_name 1
					$numcrits += 1
					break
				}
				"High"
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 2
					Update-UniqueVulns $ri.plugin_name 2
					$numhighs += 1
					break
				}
				"Medium"
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 3
					Update-UniqueVulns $ri.plugin_name 3
					$nummeds += 1
					break
				}
				"Low"
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 4
					Update-UniqueVulns $ri.plugin_name 4
					$numlows += 1
					break
				}
				"None"
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 5
					Update-UniqueVulns $ri.plugin_name 5
					$numinfos += 1
					break
				}
				default
				{
					$object | Add-Member –MemberType NoteProperty –Name SortOrder -Value 10
					Update-UniqueVulns $ri.plugin_name 10
					$numunsure += 1
					break
				}
			}

			$vulns += $object
		}

		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberCriticals -Value $numcrits
		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberHighs -Value $numhighs
		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberMediums -Value $nummeds
		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberLows -Value $numlows
		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberInfos -Value $numinfos
		$hostinfo | Add-Member –MemberType NoteProperty -Name NumberUnsures -Value $numunsure

		if ($opentcpports -ne $null)
		{
			$opentcpports = $opentcpports.Trim(';').Split(';') | Sort-Object {[int]$_}
        	$hostinfo.OpenTCPPorts = $opentcpports -join ';'
		}

		if ($openudpports -ne $null)
		{
			$openudpports = $openudpports.Trim(';').Split(';') | Sort-Object {[int]$_}
        	$hostinfo.OpenUDPPorts = $openudpports -join ';'
		}

		$hostinfo | Add-Member –MemberType NoteProperty -Name Vulnerabilities -Value ($vulns | sort  SortOrder, VulnerabilityName)
		$allhosts += $hostinfo
		Write-Debug "Parse-NessusFile: Added info for host $ip"
	}

	return $allhosts
}

function Parse-CISNessusFile($path, $oscategory)
{
	Write-Debug "Parse-CISNessusFile: Entered Parse-CISNessusFile"
	$Xml=New-Object Xml
	$Xml.Load((Convert-Path $path))
	$xreportitems = Select-Xml -Xml $Xml -XPath "/NessusClientData_v2/Report/ReportHost"
	Write-Debug "Parse-NessusFile: Successfully loaded xml into memory"
	$allhosts = @()

	foreach ($xhost in $xreportitems)
	{
		$hostinfo = @{}
		$items = @()

		foreach ($prop in $xhost.Node.HostProperties.tag)
		{
			if ($prop.name -eq "HOST_START")		{ $hostinfo.ScanStarted = $prop.'#text' }
			if ($prop.name -eq "HOST_END")			{ $hostinfo.ScanCompleted = $prop.'#text' }
			if ($prop.name -eq "netbios-name")		{ $hostinfo.HostName = $prop.'#text' }
			if ($prop.name -eq "smb-login-used")	{ $hostinfo.LoginUsed = $prop.'#text' }
			if ($prop.name -eq "host-fqdn")			{ $hostinfo.FQDN = $prop.'#text' }
			if ($prop.name -eq "host-ip")			{ $hostinfo.IPAddress = $prop.'#text' }
		}

		$ip = $hostinfo.IPAddress
		Write-Debug "Parse-CISNessusFile: Building collection for $ip"
		# Build out the collection
		foreach ($ri in $xhost.Node.ReportItem)
		{
			$checkname = $ri.'compliance-check-name'
			if ($checkname -ne $null)
			{
				$category = GetCategory $oscategory $checkname
				if ($category -ne $null)
				{
					$object = New-Object –TypeName PSObject
					$object | Add-Member –MemberType NoteProperty –Name Compliance –Value $ri.compliance
					$object | Add-Member –MemberType NoteProperty –Name PluginName -Value $ri.plugin_name
					$object | Add-Member –MemberType NoteProperty –Name PluginPublication -Value $ri.plugin_publication_date
					$object | Add-Member –MemberType NoteProperty –Name RiskFactor -Value $ri.risk_factor
					$object | Add-Member –MemberType NoteProperty –Name CheckName -Value (CleanName $category $checkname)
					$object | Add-Member -MemberType NoteProperty -Name CheckCategory -Value $category
					$object | Add-Member –MemberType NoteProperty –Name CheckActualValue -Value $ri.'compliance-actual-value'
					$object | Add-Member -MemberType NoteProperty -Name CheckPolicyValue -Value $ri.'compliance-policy-value'
					$object | Add-Member –MemberType NoteProperty –Name CheckDescription -Value $ri.description
					$object | Add-Member –MemberType NoteProperty –Name CheckID -Value $ri.'compliance-check-id'
					$object | Add-Member –MemberType NoteProperty –Name CheckInfo -Value $ri.'compliance-info'
					$object | Add-Member –MemberType NoteProperty –Name CheckResult -Value $ri.'compliance-result'
					$object | Add-Member –MemberType NoteProperty –Name CheckReference -Value $ri'.compliance-solution'
					$object | Add-Member –MemberType NoteProperty –Name CheckSolution -Value $ri.'compliance-solution'
					$object | Add-Member –MemberType NoteProperty –Name CheckSeeAlso -Value $ri.'compliance-see-also'
					$items += $object
				}
			}
		}

		$hostinfo.ReportItems = $items
		$allhosts += $hostinfo
	}
	return $allhosts
}

function Create-PieChart($title, $stats, $filename)
{
	[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
	[void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms.DataVisualization")

	$chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
	$chart.Width = 237
	$chart.Height = 280
	$chart.BackColor = [System.Drawing.Color]::White
	$chart.Titles.Add("Vulnerabilities (% of Total)") | Out-Null
	#$chart.Titles[0].Font = "segoeuilight,13pt"
	$chart.Titles[0].Alignment = "topLeft"
	$chart.AntiAliasing = [System.Windows.Forms.DataVisualization.Charting.AntiAliasingStyles]::All
	$chart.TextAntiAliasingQuality = [System.Windows.Forms.DataVisualization.Charting.TextAntiAliasingQuality]::High

	$chartarea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
	$chartarea.Name = "ChartArea1"
	$chartarea.BorderWidth = 0
	#$chartarea.Area3DStyle.Enable3D = $true
	$chartarea.Position.Height = 75
	$chartarea.Position.Width = 75
	$chartarea.Position.X = 12
	$chartarea.Position.Y = 10
	$chartarea.AxisX.LineWidth = 0
	$chartarea.AxisX.IsMarginVisible = "False"
	$chartarea.AxisX.MajorGrid.LineColor = [System.Drawing.Color]::LightGray
	$chartarea.AxisY.MajorGrid.LineColor = [System.Drawing.Color]::LightGray
	$chartarea.Area3DStyle.WallWidth = 0
	$chartarea.Area3DStyle.LightStyle = [System.Windows.Forms.DataVisualization.Charting.LightStyle]::Simplistic
	$chartarea.BackColor = [System.Drawing.Color]::White
	$chart.ChartAreas.Add($chartarea)

	$legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend -ArgumentList "Legend"
	$legend.Docking = [System.Windows.Forms.DataVisualization.Charting.Docking]::Bottom
	$legend.Alignment = [System.Drawing.StringAlignment]::Center
	$chart.Legends.Add($legend)


	$s = $chart.Series.Add("Series")
	$s.Name = $title
	$s.IsValueShownAsLabel = $true
	$s.Legend = "Legend"
	$s.IsVisibleInLegend = $true
	$s.ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie

	$percentages = @{}
	$total = 0
	$stats.Values | %{$total += $_}

	foreach ($v in $stats.Keys)
	{
		$percentages.Add($v, "{0:N0}" -f (($stats[$v] / $total) * 100))
	}

	$s.Points.DataBindXY($percentages.Keys, $percentages.Values)

	foreach ($p in $s.Points)
	{
		switch ($p.AxisLabel)
		{
			{($_ -eq "Critical") -or ($_ -eq "Failed") }
			{
				$p.Color = [System.Drawing.ColorTranslator]::FromHtml("#D43F3A")
				break
			}
			{($_ -eq "High") -or ($_ -eq "Error") }
			{
				$p.Color = [System.Drawing.ColorTranslator]::FromHtml("#EE9336")
				break
			}
			{($_ -eq "Medium") -or ($_ -eq "Warning") }
			{
				$p.Color = [System.Drawing.ColorTranslator]::FromHtml("#FDC431")
				break
			}
			{($_ -eq "Low") -or ($_ -eq "Passed") }
			{
				$p.Color = [System.Drawing.ColorTranslator]::FromHtml("#4CAE4C")
				break
			}
			"Info"
			{
				$p.Color = [System.Drawing.ColorTranslator]::FromHtml("#D43F3A")
				break
			}
		}
	}

	foreach ($k in $percentages.Keys)
	{
		$v = $percentages[$k]
		Write-Debug "ChartData: $k : $v"
	}

	$chart.SaveImage("$filename","png")
	Write-Debug "Create-PieChart: Image file saved to $filename"
}

#endregion

#region MAIN SCRIPT
#______________________________________ MAIN SCRIPT BLOCK ______________________________________

# Do Prereqs. Ensure files & folders exist, etc.
Write-Host "[*] Performing PreReq Checks..."
Do-PreReqs

# Parse out the nessus file into a friendly collection
Write-Host "[*] Parsing Nessus File (could take a while)..."

if ($CIS -eq $true)
{
	$allhostinfo = Parse-CISNessusFile $NessusFilePath $oscategory
	Write-Host "[*] Copying html template to $newfolder"
	Copy-Item $htmltemplatedir $newfolder -Recurse

	$reportlinks = ""
	foreach ($hostinfo in $allhostinfo)
	{
		$findingreport = Create-CISFinding $hostinfo $reportsbyhostfolder
	}

	$csvinfo = @()
	foreach ($h in $allhostinfo)
	{
		foreach ($ri in $h.ReportItems)
		{
			$csvinfo += [pscustomobject][ordered]@{
				IPAddress = $h.IPAddress
				FQDN = $h.FQDN
				CheckName = $ri.CheckName
				Description = $ri.CheckDescription
				Result = $ri.CheckResult
				PolicyValue = $ri.CheckPolicyValue
				ActualValue = $ri.CheckActualValue
			}
		}
	}

	Write-Host "[*] Creating dashboard..."
	Create-CISDashboard $allhostinfo $reportlinks $newfolder $customername $operatingsystem

	$csvpath = "$extraspath\findings.csv"
}
else
{
	$allhostinfo = Parse-NessusFile $NessusFilePath

	# Make a duplicate of the html template directory
	Write-Host "[*] Copying html template to $newfolder"
	Copy-Item $htmltemplatedir $newfolder -Recurse
	# Create an html report for each host
	if ($createreportsbyhost -eq $true)
	{
		foreach ($hostinfo in $allhostinfo)
		{
			$hosthtml = Format-HostHtml $hostinfo $false
			$findingreport = Create-HostReport $hostinfo $reportsbyhostfolder $hosthtml
		}
	}

	$csvinfo = @()
	foreach ($h in $allhostinfo)
	{
		$csvinfo += [pscustomobject][ordered]@{
			IPAddress =			$h.IPAddress
			HostName =			$h.HostName
			OperatingSystem =	$h.OperatingSystem
			OpenTCPPorts =		$h.OpenTCPPorts
			OpenUDPPorts =		$h.OpenUDPPorts
		}
	}

	# Create a dashboard file (index.htm)
	Write-Host "[*] Creating dashboard..."
	$vulnstats = Create-DashboardReport $allhostinfo $reportlinks $newfolder $CustomerName $reportsbyhostfolder

	Write-Host "[*] Creating vulnerability report (could also take a while)..."
	# Create the report that shows all vulnerabilities
	$allvulns = Get-VulnsByHost $allhostinfo
	Create-VulnReport $vulnnames $allvulns $reportbyvulnfolder $vulnstats

	$csvpath = "$extraspath\hostinfo.csv"

	Write-Host "[*] Creating $extraspath\ipsbyvuln.txt..."
	$output = ""
	foreach ($vuln in $script:ipsbyvuln.Keys)
	{
		$output += "$vuln`n"
		foreach ($ip in $script:ipsbyvuln[$vuln])
		{
			$output += "$ip`n"
		}
		$output += "`n"
	}
	New-Item -Path "$extraspath\ipsbyvuln.txt" -ItemType File -Force | Out-Null
	$output | Out-File "$extraspath\ipsbyvuln.txt"
}

Write-Host "[*] Creating $csvpath..."
New-Item -Path $csvpath -ItemType File -Force | Out-Null
$csvinfo | Export-CSV -Path $csvpath

# Write out the chart. $chartstats is populated in the respective Create-Dashboard functions.
Write-Host "[*] Saving chart to $chartpath"
Create-PieChart "High Level" $chartstats $chartpath

# Cleanup
Remove-Item -Path "$newfolder\templateFindings.html"
Remove-Item -Path "$newfolder\templateDashboard.html"
Remove-Item -Path "$newfolder\templateByVuln.html" -ErrorAction SilentlyContinue

# Done
Write-Host "[*] Done!`n"
#endregion