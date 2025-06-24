<#
.SYNOPSIS
    Microsoft Teams Channels and Membership Report Generator
.DESCRIPTION
    Generates comprehensive HTML reports of all Teams, channels, and memberships
    with privacy settings, member details, and access control analysis.
.PARAMETER TenantId
    Azure AD Tenant ID (optional)
.PARAMETER ClientId
    Azure AD Application Client ID (optional)
.PARAMETER UseDeviceCode
    Use device code authentication flow
.EXAMPLE
    .\teams-channels-report.ps1
.EXAMPLE
    .\teams-channels-report.ps1 -UseDeviceCode -Verbose
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseDeviceCode
)

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Teams -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Write-Host "Successfully imported Microsoft Graph modules" -ForegroundColor Green
} catch {
    Write-Error "Failed to import required modules. Please install Microsoft Graph PowerShell SDK first."
    Write-Host "Run: Install-Module Microsoft.Graph -Force" -ForegroundColor Yellow
    exit 1
}

# Authentication function
function Connect-ToMicrosoftGraph {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [bool]$UseDeviceCode
    )
    
    try {
        $connectParams = @{
            Scopes = @(
                'Team.ReadBasic.All',
                'Channel.ReadBasic.All',
                'TeamMember.Read.All',
                'User.Read.All',
                'Directory.Read.All'
            )
        }
        
        if ($UseDeviceCode) {
            $connectParams.Add('UseDeviceAuthentication', $true)
        }
        
        if ($TenantId) {
            $connectParams.Add('TenantId', $TenantId)
        }
        
        if ($ClientId) {
            $connectParams.Add('ClientId', $ClientId)
        }
        
        Connect-MgGraph @connectParams -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
        
        # Verify connection
        $context = Get-MgContext
        Write-Host "Connected to tenant: $($context.TenantId)" -ForegroundColor Cyan
        Write-Host "Authenticated as: $($context.Account)" -ForegroundColor Cyan
        
    } catch {
        Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 1
    }
}

# Get all teams with detailed information
function Get-AllTeams {
    Write-Host "Retrieving all Teams..." -ForegroundColor Yellow
    
    try {
        $teams = Get-MgTeam -All -ErrorAction Stop
        Write-Host "Found $($teams.Count) teams" -ForegroundColor Green
        
        $enrichedTeams = @()
        $counter = 0
        
        foreach ($team in $teams) {
            $counter++
            Write-Progress -Activity "Processing teams" -Status "Processing $($team.DisplayName)" -PercentComplete (($counter / $teams.Count) * 100)
            
            # Get team details
            try {
                $teamDetails = Get-MgTeam -TeamId $team.Id -ErrorAction SilentlyContinue
                $group = Get-MgGroup -GroupId $team.Id -Property @('CreatedDateTime', 'Description', 'Visibility', 'MembershipRule') -ErrorAction SilentlyContinue
                
                # Get team members
                $members = Get-TeamMembers -TeamId $team.Id
                
                # Get team channels
                $channels = Get-TeamChannels -TeamId $team.Id
                
                $enrichedTeam = [PSCustomObject]@{
                    Id = $team.Id
                    DisplayName = $team.DisplayName
                    Description = if($group) { $group.Description } else { "N/A" }
                    Visibility = if($group) { $group.Visibility } else { "Unknown" }
                    CreatedDateTime = if($group) { $group.CreatedDateTime } else { $null }
                    MembershipType = if ($group -and $group.MembershipRule) { 'Dynamic' } else { 'Assigned' }
                    MemberCount = $members.Count
                    OwnerCount = ($members | Where-Object { $_.Role -eq 'Owner' }).Count
                    ChannelCount = $channels.Count
                    PrivateChannelCount = ($channels | Where-Object { $_.MembershipType -eq 'Private' }).Count
                    SharedChannelCount = ($channels | Where-Object { $_.MembershipType -eq 'Shared' }).Count
                    Members = $members
                    Channels = $channels
                }
                
                $enrichedTeams += $enrichedTeam
                
            } catch {
                Write-Warning "Could not retrieve full details for team: $($team.DisplayName) - $($_.Exception.Message)"
                # Add basic team info even if details fail
                $enrichedTeam = [PSCustomObject]@{
                    Id = $team.Id
                    DisplayName = $team.DisplayName
                    Description = "Unable to retrieve"
                    Visibility = "Unknown"
                    CreatedDateTime = $null
                    MembershipType = "Unknown"
                    MemberCount = 0
                    OwnerCount = 0
                    ChannelCount = 0
                    PrivateChannelCount = 0
                    SharedChannelCount = 0
                    Members = @()
                    Channels = @()
                }
                $enrichedTeams += $enrichedTeam
            }
        }
        
        Write-Progress -Activity "Processing teams" -Completed
        return $enrichedTeams
        
    } catch {
        Write-Error "Failed to retrieve teams: $($_.Exception.Message)"
        return @()
    }
}

# Get team members
function Get-TeamMembers {
    param(
        [string]$TeamId
    )
    
    try {
        $members = Get-MgTeamMember -TeamId $TeamId -All -ErrorAction SilentlyContinue
        $enrichedMembers = @()
        
        foreach ($member in $members) {
            try {
                # Get user details
                $user = Get-MgUser -UserId $member.UserId -Property @('DisplayName', 'Mail', 'UserPrincipalName', 'UserType', 'Department', 'JobTitle') -ErrorAction SilentlyContinue
                
                $enrichedMember = [PSCustomObject]@{
                    Id = $member.Id
                    UserId = $member.UserId
                    DisplayName = if($user) { $user.DisplayName } else { "Unknown User" }
                    Email = if($user) { $user.Mail } else { "" }
                    UserPrincipalName = if($user) { $user.UserPrincipalName } else { "" }
                    UserType = if($user) { $user.UserType } else { "" }
                    Department = if($user) { $user.Department } else { "" }
                    JobTitle = if($user) { $user.JobTitle } else { "" }
                    Role = if ($member.Roles -contains 'owner') { 'Owner' } else { 'Member' }
                }
                
                $enrichedMembers += $enrichedMember
                
            } catch {
                Write-Warning "Could not retrieve details for user ID: $($member.UserId)"
                # Handle cases where user details can't be retrieved
                $enrichedMember = [PSCustomObject]@{
                    Id = $member.Id
                    UserId = $member.UserId
                    DisplayName = "Unknown User (ID: $($member.UserId))"
                    Email = ""
                    UserPrincipalName = ""
                    UserType = "Unknown"
                    Department = ""
                    JobTitle = ""
                    Role = if ($member.Roles -contains 'owner') { 'Owner' } else { 'Member' }
                }
                $enrichedMembers += $enrichedMember
            }
        }
        
        return $enrichedMembers
        
    } catch {
        Write-Warning "Could not retrieve members for team ID: $TeamId"
        return @()
    }
}

# Get team channels
function Get-TeamChannels {
    param(
        [string]$TeamId
    )
    
    try {
        $channels = Get-MgTeamChannel -TeamId $TeamId -All -ErrorAction SilentlyContinue
        $enrichedChannels = @()
        
        foreach ($channel in $channels) {
            try {
                # Get channel members for private channels
                $channelMembers = @()
                if ($channel.MembershipType -eq 'Private') {
                    try {
                        $channelMembers = Get-MgTeamChannelMember -TeamId $TeamId -ChannelId $channel.Id -All -ErrorAction SilentlyContinue
                    } catch {
                        # Some channels might not allow member enumeration
                    }
                }
                
                $enrichedChannel = [PSCustomObject]@{
                    Id = $channel.Id
                    DisplayName = $channel.DisplayName
                    Description = $channel.Description
                    MembershipType = $channel.MembershipType
                    CreatedDateTime = $channel.CreatedDateTime
                    WebUrl = $channel.WebUrl
                    MemberCount = $channelMembers.Count
                    Members = $channelMembers
                }
                
                $enrichedChannels += $enrichedChannel
                
            } catch {
                Write-Warning "Could not retrieve details for channel: $($channel.DisplayName)"
                
                $enrichedChannel = [PSCustomObject]@{
                    Id = $channel.Id
                    DisplayName = $channel.DisplayName
                    Description = $channel.Description
                    MembershipType = $channel.MembershipType
                    CreatedDateTime = $channel.CreatedDateTime
                    WebUrl = $channel.WebUrl
                    MemberCount = 0
                    Members = @()
                }
                
                $enrichedChannels += $enrichedChannel
            }
        }
        
        return $enrichedChannels
        
    } catch {
        Write-Warning "Could not retrieve channels for team ID: $TeamId"
        return @()
    }
}

# Generate HTML report
function Generate-TeamsHTML {
    param(
        [array]$Teams
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Calculate statistics
    $totalTeams = $Teams.Count
    $publicTeams = ($Teams | Where-Object { $_.Visibility -eq 'Public' }).Count
    $privateTeams = ($Teams | Where-Object { $_.Visibility -eq 'Private' }).Count
    $totalChannels = ($Teams | ForEach-Object { $_.ChannelCount } | Measure-Object -Sum).Sum
    $totalPrivateChannels = ($Teams | ForEach-Object { $_.PrivateChannelCount } | Measure-Object -Sum).Sum
    $totalSharedChannels = ($Teams | ForEach-Object { $_.SharedChannelCount } | Measure-Object -Sum).Sum
    $totalMembers = ($Teams | ForEach-Object { $_.MemberCount } | Measure-Object -Sum).Sum
    
    # Generate teams overview HTML
    $teamsOverviewHtml = ""
    foreach ($team in $Teams) {
        $visibilityClass = switch ($team.Visibility) {
            'Public' { 'visibility-public' }
            'Private' { 'visibility-private' }
            default { 'visibility-unknown' }
        }
        
        $created = if ($team.CreatedDateTime) { 
            $team.CreatedDateTime.ToString("yyyy-MM-dd") 
        } else { 
            "Unknown" 
        }
        
        $teamsOverviewHtml += "<tr class='$visibilityClass'>"
        $teamsOverviewHtml += "<td><strong>$($team.DisplayName)</strong></td>"
        $teamsOverviewHtml += "<td>$($team.Description)</td>"
        $teamsOverviewHtml += "<td><span class='visibility-badge $visibilityClass'>$($team.Visibility)</span></td>"
        $teamsOverviewHtml += "<td>$($team.MembershipType)</td>"
        $teamsOverviewHtml += "<td>$created</td>"
        $teamsOverviewHtml += "<td>$($team.MemberCount)</td>"
        $teamsOverviewHtml += "<td>$($team.OwnerCount)</td>"
        $teamsOverviewHtml += "<td>$($team.ChannelCount)</td>"
        $teamsOverviewHtml += "<td>$($team.PrivateChannelCount)</td>"
        $teamsOverviewHtml += "<td>$($team.SharedChannelCount)</td>"
        $teamsOverviewHtml += "</tr>"
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Channels Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; margin-top: 20px; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .visibility-public { background-color: #e8f5e8; }
        .visibility-private { background-color: #fff3e0; }
        .visibility-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .visibility-badge.visibility-public { background: #4caf50; color: white; }
        .visibility-badge.visibility-private { background: #ff9800; color: white; }
        .stats { margin: 20px 0; }
        .stats ul { list-style-type: none; padding: 0; }
        .stats li { display: inline-block; margin-right: 20px; padding: 10px; background: #f0f0f0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Microsoft Teams Channels Report</h1>
    <p>Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
    
    <div class="stats">
        <h2>Statistics</h2>
        <ul>
            <li><strong>Total Teams:</strong> $totalTeams</li>
            <li><strong>Public Teams:</strong> $publicTeams</li>
            <li><strong>Private Teams:</strong> $privateTeams</li>
            <li><strong>Total Channels:</strong> $totalChannels</li>
            <li><strong>Private Channels:</strong> $totalPrivateChannels</li>
            <li><strong>Shared Channels:</strong> $totalSharedChannels</li>
            <li><strong>Total Members:</strong> $totalMembers</li>
        </ul>
    </div>
    
    <h2>Teams Overview</h2>
    <table>
        <thead>
            <tr>
                <th>Team Name</th>
                <th>Description</th>
                <th>Visibility</th>
                <th>Membership Type</th>
                <th>Created</th>
                <th>Members</th>
                <th>Owners</th>
                <th>Channels</th>
                <th>Private Channels</th>
                <th>Shared Channels</th>
            </tr>
        </thead>
        <tbody>
            $teamsOverviewHtml
        </tbody>
    </table>
</body>
</html>
"@
    
    return $htmlContent
}

# Save HTML report with file dialog
function Save-HTMLReport {
    param(
        [string]$HtmlContent,
        [string]$DefaultFileName
    )
    
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
        $saveFileDialog.FilterIndex = 1
        $saveFileDialog.FileName = $DefaultFileName
        $saveFileDialog.Title = "Save Teams Channels Report"
        
        $dialogResult = $saveFileDialog.ShowDialog()
        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $HtmlContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8 -ErrorAction Stop
                Write-Host "Report saved successfully: $($saveFileDialog.FileName)" -ForegroundColor Green
                
                # Ask if user wants to open the report
                $openReport = Read-Host "Would you like to open the report now? (Y/N)"
                if ($openReport -eq 'Y' -or $openReport -eq 'y') {
                    Start-Process $saveFileDialog.FileName
                }
                
                return $saveFileDialog.FileName
            } catch {
                Write-Error "Failed to save report: $($_.Exception.Message)"
                return $null
            }
        } else {
            Write-Host "Save operation cancelled by user" -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Error "Failed to initialize file dialog: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
function Main {
    try {
        Write-Host "Starting Microsoft Teams Channels Report Generation" -ForegroundColor Cyan
        Write-Host "=" * 60 -ForegroundColor Cyan
        
        # Connect to Microsoft Graph
        Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
        
        # Get all teams
        $teams = Get-AllTeams
        
        if ($teams.Count -eq 0) {
            Write-Host "No teams found in the tenant" -ForegroundColor Yellow
            return
        }
        
        # Generate HTML report
        Write-Host "Generating HTML report..." -ForegroundColor Yellow
        $htmlContent = Generate-TeamsHTML -Teams $teams
        
        # Save report
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $defaultFileName = "Teams-Channels-Report-$timestamp.html"
        $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
        
        if ($savedFile) {
            Write-Host "Teams channels report generation completed successfully!" -ForegroundColor Green
            Write-Host "Report contains $($teams.Count) teams" -ForegroundColor Green
            Write-Host "Saved to: $savedFile" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "Script execution failed: $($_.Exception.Message)"
    } finally {
        # Disconnect from Microsoft Graph
        try {
            if (Get-MgContext -ErrorAction SilentlyContinue) {
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Failed to disconnect from Microsoft Graph: $($_.Exception.Message)"
        }
    }
}

# Execute main function
Main
