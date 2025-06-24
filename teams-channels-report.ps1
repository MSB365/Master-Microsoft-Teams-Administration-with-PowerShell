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
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Teams -Force
    Import-Module Microsoft.Graph.Users -Force
    Write-Host "✅ Successfully imported Microsoft Graph modules" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to import required modules. Please install Microsoft Graph PowerShell SDK first."
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
        
        Connect-MgGraph @connectParams
        Write-Host "✅ Successfully connected to Microsoft Graph" -ForegroundColor Green
        
        # Verify connection
        $context = Get-MgContext
        Write-Host "📋 Connected to tenant: $($context.TenantId)" -ForegroundColor Cyan
        Write-Host "👤 Authenticated as: $($context.Account)" -ForegroundColor Cyan
        
    } catch {
        Write-Error "❌ Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 1
    }
}

# Get all teams with detailed information
function Get-AllTeams {
    Write-Host "🏢 Retrieving all Teams..." -ForegroundColor Yellow
    
    try {
        $teams = Get-MgTeam -All
        Write-Host "📊 Found $($teams.Count) teams" -ForegroundColor Green
        
        $enrichedTeams = @()
        $counter = 0
        
        foreach ($team in $teams) {
            $counter++
            Write-Progress -Activity "Processing teams" -Status "Processing $($team.DisplayName)" -PercentComplete (($counter / $teams.Count) * 100)
            
            # Get team details
            try {
                $teamDetails = Get-MgTeam -TeamId $team.Id
                $group = Get-MgGroup -GroupId $team.Id -Property @('CreatedDateTime', 'Description', 'Visibility', 'MembershipRule')
                
                # Get team members
                $members = Get-TeamMembers -TeamId $team.Id
                
                # Get team channels
                $channels = Get-TeamChannels -TeamId $team.Id
                
                $enrichedTeam = [PSCustomObject]@{
                    Id = $team.Id
                    DisplayName = $team.DisplayName
                    Description = $group.Description
                    Visibility = $group.Visibility
                    CreatedDateTime = $group.CreatedDateTime
                    MembershipType = if ($group.MembershipRule) { 'Dynamic' } else { 'Assigned' }
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
                Write-Warning "⚠️ Could not retrieve details for team: $($team.DisplayName) - $($_.Exception.Message)"
                
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
        Write-Error "❌ Failed to retrieve teams: $($_.Exception.Message)"
        return @()
    }
}

# Get team members
function Get-TeamMembers {
    param(
        [string]$TeamId
    )
    
    try {
        $members = Get-MgTeamMember -TeamId $TeamId -All
        $enrichedMembers = @()
        
        foreach ($member in $members) {
            try {
                # Get user details
                $user = Get-MgUser -UserId $member.UserId -Property @('DisplayName', 'Mail', 'UserPrincipalName', 'UserType', 'Department', 'JobTitle')
                
                $enrichedMember = [PSCustomObject]@{
                    Id = $member.Id
                    UserId = $member.UserId
                    DisplayName = $user.DisplayName
                    Email = $user.Mail
                    UserPrincipalName = $user.UserPrincipalName
                    UserType = $user.UserType
                    Department = $user.Department
                    JobTitle = $user.JobTitle
                    Role = if ($member.Roles -contains 'owner') { 'Owner' } else { 'Member' }
                }
                
                $enrichedMembers += $enrichedMember
                
            } catch {
                # Handle cases where user details can't be retrieved
                $enrichedMember = [PSCustomObject]@{
                    Id = $member.Id
                    UserId = $member.UserId
                    DisplayName = "Unknown User"
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
        Write-Warning "⚠️ Could not retrieve members for team ID: $TeamId"
        return @()
    }
}

# Get team channels
function Get-TeamChannels {
    param(
        [string]$TeamId
    )
    
    try {
        $channels = Get-MgTeamChannel -TeamId $TeamId -All
        $enrichedChannels = @()
        
        foreach ($channel in $channels) {
            try {
                # Get channel members for private channels
                $channelMembers = @()
                if ($channel.MembershipType -eq 'Private') {
                    try {
                        $channelMembers = Get-MgTeamChannelMember -TeamId $TeamId -ChannelId $channel.Id -All
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
                Write-Warning "⚠️ Could not retrieve details for channel: $($channel.DisplayName)"
                
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
        Write-Warning "⚠️ Could not retrieve channels for team ID: $TeamId"
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
        
        $teamsOverviewHtml += @"
        <tr class="$visibilityClass">
            <td><strong>$($team.DisplayName)</strong></td>
            <td>$($team.Description)</td>
            <td><span class="visibility-badge $visibilityClass">$($team.Visibility)</span></td>
            <td>$($team.MembershipType)</td>
            <td>$created</td>
            <td>$($team.MemberCount)</td>
            <td>$($team.OwnerCount)</td>
            <td>$($team.ChannelCount)</td>
            <td>$($team.PrivateChannelCount)</td>
            <td>$($team.SharedChannelCount)</td>
        </tr>
"@
    }
    
    # Generate detailed teams and channels HTML
    $detailedTeamsHtml = ""
    foreach ($team in $Teams) {
        $detailedTeamsHtml += @"
        <div class="team-section">
            <h3>🏢 $($team.DisplayName)</h3>
            <div class="team-info">
                <p><strong>Description:</strong> $($team.Description)</p>
                <p><strong>Visibility:</strong> <span class="visibility-badge visibility-$(($team.Visibility).ToLower())">$($team.Visibility)</span></p>
                <p><strong>Members:</strong> $($team.MemberCount) | <strong>Owners:</strong> $($team.OwnerCount) | <strong>Channels:</strong> $($team.ChannelCount)</p>
            </div>
            
            <h4>📋 Channels</h4>
            <div class="channels-container">
"@
        
        foreach ($channel in $team.Channels) {
            $membershipClass = switch ($channel.MembershipType) {
                'Standard' { 'channel-standard' }
                'Private' { 'channel-private' }
                'Shared' { 'channel-shared' }
                default { 'channel-unknown' }
            }
            
            $detailedTeamsHtml += @"
                <div class="channel-card $membershipClass">
                    <h5># $($channel.DisplayName)</h5>
                    <p><strong>Type:</strong> <span class="channel-badge $membershipClass">$($channel.MembershipType)</span></p>
                    <p><strong>Description:</strong> $($channel.Description)</p>
                    $(if ($channel.MembershipType -eq 'Private' -and $channel.MemberCount -gt 0) {
                        "<p><strong>Members:</strong> $($channel.MemberCount)</p>"
                    })
                </div>
"@
        }
        
        $detailedTeamsHtml += @"
            </div>
            
            <h4>👥 Team Members</h4>
            <div class="members-container">
"@
        
        foreach ($member in $team.Members) {
            $roleClass = if ($member.Role -eq 'Owner') { 'member-owner' } else { 'member-regular' }
            $userTypeClass = if ($member.UserType -eq 'Guest') { 'user-guest' } else { 'user-internal' }
            
            $detailedTeamsHtml += @"
                <div class="member-card $roleClass $userTypeClass">
                    <h6>$($member.DisplayName)</h6>
                    <p><strong>Role:</strong> <span class="role-badge $roleClass">$($member.Role)</span></p>
                    <p><strong>Email:</strong> $($member.Email)</p>
                    <p><strong>Type:</strong> <span class="user-badge $userTypeClass">$($member.UserType)</span></p>
                    $(if ($member.Department) { "<p><strong>Department:</strong> $($member.Department)</p>" })
                    $(if ($member.JobTitle) { "<p><strong>Job Title:</strong> $($member.JobTitle)</p>" })
                </div>
"@
        }
        
        $detailedTeamsHtml += @"
            </div>
        </div>
"@
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Channels Report - $timestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #6264a7 0%, #5b5fc7 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2rem; font-weight: bold; color: #6264a7; }
        .stat-label { color: #666; margin-top: 5px; font-size: 0.9rem; }
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; margin-bottom: 20px; font-size: 1.8rem; }
        .table-container { overflow-x: auto; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 30px; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th { background: #6264a7; color: white; padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #e9ecef; }
        tr:hover { background: #f8f9fa; }
        .visibility-public { background-color: #e8f5e8 !important; }
        .visibility-private { background-color: #fff3e0 !important; }
        .visibility-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .visibility-badge.visibility-public { background: #4caf50; color: white; }
        .visibility-badge.visibility-private { background: #ff9800; color: white; }
        .team-section { background: #f8f9fa; padding: 30px; border-radius: 15px; margin-bottom: 30px; }
        .team-section h3 { color: #6264a7; margin-bottom: 15px; font-size: 1.5rem; }
        .team-info { background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .team-info p { margin-bottom: 8px; }
        .channels-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .channel-card { background: white; padding: 20px; border-radius: 10px; border-left: 4px solid #6264a7; }
        .channel-card.channel-private { border-left-color: #ff9800; }
        .channel-card.channel-shared { border-left-color: #2196f3; }
        .channel-card h5 { color: #2c3e50; margin-bottom: 10px; }
        .channel-badge { padding: 3px 6px; border-radius: 3px; font-size: 0.75rem; font-weight: bold; }
        .channel-badge.channel-standard { background: #4caf50; color: white; }
        .channel-badge.channel-private { background: #ff9800; color: white; }
        .channel-badge.channel-shared { background: #2196f3; color: white; }
        .members-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 15px; }
        .member-card { background: white; padding: 15px; border-radius: 8px; border-left: 3px solid #6264a7; }
        .member-card.member-owner { border-left-color: #f44336; }
        .member-card.user-guest { background: #fff3e0; }
        .member-card h6 { color: #2c3e50; margin-bottom: 8px; }
        .role-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }
        .role-badge.member-owner { background: #f44336; color: white; }
        .role-badge.member-regular { background: #4caf50; color: white; }
        .user-badge { padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; }
        .user-badge.user-internal { background: #2196f3; color: white; }
        .user-badge.user-guest { background: #ff9800; color: white; }
        .search-box { margin-bottom: 20px; }
        .search-box input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; }
        .footer { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        @media (max-width: 768px) {
            .header { padding: 20px; }
            .header h1 { font-size: 2rem; }
            .content { padding: 20px; }
            .stats { padding: 20px; gap: 15px; }
            .channels-container, .members-container { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏢 Microsoft Teams Channels Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$totalTeams</div>
                <div class="stat-label">Total Teams</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$publicTeams</div>
                <div class="stat-label">Public Teams</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$privateTeams</div>
                <div class="stat-label">Private Teams</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalChannels</div>
                <div class="stat-label">Total Channels</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalPrivateChannels</div>
                <div class="stat-label">Private Channels</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalSharedChannels</div>
                <div class="stat-label">Shared Channels</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalMembers</div>
                <div class="stat-label">Total Members</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p>This report provides a comprehensive overview of all Microsoft Teams, channels, and memberships in your organization. 
                It includes privacy settings, member details, and access control analysis.</p>
                
                <h3>Key Findings:</h3>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><strong>Total Teams:</strong> $totalTeams teams identified</li>
                    <li><strong>Privacy Distribution:</strong> $publicTeams public, $privateTeams private teams</li>
                    <li><strong>Channel Analysis:</strong> $totalChannels total channels ($totalPrivateChannels private, $totalSharedChannels shared)</li>
                    <li><strong>Membership:</strong> $totalMembers total team members across all teams</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>🏢 Teams Overview</h2>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="🔍 Search teams by name, description, or visibility..." onkeyup="filterTable()">
                </div>
                
                <div class="table-container">
                    <table id="teamsTable">
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
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Detailed Teams and Channels</h2>
                $detailedTeamsHtml
            </div>
            
            <div class="section">
                <h2>🛡️ Security and Governance Recommendations</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                    <h3>Access Control Review:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li><strong>Public Teams:</strong> Review $publicTeams public teams for sensitive information</li>
                        <li><strong>Private Channels:</strong> Audit $totalPrivateChannels private channels for appropriate access</li>
                        <li><strong>Guest Access:</strong> Review guest users in teams for compliance</li>
                        <li><strong>Owner Management:</strong> Ensure all teams have appropriate owners</li>
                        <li><strong>Regular Audits:</strong> Implement quarterly access reviews</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>📋 Microsoft Teams Channels Report | Generated by PowerShell Script | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </div>
    
    <script>
        function filterTable() {
            const input = document.getElementById('searchInput');
            const filter = input.value.toUpperCase();
            const table = document.getElementById('teamsTable');
            const tr = table.getElementsByTagName('tr');
            
            for (let i = 1; i < tr.length; i++) {
                const td = tr[i].getElementsByTagName('td');
                let txtValue = '';
                for (let j = 0; j < td.length; j++) {
                    txtValue += td[j].textContent || td[j].innerText;
                }
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = '';
                } else {
                    tr[i].style.display = 'none';
                }
            }
        }
    </script>
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
    
    Add-Type -AssemblyName System.Windows.Forms
    
    $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveFileDialog.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
    $saveFileDialog.FilterIndex = 1
    $saveFileDialog.FileName = $DefaultFileName
    $saveFileDialog.Title = "Save Teams Channels Report"
    
    if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $HtmlContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8
            Write-Host "✅ Report saved successfully: $($saveFileDialog.FileName)" -ForegroundColor Green
            
            # Ask if user wants to open the report
            $openReport = Read-Host "Would you like to open the report now? (Y/N)"
            if ($openReport -eq 'Y' -or $openReport -eq 'y') {
                Start-Process $saveFileDialog.FileName
            }
            
            return $saveFileDialog.FileName
        } catch {
            Write-Error "❌ Failed to save report: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Host "⚠️ Save operation cancelled by user" -ForegroundColor Yellow
        return $null
    }
}

# Main execution
function Main {
    Write-Host "🚀 Starting Microsoft Teams Channels Report Generation" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Connect to Microsoft Graph
    Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
    
    # Get all teams
    $teams = Get-AllTeams
    
    if ($teams.Count -eq 0) {
        Write-Host "ℹ️ No teams found in the tenant" -ForegroundColor Yellow
        return
    }
    
    # Generate HTML report
    Write-Host "📝 Generating HTML report..." -ForegroundColor Yellow
    $htmlContent = Generate-TeamsHTML -Teams $teams
    
    # Save report
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $defaultFileName = "Teams-Channels-Report-$timestamp.html"
    $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
    
    if ($savedFile) {
        Write-Host "🎉 Teams channels report generation completed successfully!" -ForegroundColor Green
        Write-Host "📊 Report contains $($teams.Count) teams" -ForegroundColor Green
        Write-Host "📁 Saved to: $savedFile" -ForegroundColor Green
    }
    
    # Disconnect from Microsoft Graph
    try {
        Disconnect-MgGraph | Out-Null
        Write-Host "✅ Disconnected from Microsoft Graph" -ForegroundColor Green
    } catch {
        # Ignore disconnect errors
    }
}

# Execute main function
Main
