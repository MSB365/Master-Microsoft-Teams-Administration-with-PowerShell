<#
.SYNOPSIS
    Microsoft Teams Guest User Report Generator
.DESCRIPTION
    Generates comprehensive HTML reports of all guest users in Microsoft Teams/365 environment
    with detailed information, risk assessment, and compliance insights.
.PARAMETER TenantId
    Azure AD Tenant ID (optional)
.PARAMETER ClientId
    Azure AD Application Client ID (optional)
.PARAMETER UseDeviceCode
    Use device code authentication flow
.EXAMPLE
    .\teams-guest-report.ps1
.EXAMPLE
    .\teams-guest-report.ps1 -UseDeviceCode
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
    Import-Module Microsoft.Graph.Users -Force
    Import-Module Microsoft.Graph.Identity.SignIns -Force
    Import-Module Microsoft.Graph.Reports -Force
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
                'User.Read.All',
                'Directory.Read.All',
                'AuditLog.Read.All',
                'Reports.Read.All'
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

# Get all guest users with detailed information
function Get-GuestUsers {
    Write-Host "🔍 Retrieving guest users..." -ForegroundColor Yellow
    
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Property @(
            'Id', 'DisplayName', 'Mail', 'UserPrincipalName', 'CreatedDateTime',
            'SignInActivity', 'Department', 'JobTitle', 'CompanyName', 'Country',
            'City', 'State', 'AccountEnabled', 'ExternalUserState', 'ExternalUserStateChangeDateTime'
        ) -All
        
        Write-Host "📊 Found $($guestUsers.Count) guest users" -ForegroundColor Green
        
        # Enrich with sign-in data
        $enrichedUsers = @()
        $counter = 0
        
        foreach ($user in $guestUsers) {
            $counter++
            Write-Progress -Activity "Processing guest users" -Status "Processing $($user.DisplayName)" -PercentComplete (($counter / $guestUsers.Count) * 100)
            
            $lastSignIn = $null
            try {
                if ($user.SignInActivity) {
                    $lastSignIn = $user.SignInActivity.LastSignInDateTime
                }
            } catch {
                # Sign-in data might not be available
            }
            
            # Calculate risk level
            $riskLevel = Get-UserRiskLevel -User $user -LastSignIn $lastSignIn
            
            $enrichedUser = [PSCustomObject]@{
                DisplayName = $user.DisplayName
                Email = $user.Mail
                UserPrincipalName = $user.UserPrincipalName
                Department = $user.Department
                JobTitle = $user.JobTitle
                CompanyName = $user.CompanyName
                Country = $user.Country
                City = $user.City
                State = $user.State
                CreatedDateTime = $user.CreatedDateTime
                LastSignInDateTime = $lastSignIn
                AccountEnabled = $user.AccountEnabled
                ExternalUserState = $user.ExternalUserState
                ExternalUserStateChangeDateTime = $user.ExternalUserStateChangeDateTime
                RiskLevel = $riskLevel
                DaysSinceCreated = if ($user.CreatedDateTime) { (Get-Date) - $user.CreatedDateTime | Select-Object -ExpandProperty Days } else { $null }
                DaysSinceLastSignIn = if ($lastSignIn) { (Get-Date) - $lastSignIn | Select-Object -ExpandProperty Days } else { $null }
            }
            
            $enrichedUsers += $enrichedUser
        }
        
        Write-Progress -Activity "Processing guest users" -Completed
        return $enrichedUsers
        
    } catch {
        Write-Error "❌ Failed to retrieve guest users: $($_.Exception.Message)"
        return @()
    }
}

# Calculate user risk level
function Get-UserRiskLevel {
    param(
        $User,
        $LastSignIn
    )
    
    $riskScore = 0
    
    # Account age risk
    if ($User.CreatedDateTime) {
        $daysSinceCreated = (Get-Date) - $User.CreatedDateTime | Select-Object -ExpandProperty Days
        if ($daysSinceCreated -gt 365) { $riskScore += 1 }
    }
    
    # Sign-in activity risk
    if ($LastSignIn) {
        $daysSinceLastSignIn = (Get-Date) - $LastSignIn | Select-Object -ExpandProperty Days
        if ($daysSinceLastSignIn -gt 90) { $riskScore += 2 }
        elseif ($daysSinceLastSignIn -gt 30) { $riskScore += 1 }
    } else {
        $riskScore += 3  # Never signed in
    }
    
    # Account status risk
    if (-not $User.AccountEnabled) { $riskScore += 2 }
    
    # External user state risk
    if ($User.ExternalUserState -eq 'PendingAcceptance') { $riskScore += 1 }
    
    # Determine risk level
    if ($riskScore -ge 5) { return 'High' }
    elseif ($riskScore -ge 3) { return 'Medium' }
    else { return 'Low' }
}

# Generate HTML report
function Generate-GuestHTML {
    param(
        [array]$GuestUsers
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Calculate statistics
    $totalGuests = $GuestUsers.Count
    $activeGuests = ($GuestUsers | Where-Object { $_.AccountEnabled -eq $true }).Count
    $highRiskGuests = ($GuestUsers | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $neverSignedIn = ($GuestUsers | Where-Object { $null -eq $_.LastSignInDateTime }).Count
    $inactiveGuests = ($GuestUsers | Where-Object { $_.DaysSinceLastSignIn -gt 90 }).Count
    
    # Generate user rows HTML
    $userRowsHtml = ""
    foreach ($user in $GuestUsers) {
        $riskClass = switch ($user.RiskLevel) {
            'High' { 'risk-high' }
            'Medium' { 'risk-medium' }
            'Low' { 'risk-low' }
            default { 'risk-unknown' }
        }
        
        $lastSignIn = if ($user.LastSignInDateTime) { 
            $user.LastSignInDateTime.ToString("yyyy-MM-dd HH:mm") 
        } else { 
            "Never" 
        }
        
        $created = if ($user.CreatedDateTime) { 
            $user.CreatedDateTime.ToString("yyyy-MM-dd") 
        } else { 
            "Unknown" 
        }
        
        $userRowsHtml += "<tr class=`"$riskClass`">"
        $userRowsHtml += "<td>$($user.DisplayName)</td>"
        $userRowsHtml += "<td>$($user.Email)</td>"
        $userRowsHtml += "<td>$($user.Department)</td>"
        $userRowsHtml += "<td>$($user.JobTitle)</td>"
        $userRowsHtml += "<td>$($user.CompanyName)</td>"
        $userRowsHtml += "<td>$($user.Country)</td>"
        $userRowsHtml += "<td>$created</td>"
        $userRowsHtml += "<td>$lastSignIn</td>"
        $userRowsHtml += "<td><span class=`"risk-badge $riskClass`">$($user.RiskLevel)</span></td>"
        $userRowsHtml += "<td>$($user.ExternalUserState)</td>"
        $userRowsHtml += "<td>$($user.AccountEnabled)</td>"
        $userRowsHtml += "</tr>"
    }
    
    # Create the HTML content using here-string with proper escaping
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Guest Users Report - $timestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2rem; font-weight: bold; color: #0078d4; }
        .stat-label { color: #666; margin-top: 5px; }
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; margin-bottom: 20px; font-size: 1.8rem; }
        .table-container { overflow-x: auto; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; }
        th { background: #0078d4; color: white; padding: 15px; text-align: left; font-weight: 600; }
        td { padding: 12px 15px; border-bottom: 1px solid #e9ecef; }
        tr:hover { background: #f8f9fa; }
        .risk-high { background-color: #ffebee !important; }
        .risk-medium { background-color: #fff3e0 !important; }
        .risk-low { background-color: #e8f5e8 !important; }
        .risk-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .risk-badge.risk-high { background: #f44336; color: white; }
        .risk-badge.risk-medium { background: #ff9800; color: white; }
        .risk-badge.risk-low { background: #4caf50; color: white; }
        .search-box { margin-bottom: 20px; }
        .search-box input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 1rem; }
        .footer { background: #2c3e50; color: white; padding: 20px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Microsoft Teams Guest Users Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$totalGuests</div>
                <div class="stat-label">Total Guest Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$activeGuests</div>
                <div class="stat-label">Active Accounts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$highRiskGuests</div>
                <div class="stat-label">High Risk Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$neverSignedIn</div>
                <div class="stat-label">Never Signed In</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$inactiveGuests</div>
                <div class="stat-label">Inactive (90+ days)</div>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <p>This report provides a comprehensive overview of all guest users in your Microsoft Teams environment. 
                Guest users are external users who have been invited to collaborate in your organization's Teams.</p>
                
                <h3>Key Findings:</h3>
                <ul style="margin-left: 20px; margin-top: 10px;">
                    <li><strong>Total Guest Users:</strong> $totalGuests users identified</li>
                    <li><strong>Security Risk:</strong> $highRiskGuests high-risk accounts require immediate attention</li>
                    <li><strong>Inactive Accounts:</strong> $inactiveGuests users haven't signed in for 90+ days</li>
                    <li><strong>Never Accessed:</strong> $neverSignedIn users have never signed in</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>Guest User Inventory</h2>
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="Search users by name, email, department, or company..." onkeyup="filterTable()">
                </div>
                
                <div class="table-container">
                    <table id="guestTable">
                        <thead>
                            <tr>
                                <th>Display Name</th>
                                <th>Email</th>
                                <th>Department</th>
                                <th>Job Title</th>
                                <th>Company</th>
                                <th>Country</th>
                                <th>Created</th>
                                <th>Last Sign-In</th>
                                <th>Risk Level</th>
                                <th>Status</th>
                                <th>Enabled</th>
                            </tr>
                        </thead>
                        <tbody>
                            $userRowsHtml
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="section">
                <h2>Security Recommendations</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                    <h3>Immediate Actions Required:</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li><strong>Review High-Risk Users:</strong> Investigate $highRiskGuests high-risk guest accounts</li>
                        <li><strong>Clean Up Inactive Accounts:</strong> Consider removing $inactiveGuests inactive users</li>
                        <li><strong>Follow Up on Pending Invitations:</strong> Check users who never signed in</li>
                        <li><strong>Regular Access Reviews:</strong> Implement quarterly guest user reviews</li>
                        <li><strong>Implement Conditional Access:</strong> Apply appropriate policies for guest users</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Microsoft Teams Guest Users Report | Generated by PowerShell Script | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </div>
    
    <script>
        function filterTable() {
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('guestTable');
            var tr = table.getElementsByTagName('tr');
            
            for (var i = 1; i < tr.length; i++) {
                var td = tr[i].getElementsByTagName('td');
                var txtValue = '';
                for (var j = 0; j < td.length; j++) {
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
    $saveFileDialog.Title = "Save Guest Users Report"
    
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
    Write-Host "🚀 Starting Microsoft Teams Guest Users Report Generation" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    # Connect to Microsoft Graph
    Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
    
    # Get guest users
    $guestUsers = Get-GuestUsers
    
    if ($guestUsers.Count -eq 0) {
        Write-Host "ℹ️ No guest users found in the tenant" -ForegroundColor Yellow
        return
    }
    
    # Generate HTML report
    Write-Host "📝 Generating HTML report..." -ForegroundColor Yellow
    $htmlContent = Generate-GuestHTML -GuestUsers $guestUsers
    
    # Save report
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $defaultFileName = "Teams-Guest-Accounts-Report-$timestamp.html"
    $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
    
    if ($savedFile) {
        Write-Host "🎉 Guest users report generation completed successfully!" -ForegroundColor Green
        Write-Host "📊 Report contains $($guestUsers.Count) guest users" -ForegroundColor Green
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
