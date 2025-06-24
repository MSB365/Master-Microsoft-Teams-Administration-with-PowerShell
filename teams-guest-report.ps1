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
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.SignIns -ErrorAction Stop
    Import-Module Microsoft.Graph.Reports -ErrorAction Stop
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

# Get all guest users with detailed information
function Get-GuestUsers {
    Write-Host "Retrieving guest users..." -ForegroundColor Yellow
    
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Property @(
            'Id', 'DisplayName', 'Mail', 'UserPrincipalName', 'CreatedDateTime',
            'SignInActivity', 'Department', 'JobTitle', 'CompanyName', 'Country',
            'City', 'State', 'AccountEnabled', 'ExternalUserState', 'ExternalUserStateChangeDateTime'
        ) -All -ErrorAction Stop
        
        Write-Host "Found $($guestUsers.Count) guest users" -ForegroundColor Green
        
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
                # Sign-in data might not be available, continue
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
        Write-Error "Failed to retrieve guest users: $($_.Exception.Message)"
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
        
        $userRowsHtml += "<tr class='$riskClass'>"
        $userRowsHtml += "<td>$($user.DisplayName)</td>"
        $userRowsHtml += "<td>$($user.Email)</td>"
        $userRowsHtml += "<td>$($user.Department)</td>"
        $userRowsHtml += "<td>$($user.JobTitle)</td>"
        $userRowsHtml += "<td>$($user.CompanyName)</td>"
        $userRowsHtml += "<td>$($user.Country)</td>"
        $userRowsHtml += "<td>$created</td>"
        $userRowsHtml += "<td>$lastSignIn</td>"
        $userRowsHtml += "<td><span class='risk-badge $riskClass'>$($user.RiskLevel)</span></td>"
        $userRowsHtml += "<td>$($user.ExternalUserState)</td>"
        $userRowsHtml += "<td>$($user.AccountEnabled)</td>"
        $userRowsHtml += "</tr>"
    }

    # Create HTML content
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Guest Users Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { width: 100%; margin-top: 20px; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        .risk-badge {
            display: inline-block;
            padding: 2px 5px;
            border-radius: 5px;
            font-size: 0.8em;
            color: white;
        }
        .risk-badge.risk-high { background-color: red; }
        .risk-badge.risk-medium { background-color: orange; }
        .risk-badge.risk-low { background-color: green; }
        tr.risk-high { background-color: #ffebee; }
        tr.risk-medium { background-color: #fff3e0; }
        tr.risk-low { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <h1>Microsoft Teams Guest Users Report</h1>
    <p>Report generated on: $timestamp</p>
    
    <h2>Statistics</h2>
    <ul>
        <li>Total Guest Users: $totalGuests</li>
        <li>Active Guest Users: $activeGuests</li>
        <li>High Risk Guest Users: $highRiskGuests</li>
        <li>Never Signed In: $neverSignedIn</li>
        <li>Inactive Guests (Last sign-in > 90 days): $inactiveGuests</li>
    </ul>
    
    <h2>Guest Users Details</h2>
    <table>
        <thead>
            <tr>
                <th>Display Name</th>
                <th>Email</th>
                <th>Department</th>
                <th>Job Title</th>
                <th>Company</th>
                <th>Country</th>
                <th>Created Date</th>
                <th>Last Sign-In</th>
                <th>Risk Level</th>
                <th>External User State</th>
                <th>Account Enabled</th>
            </tr>
        </thead>
        <tbody>
            $userRowsHtml
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
        $saveFileDialog.Title = "Save Guest Users Report"
        
        $dialogResult = $saveFileDialog.ShowDialog()
        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $HtmlContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8 -ErrorAction Stop
                Write-Host "Report saved successfully: $($saveFileDialog.FileName)" -ForegroundColor Green
            
                # Ask if user wants to open the report
                $openReport = Read-Host "Open report? (Y/N)"
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
        Write-Host "Starting Microsoft Teams Guest Users Report Generation" -ForegroundColor Cyan
        Write-Host "=" * 60 -ForegroundColor Cyan
        
        # Connect to Microsoft Graph
        Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
        
        # Get guest users
        $guestUsers = Get-GuestUsers
        
        if ($guestUsers.Count -eq 0) {
            Write-Host "No guest users found in the tenant" -ForegroundColor Yellow
            return
        }
        
        # Generate HTML report
        Write-Host "Generating HTML report..." -ForegroundColor Yellow
        $htmlContent = Generate-GuestHTML -GuestUsers $guestUsers
        
        # Save report
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $defaultFileName = "Teams-Guest-Accounts-Report-$timestamp.html"
        $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
        
        if ($savedFile) {
            Write-Host "Guest users report generation completed successfully!" -ForegroundColor Green
            Write-Host "Report contains $($guestUsers.Count) guest users" -ForegroundColor Green
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
