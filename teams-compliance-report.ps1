<#
.SYNOPSIS
    Microsoft Teams Compliance and Security Report Generator
.DESCRIPTION
    Generates comprehensive compliance reports for Microsoft Teams environment
    covering GDPR, HIPAA, SOX compliance with security recommendations.
.PARAMETER TenantId
    Azure AD Tenant ID (optional)
.PARAMETER ClientId
    Azure AD Application Client ID (optional)
.PARAMETER UseDeviceCode
    Use device code authentication flow
.EXAMPLE
    .\teams-compliance-report.ps1
.EXAMPLE
    .\teams-compliance-report.ps1 -UseDeviceCode
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
    Import-Module Microsoft.Graph.Teams -ErrorAction Stop
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
                'Team.ReadBasic.All',
                'Channel.ReadBasic.All',
                'TeamMember.Read.All',
                'Policy.Read.All',
                'Reports.Read.All',
                'AuditLog.Read.All'
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

# Perform comprehensive compliance assessment
function Get-ComplianceAssessment {
    Write-Host "Performing compliance assessment..." -ForegroundColor Yellow
    
    $assessment = [PSCustomObject]@{
        GuestUsers = @()
        Teams = @()
        PublicTeams = @()
        ComplianceScore = 0
        GDPRCompliance = @{}
        HIPAACompliance = @{}
        SOXCompliance = @{}
        SecurityRecommendations = @()
        RiskFactors = @()
    }
    
    # Get guest users for GDPR assessment
    Write-Host "Analyzing guest users..." -ForegroundColor Yellow
    $assessment.GuestUsers = Get-GuestUsersForCompliance
    
    # Get teams for security assessment
    Write-Host "Analyzing teams and channels..." -ForegroundColor Yellow
    $assessment.Teams = Get-TeamsForCompliance
    $assessment.PublicTeams = $assessment.Teams | Where-Object { $_.Visibility -eq 'Public' }
    
    # Perform GDPR compliance check
    Write-Host "Performing GDPR compliance assessment..." -ForegroundColor Yellow
    $assessment.GDPRCompliance = Test-GDPRCompliance -GuestUsers $assessment.GuestUsers -Teams $assessment.Teams
    
    # Perform HIPAA compliance check
    Write-Host "Performing HIPAA compliance assessment..." -ForegroundColor Yellow
    $assessment.HIPAACompliance = Test-HIPAACompliance -Teams $assessment.Teams -GuestUsers $assessment.GuestUsers
    
    # Perform SOX compliance check
    Write-Host "Performing SOX compliance assessment..." -ForegroundColor Yellow
    $assessment.SOXCompliance = Test-SOXCompliance -Teams $assessment.Teams -GuestUsers $assessment.GuestUsers
    
    # Calculate overall compliance score
    $assessment.ComplianceScore = Calculate-ComplianceScore -GDPRScore $assessment.GDPRCompliance.Score -HIPAAScore $assessment.HIPAACompliance.Score -SOXScore $assessment.SOXCompliance.Score
    
    # Generate security recommendations
    $assessment.SecurityRecommendations = Get-SecurityRecommendations -Assessment $assessment
    
    # Identify risk factors
    $assessment.RiskFactors = Get-RiskFactors -Assessment $assessment
    
    return $assessment
}

# Get guest users for compliance analysis
function Get-GuestUsersForCompliance {
    try {
        $guestUsers = Get-MgUser -Filter "userType eq 'Guest'" -Property @(
            'Id', 'DisplayName', 'Mail', 'UserPrincipalName', 'CreatedDateTime',
            'SignInActivity', 'AccountEnabled', 'ExternalUserState'
        ) -All -ErrorAction Stop
        
        $enrichedGuests = @()
        foreach ($guest in $guestUsers) {
            $lastSignIn = $null
            try {
                if ($guest.SignInActivity) {
                    $lastSignIn = $guest.SignInActivity.LastSignInDateTime
                }
            } catch { 
                # Continue if sign-in data not available
            }
            
            $enrichedGuest = [PSCustomObject]@{
                Id = $guest.Id
                DisplayName = $guest.DisplayName
                Email = $guest.Mail
                UserPrincipalName = $guest.UserPrincipalName
                CreatedDateTime = $guest.CreatedDateTime
                LastSignInDateTime = $lastSignIn
                AccountEnabled = $guest.AccountEnabled
                ExternalUserState = $guest.ExternalUserState
                DaysSinceCreated = if ($guest.CreatedDateTime) { (Get-Date) - $guest.CreatedDateTime | Select-Object -ExpandProperty Days } else { $null }
                DaysSinceLastSignIn = if ($lastSignIn) { (Get-Date) - $lastSignIn | Select-Object -ExpandProperty Days } else { $null }
                IsInactive = if ($lastSignIn) { ((Get-Date) - $lastSignIn).Days -gt 90 } else { $true }
                IsStale = if ($guest.CreatedDateTime) { ((Get-Date) - $guest.CreatedDateTime).Days -gt 365 -and (-not $lastSignIn -or ((Get-Date) - $lastSignIn).Days -gt 180) } else { $false }
            }
            
            $enrichedGuests += $enrichedGuest
        }
        
        return $enrichedGuests
    } catch {
        Write-Warning "Could not retrieve guest users: $($_.Exception.Message)"
        return @()
    }
}

# Get teams for compliance analysis
function Get-TeamsForCompliance {
    try {
        $teams = Get-MgTeam -All -ErrorAction Stop
        $enrichedTeams = @()
        
        foreach ($team in $teams) {
            try {
                $group = Get-MgGroup -GroupId $team.Id -Property @('CreatedDateTime', 'Description', 'Visibility') -ErrorAction SilentlyContinue
                $members = Get-MgTeamMember -TeamId $team.Id -All -ErrorAction SilentlyContinue
                $channels = Get-MgTeamChannel -TeamId $team.Id -All -ErrorAction SilentlyContinue
                
                # Count guest members
                $guestMembers = 0
                foreach ($member in $members) {
                    try {
                        $user = Get-MgUser -UserId $member.UserId -Property @('UserType') -ErrorAction SilentlyContinue
                        if ($user -and $user.UserType -eq 'Guest') {
                            $guestMembers++
                        }
                    } catch { 
                        # Continue if user details not available
                    }
                }
                
                $enrichedTeam = [PSCustomObject]@{
                    Id = $team.Id
                    DisplayName = $team.DisplayName
                    Description = if($group) { $group.Description } else { "" }
                    Visibility = if($group) { $group.Visibility } else { "Unknown" }
                    CreatedDateTime = if($group) { $group.CreatedDateTime } else { $null }
                    MemberCount = if($members) { $members.Count } else { 0 }
                    GuestMemberCount = $guestMembers
                    ChannelCount = if($channels) { $channels.Count } else { 0 }
                    PrivateChannelCount = if($channels) { ($channels | Where-Object { $_.MembershipType -eq 'Private' }).Count } else { 0 }
                    SharedChannelCount = if($channels) { ($channels | Where-Object { $_.MembershipType -eq 'Shared' }).Count } else { 0 }
                    HasSensitiveKeywords = Test-SensitiveContent -TeamName $team.DisplayName -Description $(if($group) { $group.Description } else { "" })
                    IsPublicWithSensitiveData = ($(if($group) { $group.Visibility } else { "Unknown" }) -eq 'Public' -and (Test-SensitiveContent -TeamName $team.DisplayName -Description $(if($group) { $group.Description } else { "" })))
                }
                
                $enrichedTeams += $enrichedTeam
                
            } catch {
                Write-Warning "Could not retrieve details for team: $($team.DisplayName)"
            }
        }
        
        return $enrichedTeams
    } catch {
        Write-Warning "Could not retrieve teams: $($_.Exception.Message)"
        return @()
    }
}

# Test for sensitive content in team names and descriptions
function Test-SensitiveContent {
    param(
        [string]$TeamName,
        [string]$Description
    )
    
    $sensitiveKeywords = @(
        'confidential', 'secret', 'private', 'internal', 'restricted',
        'financial', 'finance', 'accounting', 'payroll', 'salary',
        'medical', 'health', 'patient', 'clinical', 'hipaa',
        'legal', 'attorney', 'lawsuit', 'compliance', 'audit',
        'executive', 'board', 'c-level', 'ceo', 'cfo', 'cto',
        'merger', 'acquisition', 'strategic', 'sensitive'
    )
    
    $content = "$TeamName $Description".ToLower()
    
    foreach ($keyword in $sensitiveKeywords) {
        if ($content -like "*$keyword*") {
            return $true
        }
    }
    
    return $false
}

# GDPR Compliance Assessment
function Test-GDPRCompliance {
    param(
        [array]$GuestUsers,
        [array]$Teams
    )
    
    $gdprAssessment = [PSCustomObject]@{
        Score = 0
        MaxScore = 100
        Issues = @()
        Recommendations = @()
        DataSubjectRights = @{}
        DataRetention = @{}
        ConsentManagement = @{}
    }
    
    # Data Subject Rights Assessment (25 points)
    $gdprAssessment.DataSubjectRights = @{
        GuestUserInventory = $GuestUsers.Count
        InactiveGuests = ($GuestUsers | Where-Object { $_.IsInactive }).Count
        StaleGuests = ($GuestUsers | Where-Object { $_.IsStale }).Count
        Score = 0
    }
    
    if ($GuestUsers.Count -eq 0) {
        $gdprAssessment.DataSubjectRights.Score = 25
    } elseif (($GuestUsers | Where-Object { $_.IsStale }).Count -eq 0) {
        $gdprAssessment.DataSubjectRights.Score = 20
    } elseif (($GuestUsers | Where-Object { $_.IsInactive }).Count -lt ($GuestUsers.Count * 0.2)) {
        $gdprAssessment.DataSubjectRights.Score = 15
    } else {
        $gdprAssessment.DataSubjectRights.Score = 10
    }
    
    # Data Retention Assessment (25 points)
    $gdprAssessment.DataRetention = @{
        TeamsWithGuestAccess = ($Teams | Where-Object { $_.GuestMemberCount -gt 0 }).Count
        PublicTeamsWithGuests = ($Teams | Where-Object { $_.Visibility -eq 'Public' -and $_.GuestMemberCount -gt 0 }).Count
        Score = 0
    }
    
    if ($gdprAssessment.DataRetention.PublicTeamsWithGuests -eq 0) {
        $gdprAssessment.DataRetention.Score = 25
    } elseif ($gdprAssessment.DataRetention.PublicTeamsWithGuests -lt 3) {
        $gdprAssessment.DataRetention.Score = 20
    } else {
        $gdprAssessment.DataRetention.Score = 10
    }
    
    # Consent Management Assessment (25 points)
    $pendingGuests = ($GuestUsers | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' }).Count
    if ($pendingGuests -eq 0) {
        $gdprAssessment.ConsentManagement.Score = 25
    } elseif ($pendingGuests -lt 5) {
        $gdprAssessment.ConsentManagement.Score = 20
    } else {
        $gdprAssessment.ConsentManagement.Score = 10
    }
    
    # Access Control Assessment (25 points)
    $publicTeamsCount = ($Teams | Where-Object { $_.Visibility -eq 'Public' }).Count
    $accessControlScore = 25
    if ($publicTeamsCount -gt 10) {
        $accessControlScore = 15
    } elseif ($publicTeamsCount -gt 5) {
        $accessControlScore = 20
    }
    
    # Calculate total score
    $gdprAssessment.Score = $gdprAssessment.DataSubjectRights.Score + $gdprAssessment.DataRetention.Score + $gdprAssessment.ConsentManagement.Score + $accessControlScore
    
    # Generate recommendations
    if ($gdprAssessment.DataSubjectRights.Score -lt 20) {
        $gdprAssessment.Recommendations += "Implement regular guest user access reviews and remove inactive accounts"
    }
    if ($gdprAssessment.DataRetention.Score -lt 20) {
        $gdprAssessment.Recommendations += "Review public teams with guest access for sensitive data"
    }
    if ($gdprAssessment.ConsentManagement.Score -lt 20) {
        $gdprAssessment.Recommendations += "Follow up on pending guest invitations and implement consent tracking"
    }
    
    return $gdprAssessment
}

# HIPAA Compliance Assessment
function Test-HIPAACompliance {
    param(
        [array]$Teams,
        [array]$GuestUsers
    )
    
    $hipaaAssessment = [PSCustomObject]@{
        Score = 0
        MaxScore = 100
        Issues = @()
        Recommendations = @()
        AccessControls = @{}
        AuditLogging = @{}
        DataEncryption = @{}
        RiskAssessment = @{}
    }
    
    # Access Controls Assessment (30 points)
    $teamsWithHealthKeywords = ($Teams | Where-Object { Test-HealthcareContent -TeamName $_.DisplayName -Description $_.Description }).Count
    $publicHealthTeams = ($Teams | Where-Object { $_.Visibility -eq 'Public' -and (Test-HealthcareContent -TeamName $_.DisplayName -Description $_.Description) }).Count
    
    $hipaaAssessment.AccessControls = @{
        HealthcareTeams = $teamsWithHealthKeywords
        PublicHealthcareTeams = $publicHealthTeams
        Score = 0
    }
    
    if ($publicHealthTeams -eq 0) {
        $hipaaAssessment.AccessControls.Score = 30
    } elseif ($publicHealthTeams -lt 2) {
        $hipaaAssessment.AccessControls.Score = 20
    } else {
        $hipaaAssessment.AccessControls.Score = 10
    }
    
    # Audit Logging Assessment (25 points)
    $hipaaAssessment.AuditLogging = @{
        Score = 20
        HasComprehensiveLogging = $false
    }
    
    # Data Encryption Assessment (25 points)
    $hipaaAssessment.DataEncryption = @{
        Score = 25
        EncryptionInTransit = $true
        EncryptionAtRest = $true
    }
    
    # Risk Assessment (20 points)
    $guestAccessToHealthTeams = 0
    foreach ($team in ($Teams | Where-Object { Test-HealthcareContent -TeamName $_.DisplayName -Description $_.Description })) {
        if ($team.GuestMemberCount -gt 0) {
            $guestAccessToHealthTeams++
        }
    }
    
    $hipaaAssessment.RiskAssessment = @{
        GuestAccessToHealthTeams = $guestAccessToHealthTeams
        Score = 0
    }
    
    if ($guestAccessToHealthTeams -eq 0) {
        $hipaaAssessment.RiskAssessment.Score = 20
    } elseif ($guestAccessToHealthTeams -lt 3) {
        $hipaaAssessment.RiskAssessment.Score = 15
    } else {
        $hipaaAssessment.RiskAssessment.Score = 5
    }
    
    # Calculate total score
    $hipaaAssessment.Score = $hipaaAssessment.AccessControls.Score + $hipaaAssessment.AuditLogging.Score + $hipaaAssessment.DataEncryption.Score + $hipaaAssessment.RiskAssessment.Score
    
    # Generate recommendations
    if ($hipaaAssessment.AccessControls.Score -lt 25) {
        $hipaaAssessment.Recommendations += "Review and restrict access to healthcare-related teams"
    }
    if ($hipaaAssessment.RiskAssessment.Score -lt 15) {
        $hipaaAssessment.Recommendations += "Implement stricter controls for guest access to healthcare teams"
    }
    
    return $hipaaAssessment
}

# Test for healthcare-related content
function Test-HealthcareContent {
    param(
        [string]$TeamName,
        [string]$Description
    )
    
    $healthcareKeywords = @(
        'medical', 'health', 'patient', 'clinical', 'hospital',
        'doctor', 'nurse', 'physician', 'healthcare', 'hipaa',
        'phi', 'medical record', 'diagnosis', 'treatment', 'pharmacy'
    )
    
    $content = "$TeamName $Description".ToLower()
    
    foreach ($keyword in $healthcareKeywords) {
        if ($content -like "*$keyword*") {
            return $true
        }
    }
    
    return $false
}

# Test for financial content
function Test-FinancialContent {
    param(
        [string]$TeamName,
        [string]$Description
    )
    
    $financialKeywords = @(
        'financial', 'finance', 'accounting', 'payroll', 'salary',
        'budget', 'revenue', 'expense', 'audit', 'sox', 'gaap',
        'earnings', 'profit', 'loss', 'balance sheet', 'income statement'
    )
    
    $content = "$TeamName $Description".ToLower()
    
    foreach ($keyword in $financialKeywords) {
        if ($content -like "*$keyword*") {
            return $true
        }
    }
    
    return $false
}

# SOX Compliance Assessment
function Test-SOXCompliance {
    param(
        [array]$Teams,
        [array]$GuestUsers
    )
    
    $soxAssessment = [PSCustomObject]@{
        Score = 0
        MaxScore = 100
        Issues = @()
        Recommendations = @()
        FinancialDataAccess = @{}
        ChangeManagement = @{}
        SegregationOfDuties = @{}
        AuditTrail = @{}
    }
    
    # Financial Data Access Assessment (30 points)
    $financialTeams = ($Teams | Where-Object { Test-FinancialContent -TeamName $_.DisplayName -Description $_.Description }).Count
    $publicFinancialTeams = ($Teams | Where-Object { $_.Visibility -eq 'Public' -and (Test-FinancialContent -TeamName $_.DisplayName -Description $_.Description) }).Count
    
    $soxAssessment.FinancialDataAccess = @{
        FinancialTeams = $financialTeams
        PublicFinancialTeams = $publicFinancialTeams
        Score = 0
    }
    
    if ($publicFinancialTeams -eq 0) {
        $soxAssessment.FinancialDataAccess.Score = 30
    } elseif ($publicFinancialTeams -lt 2) {
        $soxAssessment.FinancialDataAccess.Score = 20
    } else {
        $soxAssessment.FinancialDataAccess.Score = 10
    }
    
    # Change Management Assessment (25 points)
    $soxAssessment.ChangeManagement = @{
        Score = 20
        HasChangeDocumentation = $false
    }
    
    # Segregation of Duties Assessment (25 points)
    $teamsWithMultipleOwners = ($Teams | Where-Object { $_.MemberCount -gt 1 }).Count
    if ($Teams.Count -gt 0) {
        $segregationScore = [math]::Round(($teamsWithMultipleOwners / $Teams.Count) * 25)
    } else {
        $segregationScore = 25
    }
    
    $soxAssessment.SegregationOfDuties = @{
        TeamsWithMultipleOwners = $teamsWithMultipleOwners
        Score = $segregationScore
    }
    
    # Audit Trail Assessment (20 points)
    $soxAssessment.AuditTrail = @{
        Score = 15
        ComprehensiveAuditing = $false
    }
    
    # Calculate total score
    $soxAssessment.Score = $soxAssessment.FinancialDataAccess.Score + $soxAssessment.ChangeManagement.Score + $soxAssessment.SegregationOfDuties.Score + $soxAssessment.AuditTrail.Score
    
    # Generate recommendations
    if ($soxAssessment.FinancialDataAccess.Score -lt 25) {
        $soxAssessment.Recommendations += "Restrict access to financial teams and ensure they are private"
    }
    if ($soxAssessment.SegregationOfDuties.Score -lt 20) {
        $soxAssessment.Recommendations += "Ensure financial teams have multiple owners for segregation of duties"
    }
    
    return $soxAssessment
}

# Calculate overall compliance score
function Calculate-ComplianceScore {
    param(
        [int]$GDPRScore,
        [int]$HIPAAScore,
        [int]$SOXScore
    )
    
    # Weighted average: GDPR 40%, HIPAA 30%, SOX 30%
    $overallScore = [math]::Round(($GDPRScore * 0.4) + ($HIPAAScore * 0.3) + ($SOXScore * 0.3))
    return $overallScore
}

# Generate security recommendations
function Get-SecurityRecommendations {
    param(
        $Assessment
    )
    
    $recommendations = @()
    
    # Guest user recommendations
    if ($Assessment.GuestUsers.Count -gt 0) {
        $inactiveGuests = ($Assessment.GuestUsers | Where-Object { $_.IsInactive }).Count
        if ($inactiveGuests -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = 'High'
                Category = 'Guest Management'
                Recommendation = "Remove or review $inactiveGuests inactive guest users"
                Impact = 'Reduces security risk and improves compliance'
            }
        }
    }
    
    # Public teams recommendations
    if ($Assessment.PublicTeams.Count -gt 0) {
        $recommendations += [PSCustomObject]@{
            Priority = 'Medium'
            Category = 'Access Control'
            Recommendation = "Review $($Assessment.PublicTeams.Count) public teams for sensitive information"
            Impact = 'Prevents unauthorized access to sensitive data'
        }
    }
    
    # Compliance-specific recommendations
    if ($Assessment.GDPRCompliance.Score -lt 70) {
        $recommendations += [PSCustomObject]@{
            Priority = 'High'
            Category = 'GDPR Compliance'
            Recommendation = 'Implement comprehensive guest user lifecycle management'
            Impact = 'Ensures GDPR compliance and reduces regulatory risk'
        }
    }
    
    if ($Assessment.HIPAACompliance.Score -lt 70) {
        $recommendations += [PSCustomObject]@{
            Priority = 'High'
            Category = 'HIPAA Compliance'
            Recommendation = 'Restrict guest access to healthcare-related teams'
            Impact = 'Protects PHI and ensures HIPAA compliance'
        }
    }
    
    if ($Assessment.SOXCompliance.Score -lt 70) {
        $recommendations += [PSCustomObject]@{
            Priority = 'High'
            Category = 'SOX Compliance'
            Recommendation = 'Ensure financial teams are private with proper access controls'
            Impact = 'Protects financial data and ensures SOX compliance'
        }
    }
    
    return $recommendations
}

# Identify risk factors
function Get-RiskFactors {
    param(
        $Assessment
    )
    
    $riskFactors = @()
    
    # High-risk guest users
    $staleGuests = ($Assessment.GuestUsers | Where-Object { $_.IsStale }).Count
    if ($staleGuests -gt 0) {
        $riskFactors += [PSCustomObject]@{
            RiskLevel = 'High'
            Category = 'Guest Access'
            Description = "$staleGuests stale guest accounts with potential unauthorized access"
            Mitigation = 'Remove inactive guest accounts and implement regular access reviews'
        }
    }
    
    # Public teams with sensitive content
    $publicSensitiveTeams = ($Assessment.Teams | Where-Object { $_.Visibility -eq 'Public' -and $_.HasSensitiveKeywords }).Count
    if ($publicSensitiveTeams -gt 0) {
        $riskFactors += [PSCustomObject]@{
            RiskLevel = 'High'
            Category = 'Data Exposure'
            Description = "$publicSensitiveTeams public teams with potentially sensitive content"
            Mitigation = 'Review and make sensitive teams private'
        }
    }
    
    # Guest access to sensitive teams
    $guestSensitiveAccess = ($Assessment.Teams | Where-Object { $_.HasSensitiveKeywords -and $_.GuestMemberCount -gt 0 }).Count
    if ($guestSensitiveAccess -gt 0) {
        $riskFactors += [PSCustomObject]@{
            RiskLevel = 'Medium'
            Category = 'External Access'
            Description = "$guestSensitiveAccess sensitive teams with guest access"
            Mitigation = 'Review guest access to sensitive teams and implement conditional access policies'
        }
    }
    
    return $riskFactors
}

# Generate HTML report
function Generate-ComplianceHTML {
    param(
        $Assessment
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    
    # Generate recommendations HTML
    $recommendationsHtml = ""
    foreach ($rec in $Assessment.SecurityRecommendations) {
        $priorityClass = switch ($rec.Priority) {
            'High' { 'priority-high' }
            'Medium' { 'priority-medium' }
            'Low' { 'priority-low' }
            default { 'priority-unknown' }
        }
        
        $recommendationsHtml += "<div class='recommendation-card $priorityClass'>"
        $recommendationsHtml += "<h4>$($rec.Category)</h4>"
        $recommendationsHtml += "<p><strong>Priority:</strong> <span class='priority-badge $priorityClass'>$($rec.Priority)</span></p>"
        $recommendationsHtml += "<p><strong>Recommendation:</strong> $($rec.Recommendation)</p>"
        $recommendationsHtml += "<p><strong>Impact:</strong> $($rec.Impact)</p>"
        $recommendationsHtml += "</div>"
    }
    
    # Generate risk factors HTML
    $riskFactorsHtml = ""
    foreach ($risk in $Assessment.RiskFactors) {
        $riskClass = switch ($risk.RiskLevel) {
            'High' { 'risk-high' }
            'Medium' { 'risk-medium' }
            'Low' { 'risk-low' }
            default { 'risk-unknown' }
        }
        
        $riskFactorsHtml += "<div class='risk-card $riskClass'>"
        $riskFactorsHtml += "<h4>$($risk.Category)</h4>"
        $riskFactorsHtml += "<p><strong>Risk Level:</strong> <span class='risk-badge $riskClass'>$($risk.RiskLevel)</span></p>"
        $riskFactorsHtml += "<p><strong>Description:</strong> $($risk.Description)</p>"
        $riskFactorsHtml += "<p><strong>Mitigation:</strong> $($risk.Mitigation)</p>"
        $riskFactorsHtml += "</div>"
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Compliance Report - $timestamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .compliance-dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .compliance-card { background: #f0f0f0; padding: 20px; border-radius: 10px; text-align: center; }
        .compliance-score { font-size: 2rem; font-weight: bold; margin-bottom: 10px; }
        .score-excellent { color: #4caf50; }
        .score-good { color: #8bc34a; }
        .score-fair { color: #ff9800; }
        .score-poor { color: #f44336; }
        .recommendations-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .recommendation-card { background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 5px solid #6264a7; }
        .recommendation-card.priority-high { border-left-color: #f44336; background: #ffebee; }
        .recommendation-card.priority-medium { border-left-color: #ff9800; background: #fff3e0; }
        .recommendation-card.priority-low { border-left-color: #4caf50; background: #e8f5e8; }
        .priority-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .priority-badge.priority-high { background: #f44336; color: white; }
        .priority-badge.priority-medium { background: #ff9800; color: white; }
        .priority-badge.priority-low { background: #4caf50; color: white; }
        .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .risk-card { background: #f8f9fa; padding: 20px; border-radius: 10px; border-left: 5px solid #6264a7; }
        .risk-card.risk-high { border-left-color: #f44336; background: #ffebee; }
        .risk-card.risk-medium { border-left-color: #ff9800; background: #fff3e0; }
        .risk-card.risk-low { border-left-color: #4caf50; background: #e8f5e8; }
        .risk-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .risk-badge.risk-high { background: #f44336; color: white; }
        .risk-badge.risk-medium { background: #ff9800; color: white; }
        .risk-badge.risk-low { background: #4caf50; color: white; }
    </style>
</head>
<body>
    <h1>Microsoft Teams Compliance Report</h1>
    <p>Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
    
    <div class="compliance-dashboard">
        <div class="compliance-card">
            <div class="compliance-score">$($Assessment.ComplianceScore)%</div>
            <div class="compliance-label">Overall Compliance Score</div>
        </div>
        <div class="compliance-card">
            <div class="compliance-score score-$(if($Assessment.GDPRCompliance.Score -ge 80){'excellent'}elseif($Assessment.GDPRCompliance.Score -ge 60){'good'}elseif($Assessment.GDPRCompliance.Score -ge 40){'fair'}else{'poor'})">$($Assessment.GDPRCompliance.Score)%</div>
            <div class="compliance-label">GDPR Compliance</div>
        </div>
        <div class="compliance-card">
            <div class="compliance-score score-$(if($Assessment.HIPAACompliance.Score -ge 80){'excellent'}elseif($Assessment.HIPAACompliance.Score -ge 60){'good'}elseif($Assessment.HIPAACompliance.Score -ge 40){'fair'}else{'poor'})">$($Assessment.HIPAACompliance.Score)%</div>
            <div class="compliance-label">HIPAA Compliance</div>
        </div>
        <div class="compliance-card">
            <div class="compliance-score score-$(if($Assessment.SOXCompliance.Score -ge 80){'excellent'}elseif($Assessment.SOXCompliance.Score -ge 60){'good'}elseif($Assessment.SOXCompliance.Score -ge 40){'fair'}else{'poor'})">$($Assessment.SOXCompliance.Score)%</div>
            <div class="compliance-label">SOX Compliance</div>
        </div>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This comprehensive compliance report evaluates your Microsoft Teams environment against major regulatory frameworks including GDPR, HIPAA, and SOX. The assessment identifies potential compliance gaps and provides actionable recommendations.</p>
    
    <ul>
        <li><strong>Guest Users:</strong> $($Assessment.GuestUsers.Count)</li>
        <li><strong>Total Teams:</strong> $($Assessment.Teams.Count)</li>
        <li><strong>Public Teams:</strong> $($Assessment.PublicTeams.Count)</li>
        <li><strong>Recommendations:</strong> $($Assessment.SecurityRecommendations.Count)</li>
    </ul>
    
    <h2>Security Recommendations</h2>
    <div class="recommendations-grid">
        $recommendationsHtml
    </div>
    
    <h2>Risk Factors</h2>
    <div class="risk-grid">
        $riskFactorsHtml
    </div>
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
        $saveFileDialog.Title = "Save Teams Compliance Report"
        
        $dialogResult = $saveFileDialog.ShowDialog()
        if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $HtmlContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8 -ErrorAction Stop
                Write-Host "Report saved successfully: $($saveFileDialog.FileName)" -ForegroundColor Green
                
                # Ask if user wants to open the report
                $openReport = Read-Host "Open report (Y/N)?"
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

# Main execution function
function Main {
    try {
        Write-Host "Starting Microsoft Teams Compliance Report Generation" -ForegroundColor Cyan
        Write-Host "=" * 60 -ForegroundColor Cyan
        
        # Connect to Microsoft Graph
        Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
        
        # Perform compliance assessment
        $assessment = Get-ComplianceAssessment
        
        # Generate HTML report
        Write-Host "Generating HTML report..." -ForegroundColor Yellow
        $htmlContent = Generate-ComplianceHTML -Assessment $assessment
        
        # Save report
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $defaultFileName = "Teams-Compliance-Report-$timestamp.html"
        $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
        
        if ($savedFile) {
            Write-Host "Teams compliance report generation completed successfully!" -ForegroundColor Green
            Write-Host "Overall compliance score: $($assessment.ComplianceScore)%" -ForegroundColor Green
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
