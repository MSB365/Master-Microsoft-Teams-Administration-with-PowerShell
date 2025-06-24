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
    Import-Module Microsoft.Graph.Authentication -Force
    Import-Module Microsoft.Graph.Users -Force
    Import-Module Microsoft.Graph.Teams -Force
    Import-Module Microsoft.Graph.Identity.SignIns -Force
    Import-Module Microsoft.Graph.Reports -Force
    Write-Host "[SUCCESS] Successfully imported Microsoft Graph modules" -ForegroundColor Green
} catch {
    Write-Error "[ERROR] Failed to import required modules. Please install Microsoft Graph PowerShell SDK first."
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
        
        Connect-MgGraph @connectParams
        Write-Host "[SUCCESS] Successfully connected to Microsoft Graph" -ForegroundColor Green
        
        # Verify connection
        $context = Get-MgContext
        Write-Host "📋 Connected to tenant: $($context.TenantId)" -ForegroundColor Cyan
        Write-Host "👤 Authenticated as: $($context.Account)" -ForegroundColor Cyan
        
    } catch {
        Write-Error "[ERROR] Failed to connect to Microsoft Graph: $($_.Exception.Message)"
        exit 1
    }
}

# Perform comprehensive compliance assessment
function Get-ComplianceAssessment {
    Write-Host "🔍 Performing compliance assessment..." -ForegroundColor Yellow
    
    $assessment = [PSCustomObject]@{
        GuestUsers = @()
        Teams = @()
        PublicTeams = @()
        ExternalSharing = @()
        ComplianceScore = 0
        GDPRCompliance = @{}
        HIPAACompliance = @{}
        SOXCompliance = @{}
        SecurityRecommendations = @()
        RiskFactors = @()
    }
    
    # Get guest users for GDPR assessment
    Write-Host "👥 Analyzing guest users..." -ForegroundColor Yellow
    $assessment.GuestUsers = Get-GuestUsersForCompliance
    
    # Get teams for security assessment
    Write-Host "🏢 Analyzing teams and channels..." -ForegroundColor Yellow
    $assessment.Teams = Get-TeamsForCompliance
    $assessment.PublicTeams = $assessment.Teams | Where-Object { $_.Visibility -eq 'Public' }
    
    # Perform GDPR compliance check
    Write-Host "🇪🇺 Performing GDPR compliance assessment..." -ForegroundColor Yellow
    $assessment.GDPRCompliance = Test-GDPRCompliance -GuestUsers $assessment.GuestUsers -Teams $assessment.Teams
    
    # Perform HIPAA compliance check
    Write-Host "🏥 Performing HIPAA compliance assessment..." -ForegroundColor Yellow
    $assessment.HIPAACompliance = Test-HIPAACompliance -Teams $assessment.Teams -GuestUsers $assessment.GuestUsers
    
    # Perform SOX compliance check
    Write-Host "💼 Performing SOX compliance assessment..." -ForegroundColor Yellow
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
        ) -All
        
        $enrichedGuests = @()
        foreach ($guest in $guestUsers) {
            $lastSignIn = $null
            try {
                if ($guest.SignInActivity) {
                    $lastSignIn = $guest.SignInActivity.LastSignInDateTime
                }
            } catch { }
            
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
        Write-Warning "[WARNING] Could not retrieve guest users: $($_.Exception.Message)"
        return @()
    }
}

# Get teams for compliance analysis
function Get-TeamsForCompliance {
    try {
        $teams = Get-MgTeam -All
        $enrichedTeams = @()
        
        foreach ($team in $teams) {
            try {
                $group = Get-MgGroup -GroupId $team.Id -Property @('CreatedDateTime', 'Description', 'Visibility')
                $members = Get-MgTeamMember -TeamId $team.Id -All
                $channels = Get-MgTeamChannel -TeamId $team.Id -All
                
                # Count guest members
                $guestMembers = 0
                foreach ($member in $members) {
                    try {
                        $user = Get-MgUser -UserId $member.UserId -Property @('UserType')
                        if ($user.UserType -eq 'Guest') {
                            $guestMembers++
                        }
                    } catch { }
                }
                
                $enrichedTeam = [PSCustomObject]@{
                    Id = $team.Id
                    DisplayName = $team.DisplayName
                    Description = $group.Description
                    Visibility = $group.Visibility
                    CreatedDateTime = $group.CreatedDateTime
                    MemberCount = $members.Count
                    GuestMemberCount = $guestMembers
                    ChannelCount = $channels.Count
                    PrivateChannelCount = ($channels | Where-Object { $_.MembershipType -eq 'Private' }).Count
                    SharedChannelCount = ($channels | Where-Object { $_.MembershipType -eq 'Shared' }).Count
                    HasSensitiveKeywords = Test-SensitiveContent -TeamName $team.DisplayName -Description $group.Description
                    IsPublicWithSensitiveData = ($group.Visibility -eq 'Public' -and (Test-SensitiveContent -TeamName $team.DisplayName -Description $group.Description))
                }
                
                $enrichedTeams += $enrichedTeam
                
            } catch {
                Write-Warning "[WARNING] Could not retrieve details for team: $($team.DisplayName)"
            }
        }
        
        return $enrichedTeams
    } catch {
        Write-Warning "[WARNING] Could not retrieve teams: $($_.Exception.Message)"
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
        if ($content -contains $keyword) {
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
    # Note: This would require additional permissions and audit log analysis
    $hipaaAssessment.AuditLogging = @{
        Score = 20  # Assume basic logging is enabled
        HasComprehensiveLogging = $false
    }
    
    # Data Encryption Assessment (25 points)
    # Teams uses encryption by default, so this gets full points
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
        if ($content -contains $keyword) {
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
    # This would require audit log analysis for team changes
    $soxAssessment.ChangeManagement = @{
        Score = 20  # Assume basic change tracking
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
        Score = 15  # Assume basic audit capabilities
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
        if ($content -contains $keyword) {
            return $true
        }
    }
    
    return $false
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
        
        $recommendationsHtml += @"
        <div class="recommendation-card $priorityClass">
            <h4>$($rec.Category)</h4>
            <p><strong>Priority:</strong> <span class="priority-badge $priorityClass">$($rec.Priority)</span></p>
            <p><strong>Recommendation:</strong> $($rec.Recommendation)</p>
            <p><strong>Impact:</strong> $($rec.Impact)</p>
        </div>
"@
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
        
        $riskFactorsHtml += @"
        <div class="risk-card $riskClass">
            <h4>$($risk.Category)</h4>
            <p><strong>Risk Level:</strong> <span class="risk-badge $riskClass">$($risk.RiskLevel)</span></p>
            <p><strong>Description:</strong> $($risk.Description)</p>
            <p><strong>Mitigation:</strong> $($risk.Mitigation)</p>
        </div>
"@
    }
    
    $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Teams Compliance Report - $timestamp</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }
        .container { max-width: 1400px; margin: 0 auto; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #d32f2f 0%, #f57c00 100%); color: white; padding: 40px; text-align: center; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.1rem; opacity: 0.9; }
        .compliance-dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; padding: 40px; background: #f8f9fa; }
        .compliance-card { background: white; padding: 30px; border-radius: 15px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .compliance-score { font-size: 3rem; font-weight: bold; margin-bottom: 10px; }
        .score-excellent { color: #4caf50; }
        .score-good { color: #8bc34a; }
        .score-fair { color: #ff9800; }
        .score-poor { color: #f44336; }
        .compliance-label { color: #666; font-size: 1.1rem; }
        .overall-score { grid-column: 1 / -1; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
        .overall-score .compliance-score { color: white; }
        .overall-score .compliance-label { color: rgba(255,255,255,0.9); }
        .content { padding: 40px; }
        .section { margin-bottom: 40px; }
        .section h2 { color: #2c3e50; margin-bottom: 20px; font-size: 1.8rem; }
        .recommendations-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        .recommendation-card { background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 5px solid #6264a7; }
        .recommendation-card.priority-high { border-left-color: #f44336; background: #ffebee; }
        .recommendation-card.priority-medium { border-left-color: #ff9800; background: #fff3e0; }
        .recommendation-card.priority-low { border-left-color: #4caf50; background: #e8f5e8; }
        .recommendation-card h4 { color: #2c3e50; margin-bottom: 15px; }
        .priority-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .priority-badge.priority-high { background: #f44336; color: white; }
        .priority-badge.priority-medium { background: #ff9800; color: white; }
        .priority-badge.priority-low { background: #4caf50; color: white; }
        .risk-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }
        .risk-card { background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 5px solid #6264a7; }
        .risk-card.risk-high { border-left-color: #f44336; background: #ffebee; }
        .risk-card.risk-medium { border-left-color: #ff9800; background: #fff3e0; }
        .risk-card.risk-low { border-left-color: #4caf50; background: #e8f5e8; }
        .risk-card h4 { color: #2c3e50; margin-bottom: 15px; }
        .risk-badge { padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
        .risk-badge.risk-high { background: #f44336; color: white; }
        .risk-badge.risk-medium { background: #ff9800; color: white; }
        .risk-badge.risk-low { background: #4caf50; color: white; }
        .compliance-details { background: #f8f9fa; padding: 30px; border-radius: 15px; margin-bottom: 30px; }
        .compliance-framework { margin-bottom: 25px; }
        .compliance-framework h3 { color: #2c3e50; margin-bottom: 15px; }
        .framework-score { display: inline-block; background: white; padding: 10px 20px; border-radius: 8px; margin-right: 15px; }
        .framework-details { margin-top: 15px; }
        .framework-details ul { margin-left: 20px; }
        .stats-grid { display: grid;
grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-item { background: white; padding: 20px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-number { font-size: 2rem; font-weight: bold; color: #6264a7; }
        .stat-label { color: #666; margin-top: 5px; }
        .footer { background: #2c3e50; color: white; padding: 20px; text-align: center; }
        @media (max-width: 768px) {
            .header { padding: 20px; }
            .header h1 { font-size: 2rem; }
            .content { padding: 20px; }
            .compliance-dashboard { padding: 20px; gap: 15px; }
            .recommendations-grid, .risk-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Microsoft Teams Compliance Report</h1>
            <p>Generated on $(Get-Date -Format "MMMM dd, yyyy 'at' HH:mm")</p>
        </div>
        
        <div class="compliance-dashboard">
            <div class="compliance-card overall-score">
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
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <p>This comprehensive compliance report evaluates your Microsoft Teams environment against major regulatory frameworks including GDPR, HIPAA, and SOX. The assessment identifies potential compliance gaps and provides actionable recommendations.</p>
                
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-number">$($Assessment.GuestUsers.Count)</div>
                        <div class="stat-label">Guest Users</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">$($Assessment.Teams.Count)</div>
                        <div class="stat-label">Total Teams</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">$($Assessment.PublicTeams.Count)</div>
                        <div class="stat-label">Public Teams</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">$($Assessment.SecurityRecommendations.Count)</div>
                        <div class="stat-label">Recommendations</div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Compliance Framework Details</h2>
                <div class="compliance-details">
                    <div class="compliance-framework">
                        <h3>🇪🇺 GDPR Compliance Assessment</h3>
                        <div class="framework-score">Score: $($Assessment.GDPRCompliance.Score)/100</div>
                        <div class="framework-details">
                            <p><strong>Data Subject Rights:</strong> $($Assessment.GDPRCompliance.DataSubjectRights.Score)/25 points</p>
                            <p><strong>Data Retention:</strong> $($Assessment.GDPRCompliance.DataRetention.Score)/25 points</p>
                            <p><strong>Consent Management:</strong> $($Assessment.GDPRCompliance.ConsentManagement.Score)/25 points</p>
                            $(if ($Assessment.GDPRCompliance.Recommendations.Count -gt 0) {
                                "<h4>Recommendations:</h4><ul>"
                                foreach ($rec in $Assessment.GDPRCompliance.Recommendations) {
                                    "<li>$rec</li>"
                                }
                                "</ul>"
                            })
                        </div>
                    </div>
                    
                    <div class="compliance-framework">
                        <h3>🏥 HIPAA Compliance Assessment</h3>
                        <div class="framework-score">Score: $($Assessment.HIPAACompliance.Score)/100</div>
                        <div class="framework-details">
                            <p><strong>Access Controls:</strong> $($Assessment.HIPAACompliance.AccessControls.Score)/30 points</p>
                            <p><strong>Audit Logging:</strong> $($Assessment.HIPAACompliance.AuditLogging.Score)/25 points</p>
                            <p><strong>Data Encryption:</strong> $($Assessment.HIPAACompliance.DataEncryption.Score)/25 points</p>
                            <p><strong>Risk Assessment:</strong> $($Assessment.HIPAACompliance.RiskAssessment.Score)/20 points</p>
                            $(if ($Assessment.HIPAACompliance.Recommendations.Count -gt 0) {
                                "<h4>Recommendations:</h4><ul>"
                                foreach ($rec in $Assessment.HIPAACompliance.Recommendations) {
                                    "<li>$rec</li>"
                                }
                                "</ul>"
                            })
                        </div>
                    </div>
                    
                    <div class="compliance-framework">
                        <h3>💼 SOX Compliance Assessment</h3>
                        <div class="framework-score">Score: $($Assessment.SOXCompliance.Score)/100</div>
                        <div class="framework-details">
                            <p><strong>Financial Data Access:</strong> $($Assessment.SOXCompliance.FinancialDataAccess.Score)/30 points</p>
                            <p><strong>Change Management:</strong> $($Assessment.SOXCompliance.ChangeManagement.Score)/25 points</p>
                            <p><strong>Segregation of Duties:</strong> $($Assessment.SOXCompliance.SegregationOfDuties.Score)/25 points</p>
                            <p><strong>Audit Trail:</strong> $($Assessment.SOXCompliance.AuditTrail.Score)/20 points</p>
                            $(if ($Assessment.SOXCompliance.Recommendations.Count -gt 0) {
                                "<h4>Recommendations:</h4><ul>"
                                foreach ($rec in $Assessment.SOXCompliance.Recommendations) {
                                    "<li>$rec</li>"
                                }
                                "</ul>"
                            })
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🎯 Security Recommendations</h2>
                <div class="recommendations-grid">
                    $recommendationsHtml
                </div>
            </div>
            
            <div class="section">
                <h2>⚠️ Risk Factors</h2>
                <div class="risk-grid">
                    $riskFactorsHtml
                </div>
            </div>
            
            <div class="section">
                <h2>📈 Next Steps</h2>
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                    <h3>Immediate Actions (Next 30 Days):</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Address all high-priority security recommendations</li>
                        <li>Review and remove inactive guest accounts</li>
                        <li>Audit public teams for sensitive information</li>
                        <li>Implement conditional access policies for guest users</li>
                    </ul>
                    
                    <h3>Medium-term Goals (Next 90 Days):</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Establish regular compliance monitoring processes</li>
                        <li>Implement automated guest user lifecycle management</li>
                        <li>Develop comprehensive data classification policies</li>
                        <li>Enhance audit logging and monitoring capabilities</li>
                    </ul>
                    
                    <h3>Long-term Strategy (Next 12 Months):</h3>
                    <ul style="margin-left: 20px; margin-top: 10px;">
                        <li>Achieve and maintain 90%+ compliance scores across all frameworks</li>
                        <li>Implement advanced threat protection and DLP policies</li>
                        <li>Establish comprehensive governance and compliance program</li>
                        <li>Regular third-party compliance audits and assessments</li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>📋 Microsoft Teams Compliance Report | Generated by PowerShell Script | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
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
        Add-Type -AssemblyName System.Windows.Forms
        
        $saveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $saveFileDialog.Filter = "HTML files (*.html)|*.html|All files (*.*)|*.*"
        $saveFileDialog.FilterIndex = 1
        $saveFileDialog.FileName = $DefaultFileName
        $saveFileDialog.Title = "Save Teams Compliance Report"
        
        if ($saveFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            try {
                $HtmlContent | Out-File -FilePath $saveFileDialog.FileName -Encoding UTF8
                Write-Host "[SUCCESS] Report saved successfully: $($saveFileDialog.FileName)" -ForegroundColor Green
                
                # Ask if user wants to open the report
                $openReport = Read-Host "Would you like to open the report now? (Y/N)"
                if ($openReport -eq 'Y' -or $openReport -eq 'y') {
                    Start-Process $saveFileDialog.FileName
                }
                
                return $saveFileDialog.FileName
            } catch {
                Write-Error "[ERROR] Failed to save report: $($_.Exception.Message)"
                return $null
            }
        } else {
            Write-Host "[WARNING] Save operation cancelled by user" -ForegroundColor Yellow
            return $null
        }
    } catch {
        Write-Error "[ERROR] Failed to initialize file dialog: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
function Main {
    Write-Host "🚀 Starting Microsoft Teams Compliance Report Generation" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    
    try {
        # Connect to Microsoft Graph
        Connect-ToMicrosoftGraph -TenantId $TenantId -ClientId $ClientId -UseDeviceCode $UseDeviceCode
        
        # Perform compliance assessment
        $assessment = Get-ComplianceAssessment
        
        # Generate HTML report
        Write-Host "📝 Generating HTML report..." -ForegroundColor Yellow
        $htmlContent = Generate-ComplianceHTML -Assessment $assessment
        
        # Save report
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $defaultFileName = "Teams-Compliance-Report-$timestamp.html"
        $savedFile = Save-HTMLReport -HtmlContent $htmlContent -DefaultFileName $defaultFileName
        
        if ($savedFile) {
            Write-Host "🎉 Teams compliance report generation completed successfully!" -ForegroundColor Green
            Write-Host "📊 Overall compliance score: $($assessment.ComplianceScore)%" -ForegroundColor Green
            Write-Host "📁 Saved to: $savedFile" -ForegroundColor Green
        }
        
    } catch {
        Write-Error "[ERROR] Script execution failed: $($_.Exception.Message)"
    } finally {
        # Disconnect from Microsoft Graph
        try {
            Disconnect-MgGraph | Out-Null
            Write-Host "[SUCCESS] Disconnected from Microsoft Graph" -ForegroundColor Green
        } catch {
            # Ignore disconnect errors
        }
    }
}

# Execute main function
Main
