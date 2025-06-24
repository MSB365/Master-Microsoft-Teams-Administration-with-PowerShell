<#
.SYNOPSIS
    Microsoft Teams Reporting Suite Setup and Execution Script
.DESCRIPTION
    Master script to install required modules, configure authentication, and run Microsoft Teams reports.
    Supports individual report execution or running all reports at once.
.PARAMETER ReportType
    Type of report to generate: "GuestReport", "ChannelsReport", "ComplianceReport", or "All"
.PARAMETER InstallModules
    Automatically install required Microsoft Graph PowerShell modules
.PARAMETER TenantId
    Azure AD Tenant ID (optional)
.PARAMETER ClientId
    Azure AD Application Client ID (optional)
.PARAMETER UseDeviceCode
    Use device code authentication flow
.EXAMPLE
    .\setup-and-run.ps1 -InstallModules -ReportType All
.EXAMPLE
    .\setup-and-run.ps1 -ReportType GuestReport -UseDeviceCode
.EXAMPLE
    .\setup-and-run.ps1 -ReportType ComplianceReport -TenantId "your-tenant-id"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("GuestReport", "ChannelsReport", "ComplianceReport", "All")]
    [string]$ReportType,
    
    [Parameter(Mandatory=$false)]
    [switch]$InstallModules,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseDeviceCode
)

# Script information
$ScriptVersion = "1.0.0"
$ScriptAuthor = "Microsoft Teams Administration Suite"
$ScriptDate = Get-Date -Format "yyyy-MM-dd"

# Display banner
function Show-Banner {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                    Microsoft Teams Reporting Suite                          " -ForegroundColor Cyan
    Write-Host "                                                                              " -ForegroundColor Cyan
    Write-Host "  Guest User Management | Teams & Channels Audit | Compliance Reports       " -ForegroundColor Cyan
    Write-Host "                                                                              " -ForegroundColor Cyan
    Write-Host "  Version: $ScriptVersion                                    Date: $ScriptDate        " -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
}

# Check PowerShell version
function Test-PowerShellVersion {
    try {
        $psVersion = $PSVersionTable.PSVersion
        Write-Host "Checking PowerShell version..." -ForegroundColor Yellow
        Write-Host "   Current version: $($psVersion.Major).$($psVersion.Minor)" -ForegroundColor Cyan
        
        if ($psVersion.Major -lt 5) {
            Write-Error "PowerShell 5.1 or later is required. Current version: $($psVersion.Major).$($psVersion.Minor)"
            Write-Host "Please upgrade to PowerShell 5.1 or later, or install PowerShell 7+" -ForegroundColor Yellow
            return $false
        } elseif ($psVersion.Major -eq 5 -and $psVersion.Minor -eq 0) {
            Write-Warning "PowerShell 5.0 detected. PowerShell 5.1 or later is recommended for best compatibility."
        }
        
        Write-Host "PowerShell version check passed" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to check PowerShell version: $($_.Exception.Message)"
        return $false
    }
}

# Check execution policy
function Test-ExecutionPolicy {
    try {
        Write-Host "Checking PowerShell execution policy..." -ForegroundColor Yellow
        $executionPolicy = Get-ExecutionPolicy
        Write-Host "   Current policy: $executionPolicy" -ForegroundColor Cyan
        
        $restrictivePolicies = @('Restricted', 'AllSigned')
        if ($executionPolicy -in $restrictivePolicies) {
            Write-Warning "Current execution policy ($executionPolicy) may prevent script execution."
            Write-Host "Consider running: Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
            
            $changePolicy = Read-Host "Would you like to change the execution policy for the current user? (Y/N)"
            if ($changePolicy -eq 'Y' -or $changePolicy -eq 'y') {
                try {
                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                    Write-Host "Execution policy updated successfully" -ForegroundColor Green
                } catch {
                    Write-Warning "Could not update execution policy. You may need to run as administrator."
                }
            }
        } else {
            Write-Host "Execution policy check passed" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to check execution policy: $($_.Exception.Message)"
    }
}

# Install required modules
function Install-RequiredModules {
    try {
        Write-Host "Installing Microsoft Graph PowerShell modules..." -ForegroundColor Yellow
        Write-Host "   This may take several minutes depending on your internet connection." -ForegroundColor Cyan
        
        $requiredModules = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Teams',
            'Microsoft.Graph.Identity.SignIns',
            'Microsoft.Graph.Reports'
        )
        
        $totalModules = $requiredModules.Count
        $currentModule = 0
        
        foreach ($module in $requiredModules) {
            $currentModule++
            Write-Progress -Activity "Installing Microsoft Graph modules" -Status "Installing $module" -PercentComplete (($currentModule / $totalModules) * 100)
            
            try {
                # Check if module is already installed
                $installedModule = Get-Module -ListAvailable -Name $module
                if ($installedModule) {
                    Write-Host "   $module is already installed (Version: $($installedModule[0].Version))" -ForegroundColor Green
                } else {
                    Write-Host "   Installing $module..." -ForegroundColor Yellow
                    Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                    Write-Host "   $module installed successfully" -ForegroundColor Green
                }
            } catch {
                Write-Error "   Failed to install $module`: $($_.Exception.Message)"
                Write-Host "   Try running: Install-Module $module -Force -AllowClobber" -ForegroundColor Yellow
                return $false
            }
        }
        
        Write-Progress -Activity "Installing Microsoft Graph modules" -Completed
        Write-Host "All required modules installed successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to install modules: $($_.Exception.Message)"
        return $false
    }
}

# Test module availability
function Test-RequiredModules {
    try {
        Write-Host "Checking required Microsoft Graph modules..." -ForegroundColor Yellow
        
        $requiredModules = @(
            'Microsoft.Graph.Authentication',
            'Microsoft.Graph.Users',
            'Microsoft.Graph.Teams',
            'Microsoft.Graph.Identity.SignIns',
            'Microsoft.Graph.Reports'
        )
        
        $missingModules = @()
        
        foreach ($module in $requiredModules) {
            $installedModule = Get-Module -ListAvailable -Name $module
            if ($installedModule) {
                Write-Host "   $module (Version: $($installedModule[0].Version))" -ForegroundColor Green
            } else {
                Write-Host "   $module - Not installed" -ForegroundColor Red
                $missingModules += $module
            }
        }
        
        if ($missingModules.Count -gt 0) {
            Write-Host ""
            Write-Host "Missing required modules:" -ForegroundColor Red
            foreach ($module in $missingModules) {
                Write-Host "   - $module" -ForegroundColor Red
            }
            Write-Host ""
            Write-Host "To install missing modules, run:" -ForegroundColor Yellow
            Write-Host "   Install-Module Microsoft.Graph -Force" -ForegroundColor Cyan
            Write-Host "Or run this script with the -InstallModules parameter" -ForegroundColor Cyan
            return $false
        }
        
        Write-Host "All required modules are available" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to check modules: $($_.Exception.Message)"
        return $false
    }
}

# Get script path for report execution
function Get-ScriptPath {
    param([string]$ScriptName)
    
    try {
        # Get the directory where this script is located
        $scriptDir = $PSScriptRoot
        if (-not $scriptDir) {
            $scriptDir = Split-Path -Parent $MyInvocation.PSCommandPath
        }
        if (-not $scriptDir) {
            $scriptDir = Get-Location
        }
        
        Write-Host "Looking for script: $ScriptName" -ForegroundColor Cyan
        Write-Host "Script directory: $scriptDir" -ForegroundColor Cyan
        
        # First try the same directory as this script
        $scriptPath = Join-Path $scriptDir $ScriptName
        Write-Host "Checking: $scriptPath" -ForegroundColor Gray
        
        if (Test-Path $scriptPath) {
            Write-Host "Found script at: $scriptPath" -ForegroundColor Green
            return $scriptPath
        }
        
        # Try looking in scripts subdirectory
        $scriptsDir = Join-Path $scriptDir "scripts"
        $scriptPath = Join-Path $scriptsDir $ScriptName
        Write-Host "Checking: $scriptPath" -ForegroundColor Gray
        
        if (Test-Path $scriptPath) {
            Write-Host "Found script at: $scriptPath" -ForegroundColor Green
            return $scriptPath
        }
        
        # Try looking in parent directory
        $parentDir = Split-Path -Parent $scriptDir
        $scriptPath = Join-Path $parentDir $ScriptName
        Write-Host "Checking: $scriptPath" -ForegroundColor Gray
        
        if (Test-Path $scriptPath) {
            Write-Host "Found script at: $scriptPath" -ForegroundColor Green
            return $scriptPath
        }
        
        Write-Error "Could not find script: $ScriptName"
        Write-Host "Searched in:" -ForegroundColor Yellow
        Write-Host "   - $scriptDir" -ForegroundColor Yellow
        Write-Host "   - $scriptsDir" -ForegroundColor Yellow
        Write-Host "   - $parentDir" -ForegroundColor Yellow
        
        # List files in current directory for debugging
        Write-Host "Files in current directory:" -ForegroundColor Yellow
        Get-ChildItem $scriptDir -Filter "*.ps1" | ForEach-Object {
            Write-Host "   - $($_.Name)" -ForegroundColor Gray
        }
        
        return $null
        
    } catch {
        Write-Error "Failed to locate script: $($_.Exception.Message)"
        return $null
    }
}

# Execute individual report script
function Invoke-ReportScript {
    param(
        [string]$ScriptPath,
        [string]$ReportName,
        [hashtable]$Parameters
    )
    
    try {
        Write-Host ""
        Write-Host "Starting $ReportName..." -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        
        # Build parameter string for script execution
        $paramString = ""
        foreach ($key in $Parameters.Keys) {
            if ($Parameters[$key] -is [switch] -and $Parameters[$key]) {
                $paramString += " -$key"
            } elseif ($Parameters[$key] -and $Parameters[$key] -ne "") {
                $paramString += " -$key '$($Parameters[$key])'"
            }
        }
        
        # Execute the script
        $scriptBlock = [scriptblock]::Create("& '$ScriptPath'$paramString")
        Invoke-Command -ScriptBlock $scriptBlock
        
        Write-Host ""
        Write-Host "$ReportName completed successfully" -ForegroundColor Green
        return $true
        
    } catch {
        Write-Error "Failed to execute $ReportName`: $($_.Exception.Message)"
        return $false
    }
}

# Main execution function
function Main {
    try {
        Show-Banner
        
        # System checks
        Write-Host "Performing system checks..." -ForegroundColor Yellow
        
        if (-not (Test-PowerShellVersion)) {
            exit 1
        }
        
        Test-ExecutionPolicy
        
        # Module installation/verification
        if ($InstallModules) {
            if (-not (Install-RequiredModules)) {
                Write-Error "Failed to install required modules"
                exit 1
            }
        } else {
            if (-not (Test-RequiredModules)) {
                Write-Host ""
                Write-Host "Tip: Run with -InstallModules to automatically install missing modules" -ForegroundColor Cyan
                exit 1
            }
        }
        
        # Prepare parameters for report scripts
        $reportParameters = @{}
        if ($TenantId) { $reportParameters.TenantId = $TenantId }
        if ($ClientId) { $reportParameters.ClientId = $ClientId }
        if ($UseDeviceCode) { $reportParameters.UseDeviceCode = $UseDeviceCode }
        if ($VerbosePreference -eq 'Continue') { $reportParameters.Verbose = $true }
        
        # Execute reports based on selection
        $executionResults = @()
        
        switch ($ReportType) {
            "GuestReport" {
                $scriptPath = Get-ScriptPath "teams-guest-report.ps1"
                if ($scriptPath) {
                    $result = Invoke-ReportScript -ScriptPath $scriptPath -ReportName "Guest Users Report" -Parameters $reportParameters
                    $executionResults += [PSCustomObject]@{ Report = "Guest Users"; Success = $result }
                }
            }
            
            "ChannelsReport" {
                $scriptPath = Get-ScriptPath "teams-channels-report.ps1"
                if ($scriptPath) {
                    $result = Invoke-ReportScript -ScriptPath $scriptPath -ReportName "Teams Channels Report" -Parameters $reportParameters
                    $executionResults += [PSCustomObject]@{ Report = "Teams Channels"; Success = $result }
                }
            }
            
            "ComplianceReport" {
                $scriptPath = Get-ScriptPath "teams-compliance-report.ps1"
                if ($scriptPath) {
                    $result = Invoke-ReportScript -ScriptPath $scriptPath -ReportName "Compliance Report" -Parameters $reportParameters
                    $executionResults += [PSCustomObject]@{ Report = "Compliance"; Success = $result }
                }
            }
            
            "All" {
                Write-Host ""
                Write-Host "Executing all Microsoft Teams reports..." -ForegroundColor Cyan
                Write-Host "   This will generate guest users, channels, and compliance reports." -ForegroundColor Yellow
                Write-Host "   Estimated time: 5-15 minutes depending on tenant size." -ForegroundColor Yellow
                Write-Host ""
                
                $confirmAll = Read-Host "Continue with all reports? (Y/N)"
                if ($confirmAll -ne 'Y' -and $confirmAll -ne 'y') {
                    Write-Host "Operation cancelled by user" -ForegroundColor Yellow
                    exit 0
                }
                
                # Execute all reports
                $reports = @(
                    @{ Script = "teams-guest-report.ps1"; Name = "Guest Users Report" },
                    @{ Script = "teams-channels-report.ps1"; Name = "Teams Channels Report" },
                    @{ Script = "teams-compliance-report.ps1"; Name = "Compliance Report" }
                )
                
                foreach ($report in $reports) {
                    $scriptPath = Get-ScriptPath $report.Script
                    if ($scriptPath) {
                        $result = Invoke-ReportScript -ScriptPath $scriptPath -ReportName $report.Name -Parameters $reportParameters
                        $executionResults += [PSCustomObject]@{ Report = $report.Name; Success = $result }
                        
                        # Add delay between reports to avoid API throttling
                        if ($report -ne $reports[-1]) {
                            Write-Host "Waiting 30 seconds before next report to avoid API throttling..." -ForegroundColor Yellow
                            Start-Sleep -Seconds 30
                        }
                    }
                }
            }
        }
        
        # Display execution summary
        Write-Host ""
        Write-Host "Execution Summary" -ForegroundColor Cyan
        Write-Host "============================================================" -ForegroundColor Cyan
        
        $successCount = 0
        $failureCount = 0
        
        foreach ($result in $executionResults) {
            if ($result.Success) {
                Write-Host "$($result.Report) - Completed successfully" -ForegroundColor Green
                $successCount++
            } else {
                Write-Host "$($result.Report) - Failed" -ForegroundColor Red
                $failureCount++
            }
        }
        
        Write-Host ""
        Write-Host "Results: $successCount successful, $failureCount failed" -ForegroundColor Cyan
        
        if ($failureCount -eq 0) {
            Write-Host "All reports completed successfully!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Next Steps:" -ForegroundColor Cyan
            Write-Host "   • Review the generated HTML reports" -ForegroundColor Yellow
            Write-Host "   • Address any high-priority recommendations" -ForegroundColor Yellow
            Write-Host "   • Schedule regular report generation" -ForegroundColor Yellow
            Write-Host "   • Share compliance reports with stakeholders" -ForegroundColor Yellow
        } else {
            Write-Host "Some reports failed to complete. Check the error messages above." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Troubleshooting Tips:" -ForegroundColor Cyan
            Write-Host "   • Verify you have appropriate admin permissions" -ForegroundColor Yellow
            Write-Host "   • Check your internet connection" -ForegroundColor Yellow
            Write-Host "   • Try using device code authentication (-UseDeviceCode)" -ForegroundColor Yellow
            Write-Host "   • Run individual reports to isolate issues" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "Support:" -ForegroundColor Cyan
        Write-Host "   • Documentation: Check the README.md file" -ForegroundColor Yellow
        Write-Host "   • Issues: Report problems on GitHub" -ForegroundColor Yellow
        Write-Host "   • Community: Join discussions for help and tips" -ForegroundColor Yellow
        
        Write-Host ""
        Write-Host "Thank you for using the Microsoft Teams Reporting Suite!" -ForegroundColor Green
        
    } catch {
        Write-Error "Unexpected error occurred: $($_.Exception.Message)"
        Write-Host "Stack trace:" -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
        exit 1
    }
}

# Execute main function
Main
