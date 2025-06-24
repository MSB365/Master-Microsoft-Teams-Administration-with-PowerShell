# Microsoft Teams PowerShell Reporting Suite 🚀

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-Latest-green.svg)](https://docs.microsoft.com/en-us/graph/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/teams-reporting-suite/graphs/commit-activity)

> **Comprehensive PowerShell scripts for Microsoft Teams administration, compliance reporting, and security auditing.**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Script Documentation](#script-documentation)
- [Authentication](#authentication)
- [Permissions Required](#permissions-required)
- [Output Examples](#output-examples)
- [Compliance Features](#compliance-features)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

This PowerShell suite provides comprehensive reporting capabilities for Microsoft Teams environments, focusing on:

- **Guest Account Management** - Complete inventory and risk assessment
- **Teams & Channels Audit** - Privacy settings, membership, and access control
- **Compliance Reporting** - GDPR, HIPAA, SOX compliance automation
- **Security Analysis** - Risk identification and remediation recommendations

## ✨ Features

### 🔍 **Guest Accounts Report**
- Complete guest user inventory with detailed metadata
- Last sign-in tracking and inactive account identification
- Department, job title, and organizational information
- Risk assessment based on access patterns
- Interactive HTML report with search and filtering

### 📊 **Teams & Channels Report**
- Comprehensive teams and channels inventory
- Privacy classification (Public/Private/Shared)
- Complete membership listings for all teams and private channels
- Channel creation dates and descriptions
- Owner and member role identification

### 🛡️ **Compliance & Security Report**
- Automated GDPR, HIPAA, and SOX compliance assessment
- Guest user risk analysis and recommendations
- Data retention and access control review
- Regulatory checklist with actionable items
- Executive summary with key metrics

### 🎨 **Professional HTML Reports**
- Modern, responsive design with professional styling
- Interactive tables with sorting and filtering
- Summary dashboards with key performance indicators
- Risk color-coding and visual indicators
- Print-friendly and mobile-responsive layouts

## 📋 Prerequisites

- **PowerShell 5.1** or later (PowerShell 7+ recommended)
- **Microsoft Graph PowerShell SDK**
- **Azure AD/Microsoft 365 Admin Rights**
- **Internet connectivity** for Microsoft Graph API access

## 🚀 Installation

### Option 1: Automated Installation (Recommended)

\`\`\`powershell
# Clone the repository
git clone https://github.com/yourusername/teams-reporting-suite.git
cd teams-reporting-suite

# Run the setup script with module installation
.\\setup-and-run.ps1 -InstallModules -ReportType All
\`\`\`

### Option 2: Manual Installation

\`\`\`powershell
# Install Microsoft Graph modules
Install-Module Microsoft.Graph -Force -AllowClobber
Install-Module Microsoft.Graph.Authentication -Force
Install-Module Microsoft.Graph.Users -Force
Install-Module Microsoft.Graph.Teams -Force
Install-Module Microsoft.Graph.Identity.SignIns -Force
Install-Module Microsoft.Graph.Reports -Force


## ⚡ Quick Start

### Run All Reports
\`\`\`powershell
.\\setup-and-run.ps1 -ReportType All
\`\`\`

### Run Individual Reports
\`\`\`powershell
# Guest accounts report
.\\teams-guest-report.ps1

# Teams and channels report
.\\teams-channels-report.ps1

# Compliance and security report
.\\teams-compliance-report.ps1
\`\`\`

### Use Device Code Authentication
\`\`\`powershell
.\\setup-and-run.ps1 -ReportType All -UseDeviceCode
\`\`\`

## 📖 Script Documentation

### `teams-guest-report.ps1`

Generates comprehensive guest account reports with detailed user information and risk assessment.

**Key Functions:**
- \`Get-GuestUsers\` - Retrieves all guest users with detailed properties
- \`Analyze-GuestRisks\` - Performs risk assessment based on activity patterns
- \`Generate-GuestHTML\` - Creates interactive HTML report

**Parameters:**
- \`-TenantId\` - Azure AD tenant identifier
- \`-ClientId\` - Azure AD application client ID
- \`-UseDeviceCode\` - Use device code authentication flow
- \`-Verbose\` - Enable detailed logging

### `teams-channels-report.ps1`

Provides complete inventory of Teams, channels, and membership information.

**Key Functions:**
- \`Get-AllTeams\` - Retrieves all Teams with metadata
- \`Get-TeamChannels\` - Gets channels for each team with privacy settings
- \`Get-TeamMembers\` - Collects membership information
- \`Generate-TeamsHTML\` - Creates comprehensive HTML report

### `teams-compliance-report.ps1`

Automated compliance assessment for regulatory requirements.

**Key Functions:**
- \`Test-GDPRCompliance\` - GDPR compliance assessment
- \`Test-HIPAACompliance\` - HIPAA compliance evaluation
- \`Test-SOXCompliance\` - SOX compliance verification
- \`Generate-ComplianceHTML\` - Creates compliance dashboard

### `setup-and-run.ps1`

Master script for installation, configuration, and execution.

**Parameters:**
- \`-ReportType\` - Choose: "GuestReport", "ChannelsReport", "ComplianceReport", or "All"
- \`-InstallModules\` - Automatically install required PowerShell modules
- \`-UseDeviceCode\` - Use device code authentication
- \`-TenantId\` - Specify Azure AD tenant ID
- \`-ClientId\` - Specify Azure AD application client ID

## 🔐 Authentication

### Interactive Authentication (Default)
The scripts use Microsoft Graph's interactive authentication, opening a browser window for sign-in.

### Device Code Authentication
For server environments or when browser authentication isn't available:
\`\`\`powershell
.\\teams-guest-report.ps1 -UseDeviceCode
\`\`\`

### Application Authentication
For automated scenarios, register an Azure AD application:
\`\`\`powershell
.\\teams-guest-report.ps1 -TenantId "your-tenant-id" -ClientId "your-app-id"
\`\`\`

## 🔑 Permissions Required

The scripts require the following Microsoft Graph API permissions:

| Permission | Scope | Purpose |
|------------|-------|---------|
| \`User.Read.All\` | Application/Delegated | Read user profiles and guest accounts |
| \`Directory.Read.All\` | Application/Delegated | Read directory data and organizational info |
| \`Team.ReadBasic.All\` | Application/Delegated | Read Teams information |
| \`Channel.ReadBasic.All\` | Application/Delegated | Read channel information |
| \`TeamMember.Read.All\` | Application/Delegated | Read team memberships |
| \`Policy.Read.All\` | Application/Delegated | Read compliance policies |
| \`Reports.Read.All\` | Application/Delegated | Read usage reports |
| \`AuditLog.Read.All\` | Application/Delegated | Read audit logs for compliance |

## 📊 Output Examples

### Guest Accounts Report
\`\`\`
📁 Teams-Guest-Accounts-Report-20241224-143000.html
├── Executive Summary
├── Guest User Inventory (142 users)
├── Risk Assessment Dashboard
├── Inactive Accounts Analysis
└── Compliance Recommendations
\`\`\`

### Teams & Channels Report
\`\`\`
📁 Teams-Channels-Report-20241224-143000.html
├── Teams Overview (89 teams)
├─�� Channel Inventory (456 channels)
├── Privacy Settings Analysis
├── Membership Summary
└── Access Control Review
\`\`\`

### Compliance Report
\`\`\`
📁 Teams-Compliance-Report-20241224-143000.html
├── Compliance Dashboard
├── GDPR Assessment
├── HIPAA Evaluation
├── SOX Compliance Check
└── Remediation Action Plan
\`\`\`

## 🛡️ Compliance Features

### GDPR Compliance
- **Data Subject Rights**: Guest user data inventory for right to be forgotten
- **Data Retention**: Analysis of inactive accounts and data retention policies
- **Consent Management**: Review of guest user consent and access permissions
- **Data Processing**: Documentation of data processing activities

### HIPAA Compliance
- **Access Controls**: Review of user access to sensitive channels
- **Audit Logging**: Assessment of audit log configuration
- **Data Encryption**: Verification of data protection measures
- **Risk Assessment**: Identification of potential HIPAA violations

### SOX Compliance
- **Financial Data Access**: Review of access to financial information
- **Change Management**: Documentation of administrative changes
- **Segregation of Duties**: Analysis of administrative role assignments
- **Audit Trail**: Comprehensive logging and monitoring assessment

## 🔧 Troubleshooting

### Common Issues

#### Module Installation Errors
\`\`\`powershell
# Install for current user if admin rights unavailable
Install-Module Microsoft.Graph -Scope CurrentUser -Force

# Clear module cache if experiencing conflicts
Get-Module Microsoft.Graph* -ListAvailable | Uninstall-Module -Force
Install-Module Microsoft.Graph -Force
\`\`\`

#### Authentication Failures
\`\`\`powershell
# Clear cached credentials
Disconnect-MgGraph
Clear-MgContext

# Use device code authentication
.\\teams-guest-report.ps1 -UseDeviceCode

# Verify tenant and client IDs
.\\teams-guest-report.ps1 -TenantId "your-tenant-id" -Verbose
\`\`\`

#### Permission Errors
1. Verify you have appropriate admin rights in your Microsoft 365 tenant
2. Check that all required Graph API permissions are granted
3. Ensure consent has been provided for the application permissions
4. Try running with Global Administrator privileges

#### Performance Issues
- **Large Tenants**: Scripts include progress indicators and may take several minutes
- **Rate Limiting**: Built-in retry logic handles Graph API throttling
- **Memory Usage**: Consider running during off-peak hours for very large tenants

### Debug Mode
Enable verbose logging for troubleshooting:
\`\`\`powershell
.\\teams-guest-report.ps1 -Verbose
\`\`\`


### Development Setup
\`\`\`powershell

---

