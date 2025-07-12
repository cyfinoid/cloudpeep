# Project: PeekInTheCloud – Client-Side Cloud Key Inspector

## Project Overview

**PeekInTheCloud** is a privacy-preserving, browser-based tool designed to help users **inspect and visualize services accessible using cloud API keys**. It requires **no backend** and is implemented entirely using **HTML, JavaScript, and CSS**. It helps in quick analysis and discovery of exposed or leaked cloud credentials without triggering complex or sensitive operations.

## Key Features

- ✅ Fully client-side (works entirely in browser)
- ✅ Supports AWS, Azure, and GCP
- ✅ Select cloud provider from dropdown
- ✅ Paste cloud credentials
- ✅ Displays accessible services via simple visual UI
- ✅ Clicking on a service shows what data or actions are accessible
- 🔐 Never sends credentials to any backend server

---

## Project Goals

1. **Security research / internal testing**: Useful for red teams, bug bounty hunters, or security researchers who discover cloud credentials and want to understand their scope.
2. **No external dependencies**: Should work offline and remain private.
3. **Modular cloud API integrations**: Separate implementations for each cloud provider.
4. **Extensible UI**: Can add new cloud providers or services in future.

---

## UI Flow

1. **Landing Page**  
   - Title, Info Panel, Disclaimer  
   - Dropdown: Select Cloud Provider (AWS / Azure / GCP)  
   - Credential Input: JSON / Key fields per provider  
   - Button: “Scan Credentials”

2. **Services Overview Page**  
   - Grid of service icons (e.g., S3, EC2 for AWS)  
   - Icons enabled based on access  
   - On hover: short summary of access
   - On click: popup modal with:
     - List of accessible resources
     - Actions allowed (Read/List/Write/Delete)

3. **Export View**  
   - Copy raw API response (JSON) for offline analysis
   - Optional download of results

---

## Supported Cloud Providers (Phase 1)

### AWS
- Inputs: `Access Key`, `Secret Key`, optional `Session Token`
- Services to check:
  - S3 (list buckets, test read access)
  - EC2 (describe instances)
  - IAM (list users/roles)
  - STS (GetCallerIdentity)
  - Lambda (list functions)

### Azure
- Inputs: `Client ID`, `Client Secret`, `Tenant ID`
- Services to check:
  - Resource Groups
  - VMs
  - Blob Storage
  - App Services

### GCP
- Inputs: `Service Account JSON`
- Services to check:
  - Compute Instances
  - GCS Buckets
  - IAM Roles
  - Cloud Functions

---

## Security Considerations

- All logic runs client-side
- No logging or external network calls (except to cloud APIs)
- Clearly display a **disclaimer** for ethical use only
- Warn if keys are uploaded but no network access is possible (offline testing)

---

## File Structure (suggested)

```
/project-root
│
├── index.html # Main UI with input form and service grid
├── style.css # Basic responsive styling
├── main.js # Core logic
│
├── cloud/
│ ├── aws.js # AWS-specific logic
│ ├── azure.js # Azure-specific logic
│ └── gcp.js # GCP-specific logic
│
├── icons/ # SVG or PNG icons for services
├── utils.js # Common helper functions
├── services.js # Metadata about cloud services
└── LICENSE / README.md # MIT license, basic info
```


---

## Tech Requirements

- No Node.js or backend
- Use only native browser APIs and cloud SDKs that support browser mode (e.g., AWS SDK for JavaScript v3)
- Handle all cloud SDK imports via CDN (e.g., `unpkg.com`)

---

## ✅ Completed Advanced Features

### Comprehensive Security Analysis Engine
- [x] **Security Scoring System** - Overall security score (0-100) with detailed breakdown
- [x] **Risk Assessment** - Technical and business impact risk analysis
- [x] **Threat Detection** - Identify attack vectors and threat paths
- [x] **Security Findings** - Detailed analysis of security issues by severity (Critical, High, Medium, Low)

### Compliance Framework Integration
- [x] **HIPAA Compliance** - Health Insurance Portability and Accountability Act checks
- [x] **PCI DSS Compliance** - Payment Card Industry Data Security Standard validation
- [x] **CIS Benchmarks** - Center for Internet Security benchmark compliance
- [x] **Compliance Scoring** - Individual framework scores and detailed recommendations

### Advanced Security Analysis
- [x] **Threat Modeling** - Attack path analysis and escalation route mapping
- [x] **Risk Scoring** - Technical and business impact risk assessment
- [x] **Security Posture Scoring** - Overall security posture assessment (0-100 scale)
- [x] **Automated Recommendations** - Prioritized security recommendations
- [x] **Security Findings Prioritization** - Critical, High, Medium, Low priority classification

### Enhanced Security Display
- [x] **Comprehensive Security Analysis UI** - Modern, responsive security results display
- [x] **Compliance Framework Results** - Detailed compliance analysis display
- [x] **Threat Assessment Visualization** - Attack vectors and threat paths visualization
- [x] **Prioritized Security Recommendations** - Actionable security improvement guidance

### Security Analysis Components
- [x] **Security Analyzer** (`js/security/security-analyzer.js`) - Core security analysis engine
- [x] **Threat Detector** (`js/security/threat-detector.js`) - Attack vector and threat path detection
- [x] **Risk Assessor** (`js/security/risk-assessor.js`) - Risk scoring and business impact analysis
- [x] **Compliance Frameworks** - HIPAA, PCI DSS, and CIS benchmark analyzers

---

## Stretch Goals (Future)

- Save scanned profiles in localStorage
- Dark mode UI
- Enable "Safe Mode" (only performs `list`/`describe` calls)
- Add OCI (Oracle Cloud), DigitalOcean, Aliyun support

---

## Ethics & Usage

This tool is intended for **educational and internal security testing purposes only**. It must not be used on credentials or infrastructure that you do not have permission to test.

---
