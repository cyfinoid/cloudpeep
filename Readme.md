# PeekInTheCloud - Cloud Key Inspector

A privacy-preserving, browser-based tool designed to help users **inspect and visualize services accessible using cloud API keys**. It requires **no backend** and is implemented entirely using **HTML, JavaScript, and CSS**.

## 🔐 Security & Ethics

**⚠️ IMPORTANT: This tool is intended for educational and internal security testing purposes only.**

- Only use it on credentials and infrastructure that you have permission to test
- All processing happens client-side - no credentials are sent to any server
- No logging or external network calls (except to cloud APIs)
- Clear ethical usage disclaimers are displayed

## ✨ Features

- ✅ **Fully client-side** - works entirely in browser
- ✅ **Multi-cloud support** - AWS, Azure, and GCP
- ✅ **Comprehensive service coverage** - 50+ AWS services, complete Azure/GCP enumeration
- ✅ **Visual service grid** - see accessible services at a glance
- ✅ **Detailed permissions** - understand what actions are allowed
- ✅ **Security analysis engine** - ScoutSuite-inspired security rule evaluation
- ✅ **Resource cross-referencing** - map relationships between resources
- ✅ **Enhanced resource analysis** - detailed security analysis of individual resources
- ✅ **Attack surface analysis** - identify publicly accessible and over-privileged resources
- ✅ **Security posture scoring** - calculate overall security scores and risk levels
- ✅ **Real-time debugging** - comprehensive logging and progress tracking
- ✅ **Export results** - download or copy scan results
- ✅ **Responsive design** - works on desktop and mobile
- ✅ **Offline capability** - with appropriate warnings
- ✅ **Honeytoken detection** - advanced canary token detection with warnings

## 🚀 Quick Start

1. **Open the application**
   - Simply open `index.html` in your web browser
   - No installation or setup required

2. **Select a cloud provider**
   - Choose from AWS, Azure, or GCP

3. **Enter credentials**
   - Fill in the required credential fields for your chosen provider

4. **Scan services**
   - Click "Scan Credentials" to analyze accessible services

5. **Review results**
   - View accessible services in the visual grid
   - Click on services for detailed information
   - Export results as needed

## 📋 Supported Cloud Providers

### Amazon Web Services (AWS)
**Required Credentials:**
- Access Key ID
- Secret Access Key
- Region
- Session Token (optional, for temporary credentials)

**Services Checked:**
- **Compute**: EC2, ECS, EKS, Elastic Beanstalk, EMR, Lambda
- **Storage**: S3, EFS, Storage Gateway
- **Database**: RDS, DynamoDB, Redshift, ElastiCache, Athena
- **Networking**: VPC, Subnets, Security Groups, Route53, API Gateway
- **Security**: IAM, CloudTrail, Secrets Manager, Detective
- **Analytics**: Kinesis, Glue, Step Functions, CloudWatch
- **Media**: CloudFront, MediaConvert, MediaLive, MediaPackage
- **AI/ML**: SageMaker, Lex, IoT
- **Development**: CodePipeline, CodeCommit, Cloud9, SSM
- **Management**: CloudFormation, Organizations, Backup

### Microsoft Azure
**Required Credentials:**
- Client ID
- Client Secret
- Tenant ID

**Services Checked:**
- **Compute**: Virtual Machines, App Services, Container Instances
- **Storage**: Blob Storage, File Storage, Queue Storage, Table Storage
- **Database**: SQL Database, Cosmos DB, Redis Cache
- **Networking**: Virtual Networks, Load Balancers, Application Gateway
- **Security**: Key Vault, Security Center, Active Directory
- **AI/ML**: Cognitive Services, Machine Learning
- **Development**: DevOps, Functions, Logic Apps

### Google Cloud Platform (GCP)
**Required Credentials:**
- Service Account JSON (complete JSON file)

**Services Checked:**
- **Compute**: Compute Engine, App Engine, Cloud Run
- **Storage**: Cloud Storage, Cloud Filestore
- **Database**: Cloud SQL, Firestore, BigQuery
- **Networking**: VPC, Load Balancing, Cloud Armor
- **Security**: IAM, Security Command Center
- **AI/ML**: AI Platform, Vision API, Speech API
- **Development**: Cloud Build, Cloud Source Repositories

## 🔧 Technical Details

### Architecture
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Cloud SDKs**: AWS SDK v3, Azure MSAL, Google Cloud SDK
- **CDN**: unpkg.com for SDK imports
- **Storage**: localStorage for optional profile saving

### File Structure
```
cloudpeep/
├── index.html                    # Main application
├── style.css                    # Styling and responsive design
├── js/
│   ├── app.js                  # Core application logic
│   ├── utils.js                # Utility functions
│   ├── services.js             # Broad service catalog
│   ├── service-metadata.js     # Detailed security metadata
│   ├── security-rules.js       # Security rule engine
│   ├── resource-mapper.js      # Resource cross-referencing
│   ├── enhanced-analyzer.js    # Enhanced resource analysis
│   └── scanners/
│       ├── aws-scanner.js      # AWS service scanner
│       ├── azure-scanner.js    # Azure service scanner
│       └── gcp-scanner.js      # GCP service scanner
├── icons/
│   └── favicon.svg             # Application icon
├── README.md                   # This file
├── TODO.md                     # Development roadmap
└── LICENSE                     # MIT License
```

### Browser Compatibility
- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## 🛡️ Security Considerations

### Client-Side Processing
- All credential processing happens in your browser
- No credentials are transmitted to external servers
- Network requests only go to cloud provider APIs

### Data Privacy
- No logging of credentials or scan results
- Optional localStorage for saving results locally
- Clear data when closing browser

### Network Security
- HTTPS required for cloud API calls
- CORS handling for cross-origin requests
- Network connectivity warnings

## 🚨 Error Handling

The application provides comprehensive error handling:

- **Invalid credentials** - Clear validation messages
- **Network issues** - Connectivity warnings
- **Permission errors** - Detailed access denied messages
- **API failures** - Graceful degradation

## 📊 Understanding Results

### Service Status
- **Accessible** - Service is available and accessible
- **Inaccessible** - Service exists but access is denied
- **Error** - Network or authentication issues

### Permission Levels
- **No Access** - Cannot access the service
- **List Only** - Can list resources but not read details
- **Read Access** - Can read resource details
- **Write Access** - Can modify resources
- **Full Access** - Complete control over resources

### Service Details
Click on any accessible service to see:
- Resource names and details
- API calls that were tested
- Raw API responses
- Permission levels

## 🔒 Advanced Security Analysis Features

### Comprehensive Security Engine
- **Security Scoring** - Overall security score (0-100) with detailed breakdown
- **Risk Assessment** - Technical and business impact risk analysis
- **Threat Detection** - Identify attack vectors and threat paths
- **Security Findings** - Detailed analysis of security issues by severity

### Threat Assessment
- **Attack Surface Analysis** - Identify publicly exposed resources
- **Threat Path Mapping** - Map potential attack paths and escalation routes
- **Vulnerability Detection** - Find security vulnerabilities and misconfigurations
- **Risk Classification** - Critical, High, Medium, Low threat categorization

### Security Recommendations
- **Prioritized Actions** - Critical, High, Medium priority recommendations
- **Remediation Steps** - Specific actions to improve security posture
- **Best Practices** - Industry-standard security recommendations

### Resource Security Analysis
- **Individual Resource Scoring** - Security scores for each resource
- **Configuration Analysis** - Deep dive into resource security settings
- **Permission Analysis** - Over-privileged resource detection
- **Encryption Status** - Data encryption compliance checking

## 🔒 Security Features

### Honeytoken/Canary Token Detection
PeekInTheCloud includes advanced honeytoken detection to protect users from accidentally triggering security alerts:

- **Real-time Detection**: Automatically detects known honeytoken/canary token accounts
- **Warning Modal**: Shows detailed warning before scanning canary tokens
- **Account ID Extraction**: Extracts AWS Account ID from Access Key ID for verification
- **Known Canary Lists**: Includes comprehensive lists of Thinkst Canary and off-brand canary accounts
- **User Choice**: Provides clear options to proceed or cancel (defaults to cancel)
- **Visual Warnings**: Red warning banner in results when canary tokens are scanned

**Supported Canary Services:**
- Thinkst Canary (canarytokens.org)
- Off-brand canary tokens
- Custom canary account detection

**How it works:**
1. When AWS credentials are entered, the system extracts the Account ID
2. Checks against known canary account lists
3. If detected, shows warning modal with details
4. User can choose to proceed or cancel
5. If proceeding, adds warning banner to results

This feature helps security researchers and penetration testers avoid accidentally triggering honeytoken alerts while testing discovered credentials.

## 🔄 Export Options

### Copy to Clipboard
- Copy scan results as formatted JSON
- Includes all service details and permissions

### Download JSON
- Download complete scan results
- Filename includes provider and date
- Useful for offline analysis

## 🐛 Debugging & Logging

### Real-Time Debug Panel
- **Comprehensive Logging** - Track scan progress in real-time
- **Progress Indicators** - See detailed progress for each service
- **Error Context** - Detailed error messages with context
- **Performance Metrics** - Scan duration and timing information

### Debug Features
- **Show/Hide Logs** - Toggle debug panel visibility
- **Clear Logs** - Reset debug information
- **Copy Logs** - Export debug information for troubleshooting
- **Service-Specific Logging** - Track individual service scans
- **Region Tracking** - Monitor multi-region scanning progress

## 🛠️ Troubleshooting

### Common Issues

**"AWS SDK not loaded"**
- Check internet connection
- Ensure CDN links are accessible
- Try refreshing the page

**"Invalid credentials"**
- Verify credential format
- Check for extra spaces
- Ensure all required fields are filled

**"Network error"**
- Check internet connectivity
- Verify firewall settings
- Try a different network

**"Access denied"**
- Verify credentials are correct
- Check IAM permissions
- Ensure credentials haven't expired

### Browser Console
Open browser developer tools (F12) to see:
- Detailed error messages
- API call logs
- Network request details

## 🤝 Contributing

This is an educational project. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Development Setup
1. Clone the repository
2. Open `index.html` in a web browser
3. Use browser developer tools for debugging
4. No build process required

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for:

- Ensuring they have permission to test the credentials
- Complying with applicable laws and regulations
- Following ethical hacking guidelines
- Respecting privacy and data protection requirements

The authors are not responsible for any misuse of this tool.

## 🔗 Related Projects

- [CloudSploit](https://github.com/cloudsploit/scans) - AWS security scanning
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS security assessment
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing

---

**Built with ❤️ for the security community**

