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
- ✅ **Visual service grid** - see accessible services at a glance
- ✅ **Detailed permissions** - understand what actions are allowed
- ✅ **Export results** - download or copy scan results
- ✅ **Responsive design** - works on desktop and mobile
- ✅ **Offline capability** - with appropriate warnings

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
- **S3** - Object storage buckets and objects
- **EC2** - Virtual machines and instances
- **IAM** - Users, roles, and policies
- **STS** - Identity and access information
- **Lambda** - Serverless functions

### Microsoft Azure
**Required Credentials:**
- Client ID
- Client Secret
- Tenant ID

**Services Checked:**
- **Resource Groups** - Logical containers for Azure resources
- **Virtual Machines** - Compute instances
- **Blob Storage** - Object storage containers
- **App Services** - Web applications and APIs

### Google Cloud Platform (GCP)
**Required Credentials:**
- Service Account JSON (complete JSON file)

**Services Checked:**
- **Compute Engine** - Virtual machines
- **Cloud Storage** - Object storage buckets
- **IAM** - Service accounts and roles
- **Cloud Functions** - Serverless functions

## 🔧 Technical Details

### Architecture
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Cloud SDKs**: AWS SDK v3, Azure MSAL, Google Cloud SDK
- **CDN**: unpkg.com for SDK imports
- **Storage**: localStorage for optional profile saving

### File Structure
```
cloudpeep/
├── index.html              # Main application
├── style.css              # Styling and responsive design
├── main.js                # Core application logic
├── utils.js               # Utility functions
├── services.js            # Service metadata
├── cloud/
│   ├── aws.js            # AWS service scanner
│   ├── azure.js          # Azure service scanner
│   └── gcp.js            # GCP service scanner
├── icons/
│   └── favicon.svg       # Application icon
├── README.md             # This file
└── LICENSE               # MIT License
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

## 🔄 Export Options

### Copy to Clipboard
- Copy scan results as formatted JSON
- Includes all service details and permissions

### Download JSON
- Download complete scan results
- Filename includes provider and date
- Useful for offline analysis

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

