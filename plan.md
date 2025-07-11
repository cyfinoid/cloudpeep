# PeekInTheCloud Development Plan

## Project Overview
PeekInTheCloud is a client-side cloud key inspector that allows users to analyze cloud credentials and visualize accessible services without any backend dependencies.

## Development Phases

### Phase 1: Project Setup & Core Infrastructure
**Goal**: Establish the basic project structure and core functionality

#### Tasks:
1. **Project Structure Setup**
   - [ ] Create directory structure as specified in project.md
   - [ ] Set up basic HTML template with responsive design
   - [ ] Create CSS framework for modern, clean UI
   - [ ] Set up JavaScript module structure

2. **Core UI Components**
   - [ ] Create landing page with title, info panel, and disclaimer
   - [ ] Implement cloud provider dropdown (AWS/Azure/GCP)
   - [ ] Build credential input forms for each provider
   - [ ] Add "Scan Credentials" button with loading states
   - [ ] Create services overview grid layout
   - [ ] Implement modal system for detailed service information

3. **Utility Functions**
   - [ ] Create utils.js with common helper functions
   - [ ] Implement credential validation for each provider
   - [ ] Add error handling and user feedback
   - [ ] Create service metadata structure in services.js

### Phase 2: Cloud Provider Integrations
**Goal**: Implement cloud SDK integrations for each provider

#### Tasks:
1. **AWS Integration (aws.js)**
   - [ ] Set up AWS SDK v3 via CDN
   - [ ] Implement credential configuration
   - [ ] Create service check functions:
     - [ ] S3 (list buckets, test read access)
     - [ ] EC2 (describe instances)
     - [ ] IAM (list users/roles)
     - [ ] STS (GetCallerIdentity)
     - [ ] Lambda (list functions)
   - [ ] Add error handling for permission issues

2. **Azure Integration (azure.js)**
   - [ ] Set up Azure SDK via CDN
   - [ ] Implement authentication flow
   - [ ] Create service check functions:
     - [ ] Resource Groups
     - [ ] VMs
     - [ ] Blob Storage
     - [ ] App Services
   - [ ] Add error handling for permission issues

3. **GCP Integration (gcp.js)**
   - [ ] Set up Google Cloud SDK via CDN
   - [ ] Implement service account authentication
   - [ ] Create service check functions:
     - [ ] Compute Instances
     - [ ] GCS Buckets
     - [ ] IAM Roles
     - [ ] Cloud Functions
   - [ ] Add error handling for permission issues

### Phase 3: UI/UX Implementation
**Goal**: Create a polished, user-friendly interface

#### Tasks:
1. **Service Icons & Visual Design**
   - [ ] Create/acquire SVG icons for each cloud service
   - [ ] Implement responsive grid layout for services
   - [ ] Add hover effects and visual feedback
   - [ ] Create disabled/enabled states for services

2. **Service Details Modal**
   - [ ] Design modal layout for service details
   - [ ] Implement resource listing with permissions
   - [ ] Add action permissions display (Read/List/Write/Delete)
   - [ ] Create copy-to-clipboard functionality

3. **Export Functionality**
   - [ ] Implement JSON export of scan results
   - [ ] Add download functionality for results
   - [ ] Create formatted display of raw API responses

### Phase 4: Security & Error Handling
**Goal**: Ensure the application is secure and robust

#### Tasks:
1. **Security Implementation**
   - [ ] Add comprehensive disclaimer for ethical use
   - [ ] Implement offline detection and warnings
   - [ ] Ensure no credential logging or external calls
   - [ ] Add network connectivity checks

2. **Error Handling**
   - [ ] Implement graceful error handling for API failures
   - [ ] Add user-friendly error messages
   - [ ] Handle network timeouts and connectivity issues
   - [ ] Add retry mechanisms for failed requests

3. **Input Validation**
   - [ ] Validate credential formats for each provider
   - [ ] Add real-time validation feedback
   - [ ] Implement secure credential handling

### Phase 5: Testing & Polish
**Goal**: Ensure the application works reliably and looks professional

#### Tasks:
1. **Testing**
   - [ ] Test with valid credentials for each provider
   - [ ] Test with invalid/expired credentials
   - [ ] Test offline functionality
   - [ ] Cross-browser compatibility testing

2. **UI Polish**
   - [ ] Refine responsive design for mobile devices
   - [ ] Add loading animations and transitions
   - [ ] Implement dark mode (stretch goal)
   - [ ] Add keyboard navigation support

3. **Documentation**
   - [ ] Create comprehensive README.md
   - [ ] Add usage instructions and examples
   - [ ] Document security considerations
   - [ ] Add MIT license

## Technical Implementation Details

### File Structure
```
cloudpeep/
├── index.html
├── style.css
├── main.js
├── utils.js
├── services.js
├── cloud/
│   ├── aws.js
│   ├── azure.js
│   └── gcp.js
├── icons/
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── README.md
└── LICENSE
```

### Key Technologies
- **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Cloud SDKs**: AWS SDK v3, Azure SDK, Google Cloud SDK
- **CDN**: unpkg.com for SDK imports
- **Icons**: SVG format for scalability
- **Storage**: localStorage for optional profile saving

### Security Considerations
- All processing happens client-side
- No credential storage or transmission to external servers
- Clear ethical usage disclaimers
- Offline capability with appropriate warnings

## Success Criteria
- [ ] Application works entirely in browser without backend
- [ ] Supports all three cloud providers (AWS, Azure, GCP)
- [ ] Provides clear visual feedback for accessible services
- [ ] Handles errors gracefully with user-friendly messages
- [ ] Includes comprehensive security disclaimers
- [ ] Works offline with appropriate warnings
- [ ] Responsive design that works on desktop and mobile

## Timeline Estimate
- **Phase 1**: 2-3 days
- **Phase 2**: 4-5 days
- **Phase 3**: 2-3 days
- **Phase 4**: 1-2 days
- **Phase 5**: 1-2 days

**Total Estimated Time**: 10-15 days 