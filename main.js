/**
 * Main application logic for PeekInTheCloud
 */

// Global variables
let currentProvider = null;
let scanResults = null;

/**
 * Initialize the application
 */
function init() {
    console.log('Initializing PeekInTheCloud...');
    
    // Check network connectivity
    checkNetworkConnectivity();
    
    // Set up event listeners
    setupEventListeners();
    
    // Initialize UI state
    updateUI();
    
    console.log('PeekInTheCloud initialized successfully');
}

/**
 * Check network connectivity and show warnings if needed
 */
async function checkNetworkConnectivity() {
    const isOnline = Utils.NetworkUtils.isOnline();
    const hasConnectivity = await Utils.NetworkUtils.checkConnectivity();
    
    if (!isOnline || !hasConnectivity) {
        Utils.NetworkUtils.showOfflineWarning();
    }
}

/**
 * Set up all event listeners
 */
function setupEventListeners() {
    // Cloud provider selection
    const providerSelect = document.getElementById('cloudProvider');
    providerSelect.addEventListener('change', handleProviderChange);
    
    // Form input validation
    setupFormValidation();
    
    // Scan button
    const scanButton = document.getElementById('scanButton');
    scanButton.addEventListener('click', handleScanClick);
    
    // Modal close
    const modal = document.getElementById('serviceModal');
    const modalClose = modal.querySelector('.modal-close');
    modalClose.addEventListener('click', closeModal);
    
    // Close modal on outside click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            closeModal();
        }
    });
    
    // Close modal on escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeModal();
        }
    });
    
    // Export buttons
    const copyButton = document.getElementById('copyResults');
    const downloadButton = document.getElementById('downloadResults');
    
    copyButton.addEventListener('click', handleCopyResults);
    downloadButton.addEventListener('click', handleDownloadResults);
}

/**
 * Set up form validation for real-time feedback
 */
function setupFormValidation() {
    const forms = ['aws-form', 'azure-form', 'gcp-form'];
    
    forms.forEach(formId => {
        const form = document.getElementById(formId);
        if (form) {
            const inputs = form.querySelectorAll('input, select, textarea');
            inputs.forEach(input => {
                input.addEventListener('input', () => {
                    Utils.UIUtils.updateScanButton();
                });
                input.addEventListener('change', () => {
                    Utils.UIUtils.updateScanButton();
                });
            });
        }
    });
}

/**
 * Handle cloud provider selection change
 * @param {Event} event - Change event
 */
function handleProviderChange(event) {
    const provider = event.target.value;
    currentProvider = provider;
    
    // Hide all forms
    const forms = ['aws-form', 'azure-form', 'gcp-form'];
    forms.forEach(formId => {
        Utils.UIUtils.toggleElement(formId, false);
    });
    
    // Show selected provider's form
    if (provider) {
        Utils.UIUtils.toggleElement(`${provider}-form`, true);
    }
    
    // Update scan button state
    Utils.UIUtils.updateScanButton();
    
    // Clear previous results
    clearResults();
}

/**
 * Handle scan button click
 */
async function handleScanClick() {
    if (!currentProvider) {
        Utils.ErrorHandler.showError('Please select a cloud provider', 'error');
        return;
    }
    
    // Validate credentials
    const credentials = getCredentials();
    if (!credentials) {
        return;
    }
    
    // Show loading state
    Utils.UIUtils.showLoading(true);
    
    try {
        // Perform scan based on provider
        let results;
        switch (currentProvider) {
            case 'aws':
                results = await scanAWSServices(credentials);
                break;
            case 'azure':
                results = await scanAzureServices(credentials);
                break;
            case 'gcp':
                results = await scanGCPServices(credentials);
                break;
            default:
                throw new Error('Unsupported cloud provider');
        }
        
        // Store results
        scanResults = results;
        
        // Display results
        displayResults(results);
        
        // Save to localStorage (optional)
        Utils.StorageUtils.saveResults(results, currentProvider);
        
        // Show export section
        Utils.UIUtils.toggleElement('export-section', true);
        
    } catch (error) {
        console.error('Scan failed:', error);
        Utils.ErrorHandler.showError(
            `Scan failed: ${error.message}`,
            'error'
        );
    } finally {
        // Hide loading state
        Utils.UIUtils.showLoading(false);
    }
}

/**
 * Get credentials from the current form
 * @returns {Object|null} - Credentials object or null if invalid
 */
function getCredentials() {
    if (!currentProvider) {
        return null;
    }
    
    let credentials = {};
    let validationResult;
    
    switch (currentProvider) {
        case 'aws':
            credentials = {
                accessKeyId: document.getElementById('aws-access-key').value.trim(),
                secretAccessKey: document.getElementById('aws-secret-key').value.trim(),
                sessionToken: document.getElementById('aws-session-token').value.trim(),
                region: document.getElementById('aws-region').value
            };
            validationResult = Utils.CredentialValidator.validateAWS(credentials);
            break;
            
        case 'azure':
            credentials = {
                clientId: document.getElementById('azure-client-id').value.trim(),
                clientSecret: document.getElementById('azure-client-secret').value.trim(),
                tenantId: document.getElementById('azure-tenant-id').value.trim()
            };
            validationResult = Utils.CredentialValidator.validateAzure(credentials);
            break;
            
        case 'gcp':
            const serviceAccountJson = document.getElementById('gcp-service-account').value.trim();
            validationResult = Utils.CredentialValidator.validateGCP(serviceAccountJson);
            if (validationResult.isValid) {
                credentials = { serviceAccountJson };
            }
            break;
            
        default:
            Utils.ErrorHandler.showError('Unsupported cloud provider', 'error');
            return null;
    }
    
    if (!validationResult.isValid) {
        Utils.ErrorHandler.showError(
            `Invalid credentials: ${validationResult.errors.join(', ')}`,
            'error'
        );
        return null;
    }
    
    return credentials;
}

/**
 * Scan AWS services
 * @param {Object} credentials - AWS credentials
 * @returns {Promise<Object>} - Scan results
 */
async function scanAWSServices(credentials) {
    console.log('Scanning AWS services...');
    
    if (typeof AWSCloudScanner === 'undefined') {
        throw new Error('AWS scanner not loaded');
    }
    
    return await AWSCloudScanner.scanServices(credentials);
}

/**
 * Scan Azure services
 * @param {Object} credentials - Azure credentials
 * @returns {Promise<Object>} - Scan results
 */
async function scanAzureServices(credentials) {
    console.log('Scanning Azure services...');
    
    if (typeof AzureCloudScanner === 'undefined') {
        throw new Error('Azure scanner not loaded');
    }
    
    return await AzureCloudScanner.scanServices(credentials);
}

/**
 * Scan GCP services
 * @param {Object} credentials - GCP credentials
 * @returns {Promise<Object>} - Scan results
 */
async function scanGCPServices(credentials) {
    console.log('Scanning GCP services...');
    
    if (typeof GCPCloudScanner === 'undefined') {
        throw new Error('GCP scanner not loaded');
    }
    
    return await GCPCloudScanner.scanServices(credentials);
}

/**
 * Display scan results in the UI
 * @param {Object} results - Scan results
 */
function displayResults(results) {
    const servicesGrid = document.getElementById('services-grid');
    const resultsSection = document.getElementById('results-section');
    
    // Clear previous results
    servicesGrid.innerHTML = '';
    
    // Get service metadata for current provider
    const services = ServiceMetadata.getProviderServices(currentProvider);
    
    // Create service cards
    Object.entries(services).forEach(([serviceKey, serviceMeta]) => {
        const serviceResult = results[serviceKey] || { status: 'unknown', accessible: false };
        const card = createServiceCard(serviceKey, serviceMeta, serviceResult);
        servicesGrid.appendChild(card);
    });
    
    // Show results section
    Utils.UIUtils.toggleElement('results-section', true);
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

/**
 * Create a service card element
 * @param {string} serviceKey - Service key
 * @param {Object} serviceMeta - Service metadata
 * @param {Object} serviceResult - Service scan result
 * @returns {HTMLElement} - Service card element
 */
function createServiceCard(serviceKey, serviceMeta, serviceResult) {
    const card = document.createElement('div');
    card.className = `service-card ${serviceResult.accessible ? '' : 'disabled'}`;
    
    const statusColor = ServiceMetadata.getStatusColor(serviceResult.status);
    const permissionText = serviceResult.permission ? 
        ServiceMetadata.formatPermission(serviceResult.permission) : 'Unknown';
    
    card.innerHTML = `
        <div class="service-icon">${serviceMeta.icon}</div>
        <div class="service-name">${serviceMeta.name}</div>
        <div class="service-description">${serviceMeta.description}</div>
        <div class="service-status ${statusColor}">
            ${serviceResult.accessible ? 'Accessible' : 'Inaccessible'}
        </div>
        <div class="service-permission">${permissionText}</div>
    `;
    
    // Add click handler for service details
    if (serviceResult.accessible) {
        card.addEventListener('click', () => {
            showServiceDetails(serviceKey, serviceMeta, serviceResult);
        });
    }
    
    return card;
}

/**
 * Show service details in modal
 * @param {string} serviceKey - Service key
 * @param {Object} serviceMeta - Service metadata
 * @param {Object} serviceResult - Service scan result
 */
function showServiceDetails(serviceKey, serviceMeta, serviceResult) {
    const modal = document.getElementById('serviceModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalContent = document.getElementById('modalContent');
    
    // Set modal title
    modalTitle.textContent = `${serviceMeta.fullName} Details`;
    
    // Create modal content
    let content = `
        <div class="service-details">
            <h4>Service Information</h4>
            <p><strong>Name:</strong> ${serviceMeta.fullName}</p>
            <p><strong>Description:</strong> ${serviceMeta.description}</p>
            <p><strong>Status:</strong> <span class="${ServiceMetadata.getStatusColor(serviceResult.status)}">${serviceResult.accessible ? 'Accessible' : 'Inaccessible'}</span></p>
            <p><strong>Permission Level:</strong> ${ServiceMetadata.formatPermission(serviceResult.permission)}</p>
        </div>
    `;
    
    // Add resources if available
    if (serviceResult.resources && serviceResult.resources.length > 0) {
        content += `
            <div class="service-resources">
                <h4>Accessible Resources</h4>
                <ul>
                    ${serviceResult.resources.map(resource => `<li>${Utils.SecurityUtils.sanitizeInput(resource)}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // Add API calls if available
    if (serviceResult.apiCalls && serviceResult.apiCalls.length > 0) {
        content += `
            <div class="service-api-calls">
                <h4>API Calls Tested</h4>
                <ul>
                    ${serviceResult.apiCalls.map(call => `<li>${Utils.SecurityUtils.sanitizeInput(call)}</li>`).join('')}
                </ul>
            </div>
        `;
    }
    
    // Add raw response if available
    if (serviceResult.rawResponse) {
        content += `
            <div class="service-raw-response">
                <h4>Raw API Response</h4>
                <pre><code>${Utils.SecurityUtils.sanitizeInput(JSON.stringify(serviceResult.rawResponse, null, 2))}</code></pre>
            </div>
        `;
    }
    
    modalContent.innerHTML = content;
    
    // Show modal
    modal.classList.remove('hidden');
}

/**
 * Close the modal
 */
function closeModal() {
    const modal = document.getElementById('serviceModal');
    modal.classList.add('hidden');
}

/**
 * Handle copy results button click
 */
async function handleCopyResults() {
    if (!scanResults) {
        Utils.ErrorHandler.showError('No results to copy', 'error');
        return;
    }
    
    try {
        const resultsText = JSON.stringify(scanResults, null, 2);
        const success = await Utils.UIUtils.copyToClipboard(resultsText);
        
        if (success) {
            Utils.ErrorHandler.showError('Results copied to clipboard', 'info');
        } else {
            Utils.ErrorHandler.showError('Failed to copy results', 'error');
        }
    } catch (error) {
        Utils.ErrorHandler.showError('Failed to copy results', 'error');
    }
}

/**
 * Handle download results button click
 */
function handleDownloadResults() {
    if (!scanResults) {
        Utils.ErrorHandler.showError('No results to download', 'error');
        return;
    }
    
    try {
        const filename = `peekinthecloud_${currentProvider}_${new Date().toISOString().split('T')[0]}.json`;
        Utils.UIUtils.downloadJSON(scanResults, filename);
    } catch (error) {
        Utils.ErrorHandler.showError('Failed to download results', 'error');
    }
}

/**
 * Clear scan results
 */
function clearResults() {
    scanResults = null;
    Utils.UIUtils.toggleElement('results-section', false);
    Utils.UIUtils.toggleElement('export-section', false);
}

/**
 * Update UI state
 */
function updateUI() {
    Utils.UIUtils.updateScanButton();
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', init);

// Export functions for testing
window.PeekInTheCloud = {
    init,
    handleProviderChange,
    handleScanClick,
    getCredentials,
    displayResults,
    showServiceDetails,
    closeModal,
    handleCopyResults,
    handleDownloadResults,
    clearResults,
    updateUI
}; 