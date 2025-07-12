/**
 * PeekInTheCloud - Main Application
 * Comprehensive cloud service enumeration tool
 */

class PeekInTheCloud {
    constructor() {
        this.currentProvider = null;
        this.scanners = {};
        this.results = {};
        this.securityResults = {};
        this.resourceMaps = {};
        this.enhancedAnalysis = {};
        this.isScanning = false;
        this.selectedServices = new Set();
        this.securityEngine = new SecurityRuleEngine();
        this.resourceMapper = new ResourceMapper();
        this.enhancedAnalyzer = new EnhancedAnalyzer();
        
        // Progress tracking
        this.scanProgress = {
            current: 0,
            total: 0,
            completed: 0,
            failed: 0,
            currentService: '',
            currentStatus: '',
            startTime: null
        };
    }

    initialize() {
        this.setupEventListeners();
        this.setupServiceGrid();
        this.setupDebugConsole();
        this.loadSavedCredentials();
        console.log('PeekInTheCloud initialized successfully');
    }

    /**
     * Initialize scan progress tracking
     */
    initializeScanProgress(totalServices) {
        this.scanProgress = {
            current: 0,
            total: totalServices,
            completed: 0,
            failed: 0,
            currentService: '',
            currentStatus: 'Initializing...',
            startTime: Date.now()
        };
        this.updateProgressUI();
    }

    /**
     * Update scan progress
     */
    updateScanProgress(service, status, isCompleted = false, isFailed = false) {
        if (service) {
            this.scanProgress.currentService = service;
        }
        if (status) {
            this.scanProgress.currentStatus = status;
        }
        
        if (isCompleted) {
            this.scanProgress.completed++;
            if (isFailed) {
                this.scanProgress.failed++;
            }
        }
        
        this.scanProgress.current++;
        this.updateProgressUI();
    }

    /**
     * Update progress UI elements
     */
    updateProgressUI() {
        const progress = this.scanProgress;
        const percentage = progress.total > 0 ? Math.round((progress.current / progress.total) * 100) : 0;
        const successRate = progress.completed > 0 ? Math.round(((progress.completed - progress.failed) / progress.completed) * 100) : 0;

        // Update progress bar
        const progressFill = document.getElementById('progress-fill');
        if (progressFill) {
            progressFill.style.width = `${percentage}%`;
        }

        // Update progress text
        const progressCurrent = document.getElementById('progress-current');
        const progressTotal = document.getElementById('progress-total');
        const progressPercentage = document.getElementById('progress-percentage');
        
        if (progressCurrent) progressCurrent.textContent = progress.current;
        if (progressTotal) progressTotal.textContent = progress.total;
        if (progressPercentage) progressPercentage.textContent = `${percentage}%`;

        // Update current service status
        const serviceIcon = document.getElementById('current-service-icon');
        const serviceName = document.getElementById('current-service-name');
        const serviceStatus = document.getElementById('current-service-status');
        
        if (serviceIcon) {
            const serviceInfo = CLOUD_SERVICES[this.currentProvider]?.services[progress.currentService];
            serviceIcon.textContent = serviceInfo?.icon || '🔍';
        }
        if (serviceName) serviceName.textContent = progress.currentService || 'Initializing...';
        if (serviceStatus) serviceStatus.textContent = progress.currentStatus;

        // Update statistics
        const statsCompleted = document.getElementById('stats-completed');
        const statsFailed = document.getElementById('stats-failed');
        const statsSuccessRate = document.getElementById('stats-success-rate');
        
        if (statsCompleted) {
            statsCompleted.textContent = progress.completed;
            statsCompleted.className = 'stat-value success';
        }
        if (statsFailed) {
            statsFailed.textContent = progress.failed;
            statsFailed.className = 'stat-value error';
        }
        if (statsSuccessRate) {
            statsSuccessRate.textContent = `${successRate}%`;
            statsSuccessRate.className = 'stat-value ' + (successRate >= 80 ? 'success' : successRate >= 60 ? 'warning' : 'error');
        }
    }

    /**
     * Update scan status messages
     */
    updateScanStatus(title, message) {
        const statusTitle = document.getElementById('scan-status-title');
        const statusMessage = document.getElementById('scan-status-message');
        
        if (statusTitle) statusTitle.textContent = title;
        if (statusMessage) statusMessage.textContent = message;
    }

    /**
     * Check for honeytoken/canary tokens
     * @param {string} provider - Cloud provider
     * @param {Object} credentials - Credentials to check
     * @returns {Object} Detection result
     */
    checkForHoneytoken(provider, credentials) {
        if (provider === 'aws') {
            return Utils.HoneytokenUtils.detectHoneytoken(credentials);
        }
        return { isHoneytoken: false, type: null, accountId: null };
    }

    /**
     * Show honeytoken warning modal
     * @param {Object} honeytokenInfo - Honeytoken detection result
     * @param {Function} onProceed - Callback when user chooses to proceed
     * @param {Function} onCancel - Callback when user chooses to cancel
     */
    showHoneytokenWarning(honeytokenInfo, onProceed, onCancel) {
        const modal = document.getElementById('honeytokenModal');
        const canaryType = document.getElementById('canary-type');
        const accountId = document.getElementById('canary-account-id');
        const message = document.getElementById('canary-message');
        const proceedBtn = document.getElementById('proceedHoneytokenScan');
        const cancelBtn = document.getElementById('cancelHoneytokenScan');

        // Update modal content
        if (honeytokenInfo.type === 'thinkst') {
            canaryType.textContent = 'Thinkst Canary (canarytokens.org)';
        } else if (honeytokenInfo.type === 'thinkstKnockoffs') {
            canaryType.textContent = 'Off-brand Canary Token';
        } else {
            canaryType.textContent = 'Unknown Canary Token';
        }

        accountId.textContent = honeytokenInfo.accountId;
        message.textContent = honeytokenInfo.message;

        // Set up event listeners
        const handleProceed = () => {
            modal.classList.add('hidden');
            proceedBtn.removeEventListener('click', handleProceed);
            cancelBtn.removeEventListener('click', handleCancel);
            onProceed();
        };

        const handleCancel = () => {
            modal.classList.add('hidden');
            proceedBtn.removeEventListener('click', handleProceed);
            cancelBtn.removeEventListener('click', handleCancel);
            onCancel();
        };

        proceedBtn.addEventListener('click', handleProceed);
        cancelBtn.addEventListener('click', handleCancel);

        // Show modal
        modal.classList.remove('hidden');
    }

    /**
     * Add honeytoken warning banner to results
     * @param {string} provider - Cloud provider
     * @param {Object} honeytokenInfo - Honeytoken detection result
     */
    addHoneytokenBanner(provider, honeytokenInfo) {
        const resultsContainer = document.getElementById('scan-results');
        if (!resultsContainer) return;

        const banner = document.createElement('div');
        banner.className = 'honeytoken-banner';
        banner.innerHTML = `
            <span class="banner-icon">🚨</span>
            <strong>CANARY TOKEN DETECTED:</strong> This scan was performed on a honeytoken/canary token. 
            Account ID: ${honeytokenInfo.accountId} (${honeytokenInfo.type === 'thinkst' ? 'Thinkst Canary' : 'Off-brand Canary'})
        `;

        // Insert at the top of results
        resultsContainer.insertBefore(banner, resultsContainer.firstChild);
    }

    /**
     * Test honeytoken detection (for debugging)
     */
    testHoneytokenDetection() {
        console.log('Testing honeytoken detection...');
        
        // Test with a known Thinkst canary token
        const testCredentials = {
            accessKeyId: 'AKIAXYZDQCEN4B6JSJQI', // This should extract account ID that matches a canary
            secretAccessKey: 'test-secret'
        };
        
        const result = this.checkForHoneytoken('aws', testCredentials);
        console.log('Honeytoken detection result:', result);
        
        if (result.isHoneytoken) {
            console.log('✅ Honeytoken detected correctly!');
            this.showHoneytokenWarning(result, 
                () => console.log('User chose to proceed'),
                () => console.log('User chose to cancel')
            );
        } else {
            console.log('❌ Honeytoken not detected');
        }
    }

    setupEventListeners() {
        // Provider selection
        document.getElementById('provider-select').addEventListener('change', (e) => {
            this.switchProvider(e.target.value);
        });

        // Form submissions
        document.getElementById('aws-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAWSScan();
        });

        document.getElementById('azure-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleAzureScan();
        });

        document.getElementById('gcp-form').addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleGCPScan();
        });

        // Service selection
        document.getElementById('service-grid').addEventListener('change', (e) => {
            if (e.target.type === 'checkbox') {
                this.handleServiceSelection(e.target);
            }
        });

        // Filter controls
        document.getElementById('category-filter').addEventListener('change', (e) => {
            this.filterServicesByCategory(e.target.value);
        });

        document.getElementById('search-services').addEventListener('input', (e) => {
            this.filterServicesBySearch(e.target.value);
        });

        // Export buttons
        document.getElementById('export-json').addEventListener('click', () => {
            this.exportResults('json');
        });

        document.getElementById('export-csv').addEventListener('click', () => {
            this.exportResults('csv');
        });

        // Clear results
        document.getElementById('clear-results').addEventListener('click', () => {
            this.clearResults();
        });

        // Select all/none services
        document.getElementById('select-all-services').addEventListener('click', () => {
            this.selectAllServices();
        });

        document.getElementById('select-none-services').addEventListener('click', () => {
            this.selectNoServices();
        });

        // Debug panel controls
        document.getElementById('toggle-debug').addEventListener('click', () => {
            this.toggleDebugPanel();
        });

        document.getElementById('clear-debug').addEventListener('click', () => {
            this.clearDebugLog();
        });

        document.getElementById('copy-debug').addEventListener('click', () => {
            this.copyDebugLog();
        });
    }

    setupServiceGrid() {
        const grid = document.getElementById('service-grid');
        grid.innerHTML = '';
        
        if (!this.currentProvider) return;

        const services = CLOUD_SERVICES[this.currentProvider].services;
        const categories = new Set();
        
        // Collect all categories
        Object.values(services).forEach(service => {
            categories.add(service.category);
        });

        // Create category sections
        Array.from(categories).sort().forEach(category => {
            const categoryDiv = document.createElement('div');
            categoryDiv.className = 'service-category';
            categoryDiv.innerHTML = `
                <h4>${SERVICE_CATEGORIES[category]} ${category}</h4>
                <div class="service-items"></div>
            `;
            
            const serviceItems = categoryDiv.querySelector('.service-items');
            
            // Add services for this category
            Object.entries(services)
                .filter(([_, service]) => service.category === category)
                .forEach(([key, service]) => {
                    const serviceDiv = document.createElement('div');
                    serviceDiv.className = 'service-item';
                    serviceDiv.innerHTML = `
                        <label class="service-checkbox">
                            <input type="checkbox" value="${key}" data-category="${category}">
                            <span class="service-name">${service.name}</span>
                            <span class="service-description">${service.description}</span>
                        </label>
                    `;
                    serviceItems.appendChild(serviceDiv);
                });
            
            grid.appendChild(categoryDiv);
        });
    }

    switchProvider(provider) {
        this.currentProvider = provider;
        this.selectedServices.clear();
        this.setupServiceGrid();
        this.updateUI();
        
        // Show appropriate form
        document.querySelectorAll('.credential-form').forEach(form => {
            form.style.display = 'none';
        });
        
        if (provider) {
            document.getElementById(`${provider}-form`).style.display = 'block';
        }
    }

    handleServiceSelection(checkbox) {
        const service = checkbox.value;
        
        if (checkbox.checked) {
            this.selectedServices.add(service);
        } else {
            this.selectedServices.delete(service);
        }
        
        this.updateServiceCount();
    }

    selectAllServices() {
        const checkboxes = document.querySelectorAll('#service-grid input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = true;
            this.selectedServices.add(checkbox.value);
        });
        this.updateServiceCount();
    }

    selectNoServices() {
        const checkboxes = document.querySelectorAll('#service-grid input[type="checkbox"]');
        checkboxes.forEach(checkbox => {
            checkbox.checked = false;
            this.selectedServices.delete(checkbox.value);
        });
        this.updateServiceCount();
    }

    updateServiceCount() {
        const count = this.selectedServices.size;
        const total = Object.keys(CLOUD_SERVICES[this.currentProvider]?.services || {}).length;
        document.getElementById('selected-count').textContent = `${count}/${total}`;
    }

    filterServicesByCategory(category) {
        const serviceItems = document.querySelectorAll('.service-item');
        
        serviceItems.forEach(item => {
            const checkbox = item.querySelector('input[type="checkbox"]');
            const itemCategory = checkbox.dataset.category;
            
            if (category === 'all' || itemCategory === category) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }

    filterServicesBySearch(searchTerm) {
        const serviceItems = document.querySelectorAll('.service-item');
        const searchLower = searchTerm.toLowerCase();
        
        serviceItems.forEach(item => {
            const serviceName = item.querySelector('.service-name').textContent.toLowerCase();
            const serviceDesc = item.querySelector('.service-description').textContent.toLowerCase();
            
            if (serviceName.includes(searchLower) || serviceDesc.includes(searchLower)) {
                item.style.display = 'block';
            } else {
                item.style.display = 'none';
            }
        });
    }

    async handleAWSScan() {
        const formData = new FormData(document.getElementById('aws-form'));
        const credentials = {
            accessKeyId: formData.get('access-key'),
            secretAccessKey: formData.get('secret-key'),
            sessionToken: formData.get('session-token') || undefined
        };

        await this.performScan('aws', credentials);
    }

    async handleAzureScan() {
        const formData = new FormData(document.getElementById('azure-form'));
        const credentials = {
            accessToken: formData.get('access-token')
        };

        await this.performScan('azure', credentials);
    }

    async handleGCPScan() {
        const formData = new FormData(document.getElementById('gcp-form'));
        const serviceAccountKey = formData.get('service-account-key');
        
        let credentials;
        try {
            credentials = {
                serviceAccountKey: JSON.parse(serviceAccountKey)
            };
        } catch (error) {
            this.showNotification('Invalid JSON in service account key', 'error');
            return;
        }

        await this.performScan('gcp', credentials);
    }

    async performScan(provider, credentials) {
        if (this.isScanning) {
            this.showNotification('Scan already in progress', 'warning');
            return;
        }

        const scanStartTime = Date.now();
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        
        console.log(`[${scanId}] 🚀 Starting ${provider.toUpperCase()} scan...`);
        console.log(`[${scanId}] 📊 Scan configuration:`, {
            provider: provider,
            selectedServices: this.selectedServices.size,
            totalServices: Object.keys(CLOUD_SERVICES[provider]?.services || {}).length,
            timestamp: new Date().toISOString()
        });

        try {
            this.isScanning = true;
            this.currentProvider = provider;
            this.updateUI();
            this.showNotification(`Starting ${provider.toUpperCase()} scan...`, 'info');

            // Show loading overlay
            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) {
                loadingOverlay.classList.remove('hidden');
            }

            // Initialize progress tracking
            const servicesToScan = this.selectedServices.size > 0 
                ? Array.from(this.selectedServices)
                : Object.keys(CLOUD_SERVICES[provider]?.services || {});
            
            this.initializeScanProgress(servicesToScan.length);
            this.updateScanStatus('Initializing Scanner...', `Preparing to scan ${servicesToScan.length} services`);

            // Validate credentials
            console.log(`[${scanId}] 🔐 Validating credentials...`);
            if (!this.validateCredentials(provider, credentials)) {
                console.error(`[${scanId}] ❌ Credential validation failed`);
                this.showNotification('Invalid credentials provided', 'error');
                return;
            }
            console.log(`[${scanId}] ✅ Credentials validated successfully`);

            // Check for honeytoken/canary tokens
            console.log(`[${scanId}] 🔍 Checking for honeytoken/canary tokens...`);
            const honeytokenInfo = this.checkForHoneytoken(provider, credentials);
            
            if (honeytokenInfo.isHoneytoken) {
                console.log(`[${scanId}] ⚠️ Honeytoken detected:`, honeytokenInfo);
                
                // Show warning modal and wait for user decision
                return new Promise((resolve, reject) => {
                    this.showHoneytokenWarning(honeytokenInfo, 
                        () => {
                            // User chose to proceed
                            console.log(`[${scanId}] ⚠️ User chose to proceed with honeytoken scan`);
                            this.addHoneytokenBanner(provider, honeytokenInfo);
                            this.continueScan(provider, credentials, scanId, scanStartTime, servicesToScan, resolve, reject);
                        },
                        () => {
                            // User chose to cancel
                            console.log(`[${scanId}] ❌ User cancelled honeytoken scan`);
                            this.isScanning = false;
                            this.updateUI();
                            this.showNotification('Scan cancelled - honeytoken detected', 'warning');
                            reject(new Error('Scan cancelled by user due to honeytoken detection'));
                        }
                    );
                });
            }

            // Continue with the scan
            this.continueScan(provider, credentials, scanId, scanStartTime, servicesToScan);
        } catch (error) {
            const scanDuration = Date.now() - scanStartTime;
            console.error(`[${scanId}] ❌ Scan failed after ${Utils.DataUtils.formatDuration(scanDuration)}:`, error);
            console.error(`[${scanId}] Error details:`, {
                name: error.name,
                message: error.message,
                stack: error.stack,
                provider: provider
            });
            
            // Update error status
            this.updateScanStatus('Scan Failed', `Error: ${error.message}`);
            
            // Hide loading overlay after error
            setTimeout(() => {
                const loadingOverlay = document.getElementById('loadingOverlay');
                if (loadingOverlay) {
                    loadingOverlay.classList.add('hidden');
                }
            }, 2000);
            
            this.showNotification(`Scan failed: ${error.message}`, 'error');
        } finally {
            this.isScanning = false;
            this.updateUI();
            console.log(`[${scanId}] 🏁 Scan session ended`);
        }
    }

    /**
     * Continue with the actual scanning process
     * @param {string} provider - Cloud provider
     * @param {Object} credentials - Credentials
     * @param {string} scanId - Scan ID
     * @param {number} scanStartTime - Scan start time
     * @param {Array} servicesToScan - Services to scan
     * @param {Function} resolve - Promise resolve function (optional)
     * @param {Function} reject - Promise reject function (optional)
     */
    async continueScan(provider, credentials, scanId, scanStartTime, servicesToScan, resolve = null, reject = null) {
        try {
            // Save credentials
            console.log(`[${scanId}] 💾 Saving credentials...`);
            this.saveCredentials(provider, credentials);
            console.log(`[${scanId}] ✅ Credentials saved`);

            // Initialize scanner
            console.log(`[${scanId}] 🔧 Initializing scanner...`);
            const scanner = this.getScanner(provider);
            if (!scanner) {
                throw new Error(`Scanner not available for ${provider}`);
            }
            console.log(`[${scanId}] ✅ Scanner initialized:`, scanner.constructor.name);

            console.log(`[${scanId}] 📋 Services to scan:`, {
                selected: servicesToScan.length,
                services: servicesToScan
            });

            // Perform scan
            console.log(`[${scanId}] 🔍 Beginning service enumeration...`);
            this.updateScanStatus('Scanning Services...', 'Enumerating cloud services and resources');
            
            // Set up progress tracking for the scanner
            scanner.onProgressUpdate = (service, status) => {
                this.updateScanProgress(service, status);
            };
            
            // Override scanner's result tracking with our UI updates
            const originalAddResult = scanner.addResult;
            scanner.addResult = (service, data) => {
                const isFailed = data.error;
                this.updateScanProgress(service, isFailed ? 'Failed' : 'Completed', true, isFailed);
                return originalAddResult.call(scanner, service, data);
            };
            
            const results = await scanner.scan(credentials, servicesToScan);
            
            const scanDuration = Date.now() - scanStartTime;
            console.log(`[${scanId}] ✅ Scan completed successfully!`, {
                duration: Utils.DataUtils.formatDuration(scanDuration),
                servicesScanned: Object.keys(results).length,
                successfulServices: Object.values(results).filter(r => !r.error).length,
                failedServices: Object.values(results).filter(r => r.error).length
            });
            
            // Perform security analysis
            console.log(`[${scanId}] 🔒 Starting security analysis...`);
            this.updateScanStatus('Security Analysis...', 'Analyzing security posture and compliance');
            const securityReport = this.securityEngine.generateSecurityReport(provider, results);
            console.log(`[${scanId}] ✅ Security analysis completed!`, {
                securityScore: securityReport.securityScore,
                totalFindings: securityReport.totalFindings,
                findingsBySeverity: securityReport.findingsBySeverity
            });

            // Perform resource mapping and attack surface analysis
            console.log(`[${scanId}] 🗺️ Starting resource mapping and attack surface analysis...`);
            this.updateScanStatus('Resource Mapping...', 'Building resource relationships and attack surface');
            const resourceMap = this.resourceMapper.buildResourceMap(provider, results);
            const resourceMapReport = this.resourceMapper.generateResourceMapReport();
            console.log(`[${scanId}] ✅ Resource mapping completed!`, {
                totalResources: resourceMapReport.summary.totalResources,
                resourceTypes: resourceMapReport.summary.resourceTypes,
                publicResources: resourceMapReport.summary.publicResources,
                overPrivilegedResources: resourceMapReport.summary.overPrivilegedResources,
                escalationPaths: resourceMapReport.summary.escalationPaths
            });

            // Perform enhanced resource analysis
            console.log(`[${scanId}] 🔍 Starting enhanced resource analysis...`);
            this.updateScanStatus('Enhanced Analysis...', 'Performing detailed resource security analysis');
            const enhancedAnalysis = this.enhancedAnalyzer.performEnhancedAnalysis(provider, results);
            console.log(`[${scanId}] ✅ Enhanced analysis completed!`, {
                totalResources: Object.keys(enhancedAnalysis.resources).length,
                securityPosture: enhancedAnalysis.securityPosture,
                recommendations: Object.keys(enhancedAnalysis.recommendations).reduce((acc, severity) => {
                    acc[severity] = enhancedAnalysis.recommendations[severity].length;
                    return acc;
                }, {})
            });
            
            this.results[provider] = results;
            this.securityResults[provider] = securityReport;
            this.resourceMaps[provider] = resourceMapReport;
            this.enhancedAnalysis[provider] = enhancedAnalysis;
            this.displayResults(provider, results);
            this.displaySecurityResults(provider, securityReport);
            this.displayResourceMapResults(provider, resourceMapReport);
            this.displayEnhancedAnalysisResults(provider, enhancedAnalysis);
            
            // Update final status
            this.updateScanStatus('Scan Complete!', 'All analysis completed successfully');
            
            // Hide loading overlay after a brief delay
            setTimeout(() => {
                const loadingOverlay = document.getElementById('loadingOverlay');
                if (loadingOverlay) {
                    loadingOverlay.classList.add('hidden');
                }
            }, 1000);
            
            this.showNotification(`${provider.toUpperCase()} scan completed successfully!`, 'success');
            
            if (resolve) resolve();
        } catch (error) {
            console.error(`[${scanId}] ❌ Scan failed:`, error);
            if (reject) reject(error);
            else throw error;
        }
    }

    validateCredentials(provider, credentials) {
        switch (provider) {
            case 'aws':
                return credentials.accessKeyId && credentials.secretAccessKey;
            case 'azure':
                return credentials.accessToken;
            case 'gcp':
                return credentials.serviceAccountKey;
            default:
                return false;
        }
    }

    getScanner(provider) {
        if (!this.scanners[provider]) {
            switch (provider) {
                case 'aws':
                    this.scanners[provider] = new AWSScanner();
                    break;
                case 'azure':
                    this.scanners[provider] = new AzureScanner();
                    break;
                case 'gcp':
                    this.scanners[provider] = new GCPScanner();
                    break;
            }
        }
        return this.scanners[provider];
    }

    displayResults(provider, results) {
        const resultsContainer = document.getElementById('scan-results');
        const providerResults = document.createElement('div');
        providerResults.className = 'provider-results';
        providerResults.id = `${provider}-results`;

        const header = document.createElement('div');
        header.className = 'results-header';
        header.innerHTML = `
            <h3>${CLOUD_SERVICES[provider].icon} ${CLOUD_SERVICES[provider].name} Results</h3>
            <div class="results-summary">
                <span class="services-scanned">${Object.keys(results).length} services scanned</span>
                <button class="expand-all" onclick="app.expandAllResults('${provider}')">Expand All</button>
                <button class="collapse-all" onclick="app.collapseAllResults('${provider}')">Collapse All</button>
            </div>
        `;

        providerResults.appendChild(header);

        const resultsContent = document.createElement('div');
        resultsContent.className = 'results-content';

        Object.entries(results).forEach(([service, data]) => {
            // Skip unimplemented services - they will be handled separately
            if (service === 'unimplemented_services') {
                return;
            }

            const serviceDiv = document.createElement('div');
            serviceDiv.className = 'service-result';
            
            const serviceInfo = CLOUD_SERVICES[provider].services[service];
            const serviceName = serviceInfo ? serviceInfo.name : service;
            const serviceCategory = serviceInfo ? serviceInfo.category : 'Unknown';
            
            let status = 'success';
            let content = '';
            
            if (data.error) {
                status = 'error';
                content = `<div class="error-message">${data.error}</div>`;
            } else if (data.message) {
                status = 'info';
                content = `<div class="info-message">${data.message}</div>`;
            } else {
                // Format the data for display
                content = this.formatServiceData(data);
            }

            serviceDiv.innerHTML = `
                <div class="service-header ${status}" onclick="app.toggleServiceResult(this)">
                    <span class="service-icon">${SERVICE_CATEGORIES[serviceCategory] || '🔍'}</span>
                    <span class="service-name">${serviceName}</span>
                    <span class="service-status">${this.getStatusText(data)}</span>
                    <span class="expand-icon">▼</span>
                </div>
                <div class="service-content">
                    ${content}
                </div>
            `;

            resultsContent.appendChild(serviceDiv);
        });

        // Add grouped unimplemented services section if it exists
        if (results.unimplemented_services) {
            const unimplementedDiv = document.createElement('div');
            unimplementedDiv.className = 'service-result unimplemented-section';
            
            const unimplementedData = results.unimplemented_services;
            const serviceList = unimplementedData.services.map(service => {
                const serviceInfo = CLOUD_SERVICES[provider].services[service];
                return serviceInfo ? serviceInfo.name : service;
            }).join(', ');
            
            unimplementedDiv.innerHTML = `
                <div class="service-header info" onclick="app.toggleServiceResult(this)">
                    <span class="service-icon">🚧</span>
                    <span class="service-name">Services Not Implemented Yet</span>
                    <span class="service-status">${unimplementedData.count} services</span>
                    <span class="expand-icon">▼</span>
                </div>
                <div class="service-content">
                    <div class="info-message">
                        <p><strong>${unimplementedData.message}</strong></p>
                        <p>The following ${unimplementedData.count} services are not yet implemented in this version:</p>
                        <div class="unimplemented-services-list">
                            ${unimplementedData.services.map(service => {
                                const serviceInfo = CLOUD_SERVICES[provider].services[service];
                                const serviceName = serviceInfo ? serviceInfo.name : service;
                                return `<span class="unimplemented-service">${serviceName}</span>`;
                            }).join('')}
                        </div>
                        <p><em>These services will be implemented in future updates.</em></p>
                    </div>
                </div>
            `;
            
            resultsContent.appendChild(unimplementedDiv);
        }

        providerResults.appendChild(resultsContent);
        
        // Remove existing results for this provider
        const existing = document.getElementById(`${provider}-results`);
        if (existing) {
            existing.remove();
        }
        
        resultsContainer.appendChild(providerResults);
    }

    displaySecurityResults(provider, securityReport) {
        const resultsContainer = document.getElementById('scan-results');
        const securityResults = document.createElement('div');
        securityResults.className = 'security-results';
        securityResults.id = `${provider}-security-results`;

        const header = document.createElement('div');
        header.className = 'security-header';
        header.innerHTML = `
            <h3>🔒 Security Assessment</h3>
            <div class="security-summary">
                <div class="security-score">
                    <span class="score-label">Security Score:</span>
                    <span class="score-value ${this.getSecurityScoreClass(securityReport.securityScore)}">${securityReport.securityScore}/100</span>
                </div>
                <div class="findings-summary">
                    <span class="findings-count">${securityReport.totalFindings} findings</span>
                </div>
            </div>
        `;

        securityResults.appendChild(header);

        const securityContent = document.createElement('div');
        securityContent.className = 'security-content';

        // Display findings by severity
        Object.entries(securityReport.findingsBySeverity).forEach(([severity, findings]) => {
            if (findings.length > 0) {
                const severityDiv = document.createElement('div');
                severityDiv.className = `severity-section ${severity}`;
                severityDiv.innerHTML = `
                    <h4 class="severity-title ${severity}">${this.capitalizeFirst(severity)} (${findings.length})</h4>
                    <div class="findings-list">
                        ${findings.map(finding => this.formatSecurityFinding(finding)).join('')}
                    </div>
                `;
                securityContent.appendChild(severityDiv);
            }
        });

        // Display recommendations
        if (securityReport.recommendations) {
            const recommendationsDiv = document.createElement('div');
            recommendationsDiv.className = 'recommendations-section';
            recommendationsDiv.innerHTML = `
                <h4>🔧 Security Recommendations</h4>
                <div class="recommendations-list">
                    ${this.formatRecommendations(securityReport.recommendations)}
                </div>
            `;
            securityContent.appendChild(recommendationsDiv);
        }

        securityResults.appendChild(securityContent);
        
        // Remove existing security results for this provider
        const existing = document.getElementById(`${provider}-security-results`);
        if (existing) {
            existing.remove();
        }
        
        resultsContainer.appendChild(securityResults);
    }

    formatServiceData(data) {
        if (typeof data === 'object' && data !== null) {
            const formatted = [];
            
            Object.entries(data).forEach(([key, value]) => {
                if (Array.isArray(value)) {
                    formatted.push(`
                        <div class="data-section">
                            <h4>${this.capitalizeFirst(key)} (${value.length})</h4>
                            <div class="data-table">
                                ${this.formatArrayAsTable(value)}
                            </div>
                        </div>
                    `);
                } else if (typeof value === 'object' && value !== null) {
                    formatted.push(`
                        <div class="data-section">
                            <h4>${this.capitalizeFirst(key)}</h4>
                            <pre class="json-data">${JSON.stringify(value, null, 2)}</pre>
                        </div>
                    `);
                } else {
                    formatted.push(`
                        <div class="data-item">
                            <strong>${this.capitalizeFirst(key)}:</strong> ${value}
                        </div>
                    `);
                }
            });
            
            return formatted.join('');
        } else {
            return `<pre class="json-data">${JSON.stringify(data, null, 2)}</pre>`;
        }
    }

    formatArrayAsTable(array) {
        if (array.length === 0) {
            return '<div class="no-data">No data found</div>';
        }

        const headers = Object.keys(array[0]);
        const headerRow = headers.map(h => `<th>${this.capitalizeFirst(h)}</th>`).join('');
        const dataRows = array.map(item => 
            `<tr>${headers.map(h => `<td>${item[h] || ''}</td>`).join('')}</tr>`
        ).join('');

        return `
            <table>
                <thead><tr>${headerRow}</tr></thead>
                <tbody>${dataRows}</tbody>
            </table>
        `;
    }

    getStatusText(data) {
        if (data.error) return 'Error';
        if (data.message) return 'Info';
        if (typeof data === 'object' && data !== null) {
            const keys = Object.keys(data);
            if (keys.length === 0) return 'Empty';
            return 'Success';
        }
        return 'Unknown';
    }

    toggleServiceResult(header) {
        const content = header.nextElementSibling;
        const icon = header.querySelector('.expand-icon');
        
        if (content.style.display === 'none') {
            content.style.display = 'block';
            icon.textContent = '▼';
        } else {
            content.style.display = 'none';
            icon.textContent = '▶';
        }
    }

    expandAllResults(provider) {
        const results = document.getElementById(`${provider}-results`);
        if (results) {
            results.querySelectorAll('.service-content').forEach(content => {
                content.style.display = 'block';
            });
            results.querySelectorAll('.expand-icon').forEach(icon => {
                icon.textContent = '▼';
            });
        }
    }

    collapseAllResults(provider) {
        const results = document.getElementById(`${provider}-results`);
        if (results) {
            results.querySelectorAll('.service-content').forEach(content => {
                content.style.display = 'none';
            });
            results.querySelectorAll('.expand-icon').forEach(icon => {
                icon.textContent = '▶';
            });
        }
    }

    exportResults(format) {
        if (Object.keys(this.results).length === 0) {
            this.showNotification('No results to export', 'warning');
            return;
        }

        let data, filename, mimeType;

        if (format === 'json') {
            data = JSON.stringify(this.results, null, 2);
            filename = `cloud-scan-results-${new Date().toISOString().split('T')[0]}.json`;
            mimeType = 'application/json';
        } else if (format === 'csv') {
            data = this.convertToCSV();
            filename = `cloud-scan-results-${new Date().toISOString().split('T')[0]}.csv`;
            mimeType = 'text/csv';
        }

        const blob = new Blob([data], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        this.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
    }

    convertToCSV() {
        const csvRows = [];
        
        Object.entries(this.results).forEach(([provider, services]) => {
            Object.entries(services).forEach(([service, data]) => {
                if (typeof data === 'object' && data !== null) {
                    Object.entries(data).forEach(([key, value]) => {
                        if (Array.isArray(value)) {
                            value.forEach(item => {
                                const row = {
                                    Provider: provider,
                                    Service: service,
                                    DataType: key,
                                    ...item
                                };
                                csvRows.push(row);
                            });
                        } else {
                            csvRows.push({
                                Provider: provider,
                                Service: service,
                                DataType: key,
                                Value: JSON.stringify(value)
                            });
                        }
                    });
                } else {
                    csvRows.push({
                        Provider: provider,
                        Service: service,
                        DataType: 'result',
                        Value: JSON.stringify(data)
                    });
                }
            });
        });

        if (csvRows.length === 0) return '';

        const headers = Object.keys(csvRows[0]);
        const csv = [
            headers.join(','),
            ...csvRows.map(row => headers.map(header => `"${row[header] || ''}"`).join(','))
        ].join('\n');

        return csv;
    }

    clearResults() {
        this.results = {};
        document.getElementById('scan-results').innerHTML = '';
        this.showNotification('Results cleared', 'info');
    }

    updateUI() {
        const scanButton = document.querySelector('.scan-button');
        const serviceGrid = document.getElementById('service-grid');
        const filterControls = document.getElementById('filter-controls');
        
        if (this.isScanning) {
            scanButton.textContent = 'Scanning...';
            scanButton.disabled = true;
        } else {
            scanButton.textContent = 'Start Scan';
            scanButton.disabled = false;
        }

        if (this.currentProvider) {
            serviceGrid.style.display = 'block';
            filterControls.style.display = 'block';
            this.updateServiceCount();
        } else {
            serviceGrid.style.display = 'none';
            filterControls.style.display = 'none';
        }
    }

    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.classList.add('show');
        }, 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 3000);
    }

    saveCredentials(provider, credentials) {
        const key = `${provider}_credentials`;
        const data = { ...credentials };
        
        // Don't save sensitive data in localStorage for security
        // In a real application, you might want to encrypt this
        console.log(`Credentials saved for ${provider}`);
    }

    loadSavedCredentials() {
        // Load any saved credentials if needed
        console.log('Loading saved credentials...');
    }

    capitalizeFirst(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    // Debug Console Methods
    setupDebugConsole() {
        // Override console methods to capture logs
        const originalLog = console.log;
        const originalError = console.error;
        const originalWarn = console.warn;
        const originalInfo = console.info;

        console.log = (...args) => {
            originalLog.apply(console, args);
            this.addDebugLog('info', args);
        };

        console.error = (...args) => {
            originalError.apply(console, args);
            this.addDebugLog('error', args);
        };

        console.warn = (...args) => {
            originalWarn.apply(console, args);
            this.addDebugLog('warning', args);
        };

        console.info = (...args) => {
            originalInfo.apply(console, args);
            this.addDebugLog('info', args);
        };

        // Add initial debug message
        this.addDebugLog('info', ['Debug console initialized. All console logs will be captured here.']);
    }

    addDebugLog(level, args) {
        const debugLog = document.getElementById('debug-log');
        if (!debugLog) return;

        const timestamp = new Date().toLocaleTimeString();
        const message = args.map(arg => 
            typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
        ).join(' ');

        const logEntry = document.createElement('div');
        logEntry.className = `log-entry log-${level}`;
        logEntry.innerHTML = `
            <span class="log-timestamp">[${timestamp}]</span>
            <span class="log-message">${this.sanitizeHtml(message)}</span>
        `;

        debugLog.appendChild(logEntry);
        debugLog.scrollTop = debugLog.scrollHeight;

        // Limit log entries to prevent memory issues
        const entries = debugLog.querySelectorAll('.log-entry');
        if (entries.length > 1000) {
            entries[0].remove();
        }
    }

    toggleDebugPanel() {
        const debugContent = document.getElementById('debug-content');
        const isVisible = debugContent.style.display !== 'none';
        debugContent.style.display = isVisible ? 'none' : 'block';
        
        const toggleButton = document.getElementById('toggle-debug');
        toggleButton.textContent = isVisible ? 'Show' : 'Hide';
    }

    clearDebugLog() {
        const debugLog = document.getElementById('debug-log');
        if (debugLog) {
            debugLog.innerHTML = '';
            this.addDebugLog('info', ['Debug log cleared.']);
        }
    }

    async copyDebugLog() {
        const debugLog = document.getElementById('debug-log');
        if (!debugLog) return;

        const logText = Array.from(debugLog.querySelectorAll('.log-entry'))
            .map(entry => entry.textContent)
            .join('\n');

        try {
            await navigator.clipboard.writeText(logText);
            this.showNotification('Debug log copied to clipboard', 'success');
        } catch (error) {
            this.showNotification('Failed to copy debug log', 'error');
        }
    }

    sanitizeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Security Results Helper Methods
    getSecurityScoreClass(score) {
        if (score >= 80) return 'excellent';
        if (score >= 60) return 'good';
        if (score >= 40) return 'fair';
        return 'poor';
    }

    formatSecurityFinding(finding) {
        return `
            <div class="security-finding ${finding.severity}">
                <div class="finding-header">
                    <span class="finding-title">${this.sanitizeHtml(finding.title)}</span>
                    <span class="finding-severity ${finding.severity}">${this.capitalizeFirst(finding.severity)}</span>
                </div>
                <div class="finding-content">
                    <p class="finding-description">${this.sanitizeHtml(finding.description)}</p>
                    <p class="finding-rationale"><strong>Why it matters:</strong> ${this.sanitizeHtml(finding.rationale)}</p>
                    <p class="finding-remediation"><strong>How to fix:</strong> ${this.sanitizeHtml(finding.remediation)}</p>
                    <div class="finding-details">
                        <span class="finding-resource">Resource: ${this.sanitizeHtml(finding.resourceId || 'Unknown')}</span>
                        <span class="finding-category">Category: ${this.sanitizeHtml(finding.category)}</span>
                        ${finding.compliance ? `<span class="finding-compliance">Compliance: ${finding.compliance.join(', ')}</span>` : ''}
                    </div>
                </div>
            </div>
        `;
    }

    formatRecommendations(recommendations) {
        let html = '';
        
        Object.entries(recommendations).forEach(([severity, recs]) => {
            if (recs.length > 0) {
                html += `<div class="recommendation-group ${severity}">`;
                html += `<h5 class="recommendation-severity ${severity}">${this.capitalizeFirst(severity)} Priority</h5>`;
                recs.forEach(rec => {
                    html += `
                        <div class="recommendation-item">
                            <div class="recommendation-title">${this.sanitizeHtml(rec.title)}</div>
                            <div class="recommendation-description">${this.sanitizeHtml(rec.description)}</div>
                            <div class="recommendation-action">${this.sanitizeHtml(rec.remediation)}</div>
                        </div>
                    `;
                });
                html += '</div>';
            }
        });
        
        return html;
    }

    displayResourceMapResults(provider, resourceMapReport) {
        const resultsContainer = document.getElementById('scan-results');
        const resourceMapResults = document.createElement('div');
        resourceMapResults.className = 'resource-map-results';
        resourceMapResults.id = `${provider}-resource-map-results`;

        const header = document.createElement('div');
        header.className = 'resource-map-header';
        header.innerHTML = `
            <h3>🗺️ Resource Map & Attack Surface Analysis</h3>
            <div class="resource-map-summary">
                <div class="resource-counts">
                    <span class="total-resources">${resourceMapReport.summary.totalResources} resources</span>
                    <span class="relationships">${resourceMapReport.summary.relationships} relationships</span>
                </div>
                <div class="attack-surface-summary">
                    <span class="public-resources">${resourceMapReport.summary.publicResources} public</span>
                    <span class="over-privileged">${resourceMapReport.summary.overPrivilegedResources} over-privileged</span>
                    <span class="escalation-paths">${resourceMapReport.summary.escalationPaths} escalation paths</span>
                </div>
            </div>
        `;

        resourceMapResults.appendChild(header);

        const content = document.createElement('div');
        content.className = 'resource-map-content';

        // Display resource types breakdown
        if (Object.keys(resourceMapReport.summary.resourceTypes).length > 0) {
            const resourceTypesDiv = document.createElement('div');
            resourceTypesDiv.className = 'resource-types-section';
            resourceTypesDiv.innerHTML = `
                <h4>📊 Resource Types</h4>
                <div class="resource-types-grid">
                    ${Object.entries(resourceMapReport.summary.resourceTypes).map(([type, count]) => `
                        <div class="resource-type-item">
                            <span class="resource-type-name">${type}</span>
                            <span class="resource-type-count">${count}</span>
                        </div>
                    `).join('')}
                </div>
            `;
            content.appendChild(resourceTypesDiv);
        }

        // Display attack surface analysis
        if (resourceMapReport.attackSurface.publicResources.length > 0 || 
            resourceMapReport.attackSurface.overPrivilegedResources.length > 0) {
            const attackSurfaceDiv = document.createElement('div');
            attackSurfaceDiv.className = 'attack-surface-section';
            attackSurfaceDiv.innerHTML = `
                <h4>🎯 Attack Surface Analysis</h4>
                ${this.formatAttackSurface(resourceMapReport.attackSurface)}
            `;
            content.appendChild(attackSurfaceDiv);
        }

        // Display permission escalation paths
        if (resourceMapReport.permissionPaths.escalationPaths.length > 0) {
            const escalationDiv = document.createElement('div');
            escalationDiv.className = 'escalation-paths-section';
            escalationDiv.innerHTML = `
                <h4>⚠️ Permission Escalation Paths</h4>
                ${this.formatEscalationPaths(resourceMapReport.permissionPaths.escalationPaths)}
            `;
            content.appendChild(escalationDiv);
        }

        // Display resource relationships
        if (Object.keys(resourceMapReport.relationships).length > 0) {
            const relationshipsDiv = document.createElement('div');
            relationshipsDiv.className = 'relationships-section';
            relationshipsDiv.innerHTML = `
                <h4>🔗 Resource Relationships</h4>
                ${this.formatRelationships(resourceMapReport.relationships)}
            `;
            content.appendChild(relationshipsDiv);
        }

        resourceMapResults.appendChild(content);
        
        // Remove existing resource map results for this provider
        const existing = document.getElementById(`${provider}-resource-map-results`);
        if (existing) {
            existing.remove();
        }
        
        resultsContainer.appendChild(resourceMapResults);
    }

    formatAttackSurface(attackSurface) {
        let html = '';

        if (attackSurface.publicResources.length > 0) {
            html += `
                <div class="attack-surface-group">
                    <h5 class="attack-surface-title critical">Publicly Accessible Resources (${attackSurface.publicResources.length})</h5>
                    <div class="attack-surface-list">
                        ${attackSurface.publicResources.map(resource => `
                            <div class="attack-surface-item critical">
                                <span class="resource-name">${this.sanitizeHtml(resource.name)}</span>
                                <span class="resource-type">${resource.type}</span>
                                <span class="exposure-level ${resource.exposure.toLowerCase()}">${resource.exposure}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        if (attackSurface.overPrivilegedResources.length > 0) {
            html += `
                <div class="attack-surface-group">
                    <h5 class="attack-surface-title high">Over-Privileged Resources (${attackSurface.overPrivilegedResources.length})</h5>
                    <div class="attack-surface-list">
                        ${attackSurface.overPrivilegedResources.map(resource => `
                            <div class="attack-surface-item high">
                                <span class="resource-name">${this.sanitizeHtml(resource.name)}</span>
                                <span class="resource-type">${resource.type}</span>
                                <span class="privilege-level">Over-Privileged</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        }

        return html;
    }

    formatEscalationPaths(escalationPaths) {
        return `
            <div class="escalation-paths-list">
                ${escalationPaths.map(path => `
                    <div class="escalation-path-item ${path.severity.toLowerCase()}">
                        <div class="escalation-path-header">
                            <span class="escalation-source">${this.sanitizeHtml(path.source)}</span>
                            <span class="escalation-severity ${path.severity.toLowerCase()}">${path.severity}</span>
                        </div>
                        <div class="escalation-path-steps">
                            ${path.path.map(step => `
                                <div class="escalation-step">
                                    <span class="step-resource">${this.sanitizeHtml(step.resource)}</span>
                                    <span class="step-permissions">${step.permissions.length} elevated permissions</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    formatRelationships(relationships) {
        const relationshipGroups = {};
        
        Object.entries(relationships).forEach(([sourceId, rels]) => {
            rels.forEach(rel => {
                if (!relationshipGroups[rel.type]) {
                    relationshipGroups[rel.type] = [];
                }
                relationshipGroups[rel.type].push({
                    source: sourceId,
                    target: rel.target
                });
            });
        });

        return `
            <div class="relationships-list">
                ${Object.entries(relationshipGroups).map(([type, rels]) => `
                    <div class="relationship-group">
                        <h6 class="relationship-type">${this.formatRelationshipType(type)} (${rels.length})</h6>
                        <div class="relationship-items">
                            ${rels.slice(0, 10).map(rel => `
                                <div class="relationship-item">
                                    <span class="source-resource">${this.sanitizeHtml(rel.source)}</span>
                                    <span class="relationship-arrow">→</span>
                                    <span class="target-resource">${this.sanitizeHtml(rel.target)}</span>
                                </div>
                            `).join('')}
                            ${rels.length > 10 ? `<div class="relationship-more">... and ${rels.length - 10} more</div>` : ''}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    formatRelationshipType(type) {
        const typeMap = {
            'uses-iam-role': 'Uses IAM Role',
            'uses-security-group': 'Uses Security Group',
            'in-vpc': 'In VPC',
            'uses-service-account': 'Uses Service Account',
            'in-vnet': 'In Virtual Network'
        };
        return typeMap[type] || type;
    }

    displayEnhancedAnalysisResults(provider, enhancedAnalysis) {
        const resultsContainer = document.getElementById('scan-results');
        const enhancedResults = document.createElement('div');
        enhancedResults.className = 'enhanced-analysis-results';
        enhancedResults.id = `${provider}-enhanced-analysis-results`;

        const header = document.createElement('div');
        header.className = 'enhanced-analysis-header';
        header.innerHTML = `
            <h3>🔍 Enhanced Resource Analysis</h3>
            <div class="enhanced-analysis-summary">
                <div class="security-posture">
                    <span class="posture-label">Security Posture:</span>
                    <span class="posture-score ${this.getSecurityScoreClass(enhancedAnalysis.securityPosture.overallScore)}">${enhancedAnalysis.securityPosture.overallScore}/100</span>
                </div>
                <div class="resource-breakdown">
                    <span class="total-resources">${Object.keys(enhancedAnalysis.resources).length} resources analyzed</span>
                    <span class="risk-distribution">
                        ${Object.entries(enhancedAnalysis.securityPosture.riskDistribution).map(([risk, count]) => 
                            count > 0 ? `${count} ${risk}` : ''
                        ).filter(Boolean).join(', ')}
                    </span>
                </div>
            </div>
        `;

        enhancedResults.appendChild(header);

        const content = document.createElement('div');
        content.className = 'enhanced-analysis-content';

        // Display security posture overview
        const postureDiv = document.createElement('div');
        postureDiv.className = 'security-posture-section';
        postureDiv.innerHTML = `
            <h4>📊 Security Posture Overview</h4>
            <div class="posture-details">
                <div class="posture-metrics">
                    <div class="metric">
                        <span class="metric-label">Overall Score:</span>
                        <span class="metric-value ${this.getSecurityScoreClass(enhancedAnalysis.securityPosture.overallScore)}">${enhancedAnalysis.securityPosture.overallScore}/100</span>
                    </div>
                    <div class="metric">
                        <span class="metric-label">Average Score:</span>
                        <span class="metric-value">${enhancedAnalysis.securityPosture.averageScore}/100</span>
                    </div>
                </div>
                <div class="risk-breakdown">
                    ${Object.entries(enhancedAnalysis.securityPosture.riskDistribution).map(([risk, count]) => `
                        <div class="risk-item ${risk}">
                            <span class="risk-label">${this.capitalizeFirst(risk)}</span>
                            <span class="risk-count">${count}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        content.appendChild(postureDiv);

        // Display detailed resource analysis
        const resourcesDiv = document.createElement('div');
        resourcesDiv.className = 'detailed-resources-section';
        resourcesDiv.innerHTML = `
            <h4>🔍 Detailed Resource Analysis</h4>
            <div class="resource-analysis-grid">
                ${Object.values(enhancedAnalysis.resources).map(resource => this.formatDetailedResource(resource)).join('')}
            </div>
        `;
        content.appendChild(resourcesDiv);

        // Display recommendations
        if (Object.values(enhancedAnalysis.recommendations).some(recs => recs.length > 0)) {
            const recommendationsDiv = document.createElement('div');
            recommendationsDiv.className = 'enhanced-recommendations-section';
            recommendationsDiv.innerHTML = `
                <h4>💡 Enhanced Recommendations</h4>
                ${this.formatEnhancedRecommendations(enhancedAnalysis.recommendations)}
            `;
            content.appendChild(recommendationsDiv);
        }

        enhancedResults.appendChild(content);
        
        // Remove existing enhanced analysis results for this provider
        const existing = document.getElementById(`${provider}-enhanced-analysis-results`);
        if (existing) {
            existing.remove();
        }
        
        resultsContainer.appendChild(enhancedResults);
    }

    formatDetailedResource(resource) {
        const findings = resource.analysis.findings || [];
        const findingsHtml = findings.length > 0 ? `
            <div class="resource-findings">
                ${findings.map(finding => `
                    <div class="finding-item ${finding.severity}">
                        <span class="finding-title">${this.sanitizeHtml(finding.title)}</span>
                        <span class="finding-category">${finding.category}</span>
                    </div>
                `).join('')}
            </div>
        ` : '<div class="no-findings">No security findings</div>';

        return `
            <div class="resource-analysis-item ${resource.riskLevel}">
                <div class="resource-header">
                    <span class="resource-icon">${this.getResourceIcon(resource.type)}</span>
                    <span class="resource-name">${this.sanitizeHtml(resource.name)}</span>
                    <span class="resource-type">${resource.type}</span>
                    <div class="resource-scores">
                        <span class="security-score ${this.getSecurityScoreClass(resource.securityScore)}">${resource.securityScore}/100</span>
                        <span class="risk-level ${resource.riskLevel}">${this.capitalizeFirst(resource.riskLevel)}</span>
                    </div>
                </div>
                <div class="resource-details">
                    ${this.formatResourceAnalysis(resource.analysis)}
                </div>
                ${findingsHtml}
            </div>
        `;
    }

    formatResourceAnalysis(analysis) {
        let html = '<div class="analysis-details">';
        
        // Format based on resource type
        if (analysis.encryption) {
            html += `
                <div class="analysis-section">
                    <h6>Encryption</h6>
                    <div class="analysis-item">
                        <span class="label">Enabled:</span>
                        <span class="value ${analysis.encryption.enabled ? 'success' : 'error'}">${analysis.encryption.enabled ? 'Yes' : 'No'}</span>
                    </div>
                    ${analysis.encryption.algorithm ? `
                        <div class="analysis-item">
                            <span class="label">Algorithm:</span>
                            <span class="value">${analysis.encryption.algorithm}</span>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        if (analysis.network) {
            html += `
                <div class="analysis-section">
                    <h6>Network</h6>
                    ${analysis.network.publicIp ? `
                        <div class="analysis-item">
                            <span class="label">Public IP:</span>
                            <span class="value">${analysis.network.publicIp}</span>
                        </div>
                    ` : ''}
                    ${analysis.network.hasPublicIp !== undefined ? `
                        <div class="analysis-item">
                            <span class="label">Has Public IP:</span>
                            <span class="value ${analysis.network.hasPublicIp ? 'error' : 'success'}">${analysis.network.hasPublicIp ? 'Yes' : 'No'}</span>
                        </div>
                    ` : ''}
                </div>
            `;
        }

        if (analysis.access) {
            html += `
                <div class="analysis-section">
                    <h6>Access Control</h6>
                    ${Object.entries(analysis.access).map(([key, value]) => `
                        <div class="analysis-item">
                            <span class="label">${this.formatLabel(key)}:</span>
                            <span class="value ${typeof value === 'boolean' ? (value ? 'error' : 'success') : ''}">${typeof value === 'boolean' ? (value ? 'Yes' : 'No') : value}</span>
                        </div>
                    `).join('')}
                </div>
            `;
        }

        html += '</div>';
        return html;
    }

    formatEnhancedRecommendations(recommendations) {
        let html = '';
        
        Object.entries(recommendations).forEach(([severity, recs]) => {
            if (recs.length > 0) {
                html += `
                    <div class="recommendation-group ${severity}">
                        <h5 class="recommendation-severity ${severity}">${this.capitalizeFirst(severity)} Priority (${recs.length})</h5>
                        <div class="recommendation-items">
                            ${recs.map(rec => `
                                <div class="recommendation-item">
                                    <div class="rec-resource">
                                        <span class="rec-resource-name">${this.sanitizeHtml(rec.resource)}</span>
                                        <span class="rec-resource-type">${rec.type}</span>
                                    </div>
                                    <div class="rec-finding">
                                        <div class="rec-finding-title">${this.sanitizeHtml(rec.finding.title)}</div>
                                        <div class="rec-finding-description">${this.sanitizeHtml(rec.finding.description)}</div>
                                        <div class="rec-finding-remediation">${this.sanitizeHtml(rec.finding.remediation)}</div>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
        });
        
        return html;
    }

    getResourceIcon(type) {
        const icons = {
            'S3 Bucket': '🪣',
            'EC2 Instance': '🖥️',
            'IAM User': '👤',
            'IAM Role': '🔑',
            'RDS Instance': '🗄️',
            'Virtual Machine': '🖥️',
            'Storage Account': '💾',
            'Compute Instance': '🖥️',
            'Cloud Storage Bucket': '🪣'
        };
        return icons[type] || '🔍';
    }

    formatLabel(key) {
        return key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase());
    }
}

// Initialize the application when the page loads
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new PeekInTheCloud();
}); 