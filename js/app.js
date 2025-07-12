/**
 * PeekInTheCloud - Main Application
 * Comprehensive cloud service enumeration tool
 */

class PeekInTheCloud {
    constructor() {
        this.currentProvider = null;
        this.scanners = {};
        this.results = {};
        this.isScanning = false;
        this.selectedServices = new Set();
        
        this.initialize();
    }

    initialize() {
        this.setupEventListeners();
        this.loadSavedCredentials();
        this.setupServiceGrid();
        this.updateUI();
        this.setupDebugConsole();
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
            this.updateUI();
            this.showNotification(`Starting ${provider.toUpperCase()} scan...`, 'info');

            // Validate credentials
            console.log(`[${scanId}] 🔐 Validating credentials...`);
            if (!this.validateCredentials(provider, credentials)) {
                console.error(`[${scanId}] ❌ Credential validation failed`);
                this.showNotification('Invalid credentials provided', 'error');
                return;
            }
            console.log(`[${scanId}] ✅ Credentials validated successfully`);

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

            // Get selected services or all services
            const servicesToScan = this.selectedServices.size > 0 
                ? Array.from(this.selectedServices)
                : null;

            console.log(`[${scanId}] 📋 Services to scan:`, {
                selected: servicesToScan ? servicesToScan.length : 'ALL',
                services: servicesToScan || 'All available services'
            });

            // Perform scan
            console.log(`[${scanId}] 🔍 Beginning service enumeration...`);
            const results = await scanner.scan(credentials, servicesToScan);
            
            const scanDuration = Date.now() - scanStartTime;
            console.log(`[${scanId}] ✅ Scan completed successfully!`, {
                duration: Utils.DataUtils.formatDuration(scanDuration),
                servicesScanned: Object.keys(results).length,
                successfulServices: Object.values(results).filter(r => !r.error).length,
                failedServices: Object.values(results).filter(r => r.error).length
            });
            
            this.results[provider] = results;
            this.displayResults(provider, results);
            
            this.showNotification(`${provider.toUpperCase()} scan completed successfully!`, 'success');
            
        } catch (error) {
            const scanDuration = Date.now() - scanStartTime;
            console.error(`[${scanId}] ❌ Scan failed after ${Utils.DataUtils.formatDuration(scanDuration)}:`, error);
            console.error(`[${scanId}] Error details:`, {
                name: error.name,
                message: error.message,
                stack: error.stack,
                provider: provider
            });
            this.showNotification(`Scan failed: ${error.message}`, 'error');
        } finally {
            this.isScanning = false;
            this.updateUI();
            console.log(`[${scanId}] 🏁 Scan session ended`);
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

        providerResults.appendChild(resultsContent);
        
        // Remove existing results for this provider
        const existing = document.getElementById(`${provider}-results`);
        if (existing) {
            existing.remove();
        }
        
        resultsContainer.appendChild(providerResults);
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
}

// Initialize the application when the page loads
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new PeekInTheCloud();
}); 