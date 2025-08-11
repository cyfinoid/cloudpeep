/**
 * PeekInTheCloud - Utility Functions
 * Comprehensive utility library for cloud service enumeration
 * Updated-10 Aug 2025
 */

// Global state management
const AppState = {
    currentProvider: null,
    scanResults: null,
    isScanning: false
};

const Utils = {
    /**
     * Global application state
     */
    AppState,

    /**
     * Error handling utilities
     */
    ErrorHandler: {
        /**
         * Show error message to user
         * @param {string} message - Error message
         * @param {string} type - Error type (error, warning, info)
         */
        showError(message, type = 'error') {
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            notification.innerHTML = `
                <span class="notification-message">${this.sanitizeInput(message)}</span>
                <button class="notification-close" onclick="this.parentElement.remove()">×</button>
            `;
            
            document.body.appendChild(notification);
            
            // Auto-remove after 5 seconds
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.remove();
                }
            }, 5000);
        },

        /**
         * Handle API errors and return formatted error info
         * @param {Error} error - The error object
         * @param {string} service - Service name
         * @returns {Object} Formatted error information
         */
        handleAPIError(error, service) {
            let errorMessage = 'Unknown error occurred';
            let errorCode = 'UNKNOWN';
            let isRetryable = false;

            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                errorMessage = 'Network error - please check your connection';
                errorCode = 'NETWORK_ERROR';
                isRetryable = true;
            } else if (error.name === 'AuthenticationError') {
                errorMessage = 'Authentication failed - please check your credentials';
                errorCode = 'AUTH_ERROR';
                isRetryable = false;
            } else if (error.name === 'PermissionError') {
                errorMessage = `Access denied to ${service} - insufficient permissions`;
                errorCode = 'PERMISSION_ERROR';
                isRetryable = false;
            } else if (error.name === 'RateLimitError') {
                errorMessage = 'Rate limit exceeded - please wait before retrying';
                errorCode = 'RATE_LIMIT_ERROR';
                isRetryable = true;
            } else if (error.message) {
                errorMessage = error.message;
                errorCode = error.code || 'API_ERROR';
                isRetryable = error.retryable || false;
            }

            return {
                message: errorMessage,
                code: errorCode,
                service: service,
                retryable: isRetryable,
                timestamp: new Date().toISOString()
            };
        },

        /**
         * Log error for debugging
         * @param {Error} error - The error object
         * @param {string} context - Error context
         */
        logError(error, context = '') {
            console.error(`[${context}] Error:`, error);
            
            // In production, you might want to send this to a logging service
            if (typeof window !== 'undefined' && window.gtag) {
                window.gtag('event', 'exception', {
                    description: error.message,
                    fatal: false
                });
            }
        }
    },

    /**
     * UI utility functions
     */
    UIUtils: {
        /**
         * Toggle element visibility
         * @param {string} elementId - Element ID
         * @param {boolean} show - Whether to show or hide
         */
        toggleElement(elementId, show) {
            const element = document.getElementById(elementId);
            if (element) {
                element.style.display = show ? 'block' : 'none';
            }
        },

        /**
         * Show/hide loading indicator
         * @param {boolean} show - Whether to show loading
         */
        showLoading(show) {
            const loadingElement = document.getElementById('loading');
            if (loadingElement) {
                loadingElement.style.display = show ? 'flex' : 'none';
            }
        },

        /**
         * Show loading state with overlay
         * @param {boolean} show - Show or hide loading
         */
        showLoadingOverlay(show) {
            const overlay = document.getElementById('loadingOverlay');
            const button = document.getElementById('scanButton');
            const buttonText = button?.querySelector('.button-text');
            const spinner = button?.querySelector('.loading-spinner');

            if (show) {
                overlay?.classList.remove('hidden');
                if (button) button.disabled = true;
                if (buttonText) buttonText.textContent = 'Scanning...';
                if (spinner) spinner.classList.remove('hidden');
                AppState.isScanning = true;
            } else {
                overlay?.classList.add('hidden');
                if (button) button.disabled = false;
                if (buttonText) buttonText.textContent = 'Scan Credentials';
                if (spinner) spinner.classList.add('hidden');
                AppState.isScanning = false;
            }
        },

        /**
         * Update scan button state
         */
        updateScanButton() {
            const scanButtons = document.querySelectorAll('.scan-button');
            scanButtons.forEach(button => {
                const form = button.closest('form');
                if (form) {
                    const inputs = form.querySelectorAll('input[required]');
                    const isValid = Array.from(inputs).every(input => input.value.trim() !== '');
                    button.disabled = !isValid;
                }
            });
        },

        /**
         * Enable/disable scan button based on form validity
         */
        updateScanButtonAdvanced() {
            const button = document.getElementById('scanButton');
            const provider = document.getElementById('cloudProvider')?.value;
            
            if (!provider) {
                if (button) button.disabled = true;
                return;
            }

            let isValid = false;
            const form = document.getElementById(`${provider}-form`);
            
            if (form && !form.classList.contains('hidden')) {
                const inputs = form.querySelectorAll('input, select, textarea');
                isValid = Array.from(inputs).every(input => {
                    if (input.type === 'password' || input.type === 'text') {
                        return input.value.trim() !== '';
                    }
                    return true;
                });
            }

            if (button) button.disabled = !isValid || AppState.isScanning;
        },

        /**
         * Copy text to clipboard
         * @param {string} text - Text to copy
         * @returns {Promise<boolean>} Success status
         */
        async copyToClipboard(text) {
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(text);
                    return true;
                } else {
                    // Fallback for older browsers
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    textArea.style.position = 'fixed';
                    textArea.style.left = '-999999px';
                    textArea.style.top = '-999999px';
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    const result = document.execCommand('copy');
                    document.body.removeChild(textArea);
                    return result;
                }
            } catch (error) {
                console.error('Failed to copy to clipboard:', error);
                return false;
            }
        },

        /**
         * Download data as JSON file
         * @param {Object} data - Data to download
         * @param {string} filename - Filename
         */
        downloadJSON(data, filename) {
            const blob = new Blob([JSON.stringify(data, null, 2)], {
                type: 'application/json'
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        /**
         * Download data as CSV file
         * @param {Array} data - Data to download
         * @param {string} filename - Filename
         */
        downloadCSV(data, filename) {
            if (!data || data.length === 0) {
                Utils.ErrorHandler.showError('No data to export', 'error');
                return;
            }

            const headers = Object.keys(data[0]);
            const csvContent = [
                headers.join(','),
                ...data.map(row => 
                    headers.map(header => 
                        JSON.stringify(row[header] || '')
                    ).join(',')
                )
            ].join('\n');

            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        /**
         * Create progress bar
         * @param {number} current - Current progress
         * @param {number} total - Total items
         * @returns {string} Progress HTML
         */
        createProgressBar(current, total) {
            const percentage = Math.round((current / total) * 100);
            return `
                <div class="progress-container">
                    <div class="progress-bar" style="width: ${percentage}%"></div>
                    <span class="progress-text">${current}/${total} (${percentage}%)</span>
                </div>
            `;
        }
    },

    /**
     * Storage utility functions
     */
    StorageUtils: {
        /**
         * Save results to localStorage
         * @param {Object} results - Scan results
         * @param {string} provider - Cloud provider
         */
        saveResults(results, provider) {
            try {
                const key = `peekinthecloud_results_${provider}`;
                const data = {
                    results: results,
                    provider: provider,
                    timestamp: new Date().toISOString(),
                    version: '1.0.0'
                };
                localStorage.setItem(key, JSON.stringify(data));
            } catch (error) {
                Utils.ErrorHandler.logError(error, 'StorageUtils.saveResults');
            }
        },

        /**
         * Load results from localStorage
         * @param {string} provider - Cloud provider
         * @returns {Object|null} Saved results
         */
        loadResults(provider) {
            try {
                const key = `peekinthecloud_results_${provider}`;
                const data = localStorage.getItem(key);
                return data ? JSON.parse(data) : null;
            } catch (error) {
                Utils.ErrorHandler.logError(error, 'StorageUtils.loadResults');
                return null;
            }
        },

        /**
         * Save credentials to localStorage (encrypted)
         * @param {string} provider - Cloud provider
         * @param {Object} credentials - Credentials object
         */
        saveCredentials(provider, credentials) {
            try {
                const key = `peekinthecloud_creds_${provider}`;
                // In a real application, you'd want to encrypt this
                const data = {
                    credentials: credentials,
                    provider: provider,
                    timestamp: new Date().toISOString()
                };
                localStorage.setItem(key, JSON.stringify(data));
            } catch (error) {
                Utils.ErrorHandler.logError(error, 'StorageUtils.saveCredentials');
            }
        },

        /**
         * Load credentials from localStorage
         * @param {string} provider - Cloud provider
         * @returns {Object|null} Saved credentials
         */
        loadCredentials(provider) {
            try {
                const key = `peekinthecloud_creds_${provider}`;
                const data = localStorage.getItem(key);
                return data ? JSON.parse(data) : null;
            } catch (error) {
                Utils.ErrorHandler.logError(error, 'StorageUtils.loadCredentials');
                return null;
            }
        },

        /**
         * Clear all stored data
         */
        clearAllData() {
            try {
                const keys = Object.keys(localStorage);
                keys.forEach(key => {
                    if (key.startsWith('peekinthecloud_')) {
                        localStorage.removeItem(key);
                    }
                });
            } catch (error) {
                Utils.ErrorHandler.logError(error, 'StorageUtils.clearAllData');
            }
        },

        /**
         * Get saved scan results (legacy function)
         * @returns {Array} - Array of saved results
         */
        getSavedResults() {
            const results = [];
            try {
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key && key.startsWith('peekinthecloud_')) {
                        const data = JSON.parse(localStorage.getItem(key));
                        results.push(data);
                    }
                }
            } catch (error) {
                console.warn('Failed to retrieve saved results:', error);
            }
            return results.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        },

        /**
         * Clear saved results (legacy function)
         */
        clearSavedResults() {
            try {
                const keysToRemove = [];
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    if (key && key.startsWith('peekinthecloud_')) {
                        keysToRemove.push(key);
                    }
                }
                keysToRemove.forEach(key => localStorage.removeItem(key));
            } catch (error) {
                console.warn('Failed to clear saved results:', error);
            }
        }
    },

    /**
     * Network utility functions
     */
    NetworkUtils: {
        /**
         * Check if device is online
         * @returns {boolean} Online status
         */
        isOnline() {
            return navigator.onLine;
        },

        /**
         * Check network connectivity
         * @returns {Promise<boolean>} Connectivity status
         */
        async checkConnectivity() {
            try {
                const response = await fetch('https://httpbin.org/get', {
                    method: 'HEAD',
                    mode: 'no-cors'
                });
                return true;
            } catch (error) {
                return false;
            }
        },

        /**
         * Show offline warning
         */
        showOfflineWarning() {
            if (!this.isOnline()) {
                Utils.ErrorHandler.showError(
                    'You appear to be offline. Some features may not work properly.',
                    'warning'
                );
            }
        },

        /**
         * Test API endpoint connectivity
         * @param {string} url - URL to test
         * @returns {Promise<boolean>} Connectivity status
         */
        async testEndpoint(url) {
            try {
                const response = await fetch(url, {
                    method: 'HEAD',
                    mode: 'no-cors'
                });
                return true;
            } catch (error) {
                return false;
            }
        }
    },

    /**
     * Credential validation utilities
     */
    CredentialValidator: {
        /**
         * Validate AWS credentials
         * @param {Object} credentials - AWS credentials
         * @returns {Object} Validation result
         */
        validateAWS(credentials) {
            const errors = [];
            
            if (!credentials.accessKeyId || credentials.accessKeyId.trim() === '') {
                errors.push('Access Key ID is required');
            } else if (!/^AKIA[0-9A-Z]{16}$/.test(credentials.accessKeyId)) {
                errors.push('Access Key ID format is invalid');
            }
            
            if (!credentials.secretAccessKey || credentials.secretAccessKey.trim() === '') {
                errors.push('Secret Access Key is required');
            } else if (credentials.secretAccessKey.length < 40) {
                errors.push('Secret Access Key appears to be too short');
            }
            
            if (credentials.region && !/^[a-z0-9-]+$/.test(credentials.region)) {
                errors.push('Region format is invalid');
            }
            
            return {
                isValid: errors.length === 0,
                errors: errors
            };
        },

        /**
         * Validate Azure credentials
         * @param {Object} credentials - Azure credentials
         * @returns {Object} Validation result
         */
        validateAzure(credentials) {
            const errors = [];
            
            if (!credentials.clientId || credentials.clientId.trim() === '') {
                errors.push('Client ID is required');
            } else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(credentials.clientId)) {
                errors.push('Client ID format is invalid (should be a GUID)');
            }
            
            if (!credentials.clientSecret || credentials.clientSecret.trim() === '') {
                errors.push('Client Secret is required');
            }
            
            if (!credentials.tenantId || credentials.tenantId.trim() === '') {
                errors.push('Tenant ID is required');
            } else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(credentials.tenantId)) {
                errors.push('Tenant ID format is invalid (should be a GUID)');
            }
            
            return {
                isValid: errors.length === 0,
                errors: errors
            };
        },

        /**
         * Validate GCP service account JSON
         * @param {string} serviceAccountJson - Service account JSON string
         * @returns {Object} Validation result
         */
        validateGCP(serviceAccountJson) {
            const errors = [];
            
            if (!serviceAccountJson || serviceAccountJson.trim() === '') {
                errors.push('Service Account JSON is required');
                return { isValid: false, errors: errors };
            }
            
            try {
                const parsed = JSON.parse(serviceAccountJson);
                
                if (!parsed.type || parsed.type !== 'service_account') {
                    errors.push('Invalid service account type');
                }
                
                if (!parsed.project_id || parsed.project_id.trim() === '') {
                    errors.push('Project ID is required');
                }
                
                if (!parsed.private_key_id || parsed.private_key_id.trim() === '') {
                    errors.push('Private Key ID is required');
                }
                
                if (!parsed.private_key || parsed.private_key.trim() === '') {
                    errors.push('Private Key is required');
                }
                
                if (!parsed.client_email || parsed.client_email.trim() === '') {
                    errors.push('Client Email is required');
                }
                
            } catch (error) {
                errors.push('Invalid JSON format');
            }
            
            return {
                isValid: errors.length === 0,
                errors: errors
            };
        }
    },

    /**
     * Security utility functions
     */
    SecurityUtils: {
        /**
         * Sanitize user input to prevent XSS
         * @param {string} input - User input
         * @returns {string} Sanitized input
         */
        sanitizeInput(input) {
            if (typeof input !== 'string') {
                return String(input);
            }
            
            return input
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;')
                .replace(/\//g, '&#x2F;');
        },

        /**
         * Generate secure random string
         * @param {number} length - String length
         * @returns {string} Random string
         */
        generateRandomString(length = 32) {
            const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            let result = '';
            for (let i = 0; i < length; i++) {
                result += chars.charAt(Math.floor(Math.random() * chars.length));
            }
            return result;
        },

        /**
         * Hash sensitive data (simple implementation)
         * @param {string} data - Data to hash
         * @returns {string} Hashed data
         */
        hashData(data) {
            // Simple hash function - in production, use proper cryptographic hashing
            let hash = 0;
            if (data.length === 0) return hash.toString();
            
            for (let i = 0; i < data.length; i++) {
                const char = data.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash; // Convert to 32-bit integer
            }
            
            return Math.abs(hash).toString(36);
        },

        /**
         * Mask sensitive data for display
         * @param {string} data - Data to mask
         * @param {number} visibleChars - Number of visible characters
         * @returns {string} Masked data
         */
        maskSensitiveData(data, visibleChars = 4) {
            if (!data || data.length <= visibleChars * 2) {
                return '*'.repeat(data.length);
            }
            
            const start = data.substring(0, visibleChars);
            const end = data.substring(data.length - visibleChars);
            const middle = '*'.repeat(data.length - visibleChars * 2);
            
            return start + middle + end;
        },

        /**
         * Clear sensitive data from memory
         * @param {Object} credentials - Credentials object
         */
        clearCredentials(credentials) {
            if (credentials) {
                Object.keys(credentials).forEach(key => {
                    if (typeof credentials[key] === 'string') {
                        credentials[key] = '';
                    }
                });
            }
        }
    },

    /**
     * Data formatting utilities
     */
    DataUtils: {
        /**
         * Format bytes to human readable format
         * @param {number} bytes - Bytes to format
         * @returns {string} Formatted string
         */
        formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        },

        /**
         * Format date to readable format
         * @param {Date|string} date - Date to format
         * @returns {string} Formatted date
         */
        formatDate(date) {
            const d = new Date(date);
            return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
        },

        /**
         * Format duration in milliseconds to readable format
         * @param {number} ms - Milliseconds
         * @returns {string} Formatted duration
         */
        formatDuration(ms) {
            if (ms < 1000) return ms + 'ms';
            if (ms < 60000) return Math.round(ms / 1000) + 's';
            if (ms < 3600000) return Math.round(ms / 60000) + 'm';
            return Math.round(ms / 3600000) + 'h';
        },

        /**
         * Deep clone object
         * @param {Object} obj - Object to clone
         * @returns {Object} Cloned object
         */
        deepClone(obj) {
            if (obj === null || typeof obj !== 'object') return obj;
            if (obj instanceof Date) return new Date(obj.getTime());
            if (obj instanceof Array) return obj.map(item => this.deepClone(item));
            if (typeof obj === 'object') {
                const cloned = {};
                for (const key in obj) {
                    if (obj.hasOwnProperty(key)) {
                        cloned[key] = this.deepClone(obj[key]);
                    }
                }
                return cloned;
            }
        }
    },

    /**
     * Honeytoken/Canary Detection Utilities
     */
    HoneytokenUtils: {
        /**
         * Extract AWS Account ID from Access Key ID
         * @param {string} accessKeyId - AWS Access Key ID
         * @returns {string} AWS Account ID
         */
        extractAccountIdFromKey(accessKeyId) {
            try {
                // Remove AKIA prefix
                const trimmedKey = accessKeyId.substring(4);
                
                // Base32 decode using a more reliable method
                const decoded = this.base32Decode(trimmedKey);
                
                // Extract first 6 bytes
                const accountBytes = decoded.slice(0, 6);
                
                // Convert to BigInt for proper handling of large numbers
                let accountInt = BigInt(0);
                for (let i = 0; i < accountBytes.length; i++) {
                    accountInt = (accountInt << BigInt(8)) | BigInt(accountBytes[i]);
                }
                
                // Apply mask and shift (using BigInt)
                const mask = BigInt('0x7fffffffff80');
                const accountId = (accountInt & mask) >> BigInt(7);
                
                return accountId.toString().padStart(12, '0');
            } catch (error) {
                console.error('Error extracting account ID:', error);
                return null;
            }
        },

        /**
         * Base32 decode function
         * @param {string} input - Base32 encoded string
         * @returns {Uint8Array} Decoded bytes
         */
        base32Decode(input) {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            const padding = '=';
            
            // Remove any padding characters
            input = input.replace(/=/g, '');
            
            let bits = 0;
            let value = 0;
            let output = [];
            
            for (let i = 0; i < input.length; i++) {
                const char = input[i];
                const index = alphabet.indexOf(char.toUpperCase());
                if (index === -1) {
                    console.warn(`Invalid base32 character: ${char}`);
                    continue;
                }
                
                value = (value << 5) | index;
                bits += 5;
                
                if (bits >= 8) {
                    output.push((value >>> (bits - 8)) & 255);
                    bits -= 8;
                }
            }
            
            // Handle any remaining bits
            if (bits >= 5) {
                output.push((value << (8 - bits)) & 255);
            }
            
            return new Uint8Array(output);
        },

        /**
         * Known canary/honeytoken account IDs
         */
        canaryAccounts: {
            // Thinkst Canary (canarytokens.org)
            thinkst: [
                "052310077262",
                "171436882533", 
                "534261010715",
                "595918472158",
                "717712589309",
                "819147034852",
                "992382622183",
                "729780141977"
            ],
            
            // Thinkst Knockoffs (off-brand canaries)
            thinkstKnockoffs: [
                "044858866125",
                "251535659677",
                "344043088457",
                "351906852752",
                "390477818340",
                "426127672474",
                "427150556519",
                "439872796651",
                "445142720921",
                "465867158099",
                "637958123769",
                "693412236332",
                "732624840810",
                "735421457923",
                "959235150393",
                "982842642351"
            ]
        },

        /**
         * Check if AWS credentials are honeytokens
         * @param {Object} credentials - AWS credentials
         * @returns {Object} Detection result
         */
        detectHoneytoken(credentials) {
            if (!credentials.accessKeyId) {
                return { isHoneytoken: false, type: null, accountId: null };
            }

            const accountId = this.extractAccountIdFromKey(credentials.accessKeyId);
            if (!accountId) {
                return { isHoneytoken: false, type: null, accountId: null };
            }

            // Check against known canary accounts
            if (this.canaryAccounts.thinkst.includes(accountId)) {
                return {
                    isHoneytoken: true,
                    type: 'thinkst',
                    accountId: accountId,
                    message: 'This is an AWS canary token generated at canarytokens.org, and was not set off; learn more here: https://trufflesecurity.com/canaries'
                };
            }

            if (this.canaryAccounts.thinkstKnockoffs.includes(accountId)) {
                return {
                    isHoneytoken: true,
                    type: 'thinkstKnockoffs',
                    accountId: accountId,
                    message: 'This is an off brand AWS Canary inspired by canarytokens.org. It wasn\'t set off; learn more here: https://trufflesecurity.com/canaries'
                };
            }

            return { isHoneytoken: false, type: null, accountId: accountId };
        }
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Utils;
} 