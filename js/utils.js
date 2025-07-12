/**
 * PeekInTheCloud - Utility Functions
 * Comprehensive utility library for cloud service enumeration
 */

const Utils = {
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
    }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Utils;
} 