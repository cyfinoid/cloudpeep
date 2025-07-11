/**
 * Utility functions for PeekInTheCloud
 */

// Global state
const AppState = {
    currentProvider: null,
    scanResults: null,
    isScanning: false
};

/**
 * Credential validation functions
 */
const CredentialValidator = {
    /**
     * Validate AWS credentials
     * @param {Object} credentials - AWS credentials object
     * @returns {Object} - Validation result
     */
    validateAWS(credentials) {
        const { accessKeyId, secretAccessKey, sessionToken, region } = credentials;
        const errors = [];

        if (!accessKeyId || accessKeyId.trim() === '') {
            errors.push('Access Key ID is required');
        } else if (!accessKeyId.startsWith('AKIA') && !accessKeyId.startsWith('ASIA')) {
            errors.push('Access Key ID should start with AKIA or ASIA');
        }

        if (!secretAccessKey || secretAccessKey.trim() === '') {
            errors.push('Secret Access Key is required');
        }

        if (!region || region.trim() === '') {
            errors.push('Region is required');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    },

    /**
     * Validate Azure credentials
     * @param {Object} credentials - Azure credentials object
     * @returns {Object} - Validation result
     */
    validateAzure(credentials) {
        const { clientId, clientSecret, tenantId } = credentials;
        const errors = [];

        if (!clientId || clientId.trim() === '') {
            errors.push('Client ID is required');
        }

        if (!clientSecret || clientSecret.trim() === '') {
            errors.push('Client Secret is required');
        }

        if (!tenantId || tenantId.trim() === '') {
            errors.push('Tenant ID is required');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    },

    /**
     * Validate GCP service account JSON
     * @param {string} serviceAccountJson - GCP service account JSON string
     * @returns {Object} - Validation result
     */
    validateGCP(serviceAccountJson) {
        const errors = [];

        if (!serviceAccountJson || serviceAccountJson.trim() === '') {
            errors.push('Service Account JSON is required');
            return { isValid: false, errors };
        }

        try {
            const parsed = JSON.parse(serviceAccountJson);
            const requiredFields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email'];
            
            for (const field of requiredFields) {
                if (!parsed[field]) {
                    errors.push(`Missing required field: ${field}`);
                }
            }

            if (parsed.type !== 'service_account') {
                errors.push('Invalid service account type');
            }

        } catch (error) {
            errors.push('Invalid JSON format');
        }

        return {
            isValid: errors.length === 0,
            errors
        };
    }
};

/**
 * Error handling utilities
 */
const ErrorHandler = {
    /**
     * Show error message to user
     * @param {string} message - Error message
     * @param {string} type - Error type (error, warning, info)
     */
    showError(message, type = 'error') {
        // Create error notification
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span class="notification-message">${message}</span>
                <button class="notification-close">&times;</button>
            </div>
        `;

        // Add to page
        document.body.appendChild(notification);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 5000);

        // Close button functionality
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        });
    },

    /**
     * Handle API errors gracefully
     * @param {Error} error - Error object
     * @param {string} service - Service name
     * @returns {Object} - Standardized error object
     */
    handleAPIError(error, service) {
        let message = 'An unexpected error occurred';
        let type = 'error';

        if (error.code === 'AccessDenied' || error.code === 'UnauthorizedOperation') {
            message = `Access denied to ${service}. You may not have permission to access this service.`;
            type = 'warning';
        } else if (error.code === 'InvalidClientTokenId') {
            message = 'Invalid credentials. Please check your access keys.';
            type = 'error';
        } else if (error.code === 'ExpiredTokenException') {
            message = 'Your session token has expired. Please refresh your credentials.';
            type = 'warning';
        } else if (error.code === 'NetworkingError') {
            message = 'Network error. Please check your internet connection.';
            type = 'error';
        } else if (error.message) {
            message = error.message;
        }

        return {
            message,
            type,
            originalError: error,
            service
        };
    }
};

/**
 * Network connectivity utilities
 */
const NetworkUtils = {
    /**
     * Check if the browser is online
     * @returns {boolean} - Online status
     */
    isOnline() {
        return navigator.onLine;
    },

    /**
     * Check network connectivity with a simple request
     * @returns {Promise<boolean>} - Connectivity status
     */
    async checkConnectivity() {
        try {
            const response = await fetch('https://httpbin.org/get', {
                method: 'HEAD',
                mode: 'no-cors',
                cache: 'no-cache'
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
        ErrorHandler.showError(
            'You appear to be offline. Some features may not work properly.',
            'warning'
        );
    }
};

/**
 * LocalStorage utilities for optional profile saving
 */
const StorageUtils = {
    /**
     * Save scan results to localStorage
     * @param {Object} results - Scan results
     * @param {string} provider - Cloud provider
     */
    saveResults(results, provider) {
        try {
            const key = `peekinthecloud_${provider}_${Date.now()}`;
            const data = {
                provider,
                timestamp: new Date().toISOString(),
                results
            };
            localStorage.setItem(key, JSON.stringify(data));
            return true;
        } catch (error) {
            console.warn('Failed to save results to localStorage:', error);
            return false;
        }
    },

    /**
     * Get saved scan results
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
     * Clear saved results
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
};

/**
 * UI utility functions
 */
const UIUtils = {
    /**
     * Show/hide element
     * @param {string} elementId - Element ID
     * @param {boolean} show - Show or hide
     */
    toggleElement(elementId, show) {
        const element = document.getElementById(elementId);
        if (element) {
            if (show) {
                element.classList.remove('hidden');
            } else {
                element.classList.add('hidden');
            }
        }
    },

    /**
     * Show loading state
     * @param {boolean} show - Show or hide loading
     */
    showLoading(show) {
        const overlay = document.getElementById('loadingOverlay');
        const button = document.getElementById('scanButton');
        const buttonText = button.querySelector('.button-text');
        const spinner = button.querySelector('.loading-spinner');

        if (show) {
            overlay.classList.remove('hidden');
            button.disabled = true;
            buttonText.textContent = 'Scanning...';
            spinner.classList.remove('hidden');
            AppState.isScanning = true;
        } else {
            overlay.classList.add('hidden');
            button.disabled = false;
            buttonText.textContent = 'Scan Credentials';
            spinner.classList.add('hidden');
            AppState.isScanning = false;
        }
    },

    /**
     * Enable/disable scan button based on form validity
     */
    updateScanButton() {
        const button = document.getElementById('scanButton');
        const provider = document.getElementById('cloudProvider').value;
        
        if (!provider) {
            button.disabled = true;
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

        button.disabled = !isValid || AppState.isScanning;
    },

    /**
     * Copy text to clipboard
     * @param {string} text - Text to copy
     * @returns {Promise<boolean>} - Success status
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (error) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            const success = document.execCommand('copy');
            document.body.removeChild(textArea);
            return success;
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
    }
};

/**
 * Security utilities
 */
const SecurityUtils = {
    /**
     * Sanitize input to prevent XSS
     * @param {string} input - Input string
     * @returns {string} - Sanitized string
     */
    sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
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
};

// Export utilities for use in other modules
window.Utils = {
    AppState,
    CredentialValidator,
    ErrorHandler,
    NetworkUtils,
    StorageUtils,
    UIUtils,
    SecurityUtils
}; 