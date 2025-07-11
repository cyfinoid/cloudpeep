/**
 * Azure Cloud Scanner for PeekInTheCloud
 * Handles Azure service scanning and permission checking
 */

const AzureCloudScanner = {
    /**
     * Scan all Azure services with the provided credentials
     * @param {Object} credentials - Azure credentials object
     * @returns {Promise<Object>} - Scan results
     */
    async scanServices(credentials) {
        console.log('Starting Azure service scan...');
        
        const results = {};
        const services = ['resourceGroups', 'vms', 'blobStorage', 'appServices'];
        
        // Initialize MSAL
        const msalConfig = {
            auth: {
                clientId: credentials.clientId,
                authority: `https://login.microsoftonline.com/${credentials.tenantId}`
            }
        };
        
        const msalInstance = new msal.PublicClientApplication(msalConfig);
        
        try {
            // Get access token
            const tokenRequest = {
                scopes: ['https://management.azure.com/.default']
            };
            
            const response = await msalInstance.acquireTokenByClientCredential(tokenRequest);
            const accessToken = response.accessToken;
            
            // Scan each service
            for (const service of services) {
                try {
                    console.log(`Scanning ${service}...`);
                    results[service] = await this.scanService(service, accessToken, credentials);
                } catch (error) {
                    console.error(`Error scanning ${service}:`, error);
                    results[service] = {
                        status: 'error',
                        accessible: false,
                        error: error.message,
                        permission: 'none'
                    };
                }
            }
            
        } catch (error) {
            console.error('Failed to acquire Azure access token:', error);
            // Return error results for all services
            services.forEach(service => {
                results[service] = {
                    status: 'error',
                    accessible: false,
                    error: 'Failed to authenticate with Azure',
                    permission: 'none'
                };
            });
        }
        
        console.log('Azure service scan completed');
        return results;
    },
    
    /**
     * Scan a specific Azure service
     * @param {string} service - Service name
     * @param {string} accessToken - Azure access token
     * @param {Object} credentials - Azure credentials
     * @returns {Promise<Object>} - Service scan result
     */
    async scanService(service, accessToken, credentials) {
        switch (service) {
            case 'resourceGroups':
                return await this.scanResourceGroups(accessToken);
            case 'vms':
                return await this.scanVirtualMachines(accessToken);
            case 'blobStorage':
                return await this.scanBlobStorage(accessToken);
            case 'appServices':
                return await this.scanAppServices(accessToken);
            default:
                throw new Error(`Unsupported Azure service: ${service}`);
        }
    },
    
    /**
     * Make authenticated request to Azure REST API
     * @param {string} url - API endpoint URL
     * @param {string} accessToken - Azure access token
     * @returns {Promise<Object>} - API response
     */
    async makeAzureRequest(url, accessToken) {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Azure API request failed: ${response.status} ${response.statusText}`);
        }
        
        return await response.json();
    },
    
    /**
     * Scan Azure Resource Groups
     * @param {string} accessToken - Azure access token
     * @returns {Promise<Object>} - Resource Groups scan result
     */
    async scanResourceGroups(accessToken) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // List resource groups
            const url = 'https://management.azure.com/subscriptions?api-version=2020-01-01';
            const subscriptionsResponse = await this.makeAzureRequest(url, accessToken);
            result.apiCalls.push('ListSubscriptions');
            
            if (subscriptionsResponse.value && subscriptionsResponse.value.length > 0) {
                const subscriptionId = subscriptionsResponse.value[0].subscriptionId;
                
                const resourceGroupsUrl = `https://management.azure.com/subscriptions/${subscriptionId}/resourcegroups?api-version=2021-04-01`;
                const resourceGroupsResponse = await this.makeAzureRequest(resourceGroupsUrl, accessToken);
                result.apiCalls.push('ListResourceGroups');
                result.rawResponse = resourceGroupsResponse;
                
                if (resourceGroupsResponse.value) {
                    result.resources = resourceGroupsResponse.value.map(rg => rg.name);
                    result.permission = 'list';
                    result.accessible = true;
                    result.status = 'accessible';
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Resource Groups');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan Azure Virtual Machines
     * @param {string} accessToken - Azure access token
     * @returns {Promise<Object>} - VMs scan result
     */
    async scanVirtualMachines(accessToken) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Get subscriptions first
            const subscriptionsUrl = 'https://management.azure.com/subscriptions?api-version=2020-01-01';
            const subscriptionsResponse = await this.makeAzureRequest(subscriptionsUrl, accessToken);
            result.apiCalls.push('ListSubscriptions');
            
            if (subscriptionsResponse.value && subscriptionsResponse.value.length > 0) {
                const subscriptionId = subscriptionsResponse.value[0].subscriptionId;
                
                // List virtual machines
                const vmsUrl = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2021-11-01`;
                const vmsResponse = await this.makeAzureRequest(vmsUrl, accessToken);
                result.apiCalls.push('ListVirtualMachines');
                result.rawResponse = vmsResponse;
                
                if (vmsResponse.value) {
                    result.resources = vmsResponse.value.map(vm => `${vm.name} (${vm.properties.hardwareProfile.vmSize})`);
                    result.permission = 'read';
                    result.accessible = true;
                    result.status = 'accessible';
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Virtual Machines');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan Azure Blob Storage
     * @param {string} accessToken - Azure access token
     * @returns {Promise<Object>} - Blob Storage scan result
     */
    async scanBlobStorage(accessToken) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Get subscriptions first
            const subscriptionsUrl = 'https://management.azure.com/subscriptions?api-version=2020-01-01';
            const subscriptionsResponse = await this.makeAzureRequest(subscriptionsUrl, accessToken);
            result.apiCalls.push('ListSubscriptions');
            
            if (subscriptionsResponse.value && subscriptionsResponse.value.length > 0) {
                const subscriptionId = subscriptionsResponse.value[0].subscriptionId;
                
                // List storage accounts
                const storageUrl = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2021-09-01`;
                const storageResponse = await this.makeAzureRequest(storageUrl, accessToken);
                result.apiCalls.push('ListStorageAccounts');
                result.rawResponse = storageResponse;
                
                if (storageResponse.value) {
                    result.resources = storageResponse.value.map(account => account.name);
                    result.permission = 'list';
                    result.accessible = true;
                    result.status = 'accessible';
                    
                    // Try to list containers for first storage account
                    if (result.resources.length > 0) {
                        try {
                            const accountName = result.resources[0];
                            const containersUrl = `https://${accountName}.blob.core.windows.net/?comp=list`;
                            const containersResponse = await fetch(containersUrl, {
                                method: 'GET',
                                headers: {
                                    'Authorization': `Bearer ${accessToken}`,
                                    'x-ms-version': '2020-04-08'
                                }
                            });
                            
                            if (containersResponse.ok) {
                                result.apiCalls.push('ListContainers');
                                result.permission = 'read';
                            }
                        } catch (error) {
                            // Can list accounts but not containers
                            result.permission = 'list';
                        }
                    }
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Blob Storage');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan Azure App Services
     * @param {string} accessToken - Azure access token
     * @returns {Promise<Object>} - App Services scan result
     */
    async scanAppServices(accessToken) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Get subscriptions first
            const subscriptionsUrl = 'https://management.azure.com/subscriptions?api-version=2020-01-01';
            const subscriptionsResponse = await this.makeAzureRequest(subscriptionsUrl, accessToken);
            result.apiCalls.push('ListSubscriptions');
            
            if (subscriptionsResponse.value && subscriptionsResponse.value.length > 0) {
                const subscriptionId = subscriptionsResponse.value[0].subscriptionId;
                
                // List web apps
                const webAppsUrl = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Web/sites?api-version=2021-03-01`;
                const webAppsResponse = await this.makeAzureRequest(webAppsUrl, accessToken);
                result.apiCalls.push('ListWebApps');
                result.rawResponse = webAppsResponse;
                
                if (webAppsResponse.value) {
                    result.resources = webAppsResponse.value.map(app => `${app.name} (${app.properties.state})`);
                    result.permission = 'read';
                    result.accessible = true;
                    result.status = 'accessible';
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'App Services');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    }
};

// Export for use in main application
window.AzureCloudScanner = AzureCloudScanner; 