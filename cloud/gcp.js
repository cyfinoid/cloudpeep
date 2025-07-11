/**
 * GCP Cloud Scanner for PeekInTheCloud
 * Handles Google Cloud Platform service scanning and permission checking
 */

const GCPCloudScanner = {
    /**
     * Scan all GCP services with the provided credentials
     * @param {Object} credentials - GCP credentials object
     * @returns {Promise<Object>} - Scan results
     */
    async scanServices(credentials) {
        console.log('Starting GCP service scan...');
        
        const results = {};
        const services = ['compute', 'gcs', 'iam', 'cloudFunctions'];
        
        try {
            // Parse service account JSON
            const serviceAccount = JSON.parse(credentials.serviceAccountJson);
            
            // Initialize Google APIs
            await this.initializeGoogleAPIs(serviceAccount);
            
            // Scan each service
            for (const service of services) {
                try {
                    console.log(`Scanning ${service}...`);
                    results[service] = await this.scanService(service, serviceAccount);
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
            console.error('Failed to initialize GCP APIs:', error);
            // Return error results for all services
            services.forEach(service => {
                results[service] = {
                    status: 'error',
                    accessible: false,
                    error: 'Failed to authenticate with GCP',
                    permission: 'none'
                };
            });
        }
        
        console.log('GCP service scan completed');
        return results;
    },
    
    /**
     * Initialize Google APIs with service account
     * @param {Object} serviceAccount - Service account object
     */
    async initializeGoogleAPIs(serviceAccount) {
        // Set up authentication
        const auth = new google.auth.GoogleAuth({
            credentials: serviceAccount,
            scopes: [
                'https://www.googleapis.com/auth/cloud-platform',
                'https://www.googleapis.com/auth/compute',
                'https://www.googleapis.com/auth/devstorage.read_only',
                'https://www.googleapis.com/auth/cloud-platform.read-only'
            ]
        });
        
        // Initialize APIs
        google.options({ auth });
    },
    
    /**
     * Scan a specific GCP service
     * @param {string} service - Service name
     * @param {Object} serviceAccount - Service account object
     * @returns {Promise<Object>} - Service scan result
     */
    async scanService(service, serviceAccount) {
        switch (service) {
            case 'compute':
                return await this.scanComputeEngine(serviceAccount);
            case 'gcs':
                return await this.scanCloudStorage(serviceAccount);
            case 'iam':
                return await this.scanIAM(serviceAccount);
            case 'cloudFunctions':
                return await this.scanCloudFunctions(serviceAccount);
            default:
                throw new Error(`Unsupported GCP service: ${service}`);
        }
    },
    
    /**
     * Scan GCP Compute Engine
     * @param {Object} serviceAccount - Service account object
     * @returns {Promise<Object>} - Compute Engine scan result
     */
    async scanComputeEngine(serviceAccount) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            const compute = google.compute('v1');
            const projectId = serviceAccount.project_id;
            
            // List instances
            const instancesResponse = await compute.instances.list({
                project: projectId,
                zone: 'us-central1-a' // Default zone
            });
            
            result.apiCalls.push('ListInstances');
            result.rawResponse = instancesResponse.data;
            
            if (instancesResponse.data.items) {
                result.resources = instancesResponse.data.items.map(instance => 
                    `${instance.name} (${instance.machineType.split('/').pop()})`
                );
                result.permission = 'read';
                result.accessible = true;
                result.status = 'accessible';
            } else {
                result.resources = [];
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Compute Engine');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan GCP Cloud Storage
     * @param {Object} serviceAccount - Service account object
     * @returns {Promise<Object>} - Cloud Storage scan result
     */
    async scanCloudStorage(serviceAccount) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            const storage = google.storage('v1');
            const projectId = serviceAccount.project_id;
            
            // List buckets
            const bucketsResponse = await storage.buckets.list({
                project: projectId
            });
            
            result.apiCalls.push('ListBuckets');
            result.rawResponse = bucketsResponse.data;
            
            if (bucketsResponse.data.items) {
                result.resources = bucketsResponse.data.items.map(bucket => bucket.name);
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
                
                // Try to list objects in first bucket
                if (result.resources.length > 0) {
                    try {
                        const bucketName = result.resources[0];
                        const objectsResponse = await storage.objects.list({
                            bucket: bucketName,
                            maxResults: 1
                        });
                        
                        result.apiCalls.push('ListObjects');
                        result.permission = 'read';
                    } catch (error) {
                        // Can list buckets but not objects
                        result.permission = 'list';
                    }
                }
            } else {
                result.resources = [];
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Cloud Storage');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan GCP IAM
     * @param {Object} serviceAccount - Service account object
     * @returns {Promise<Object>} - IAM scan result
     */
    async scanIAM(serviceAccount) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            const iam = google.iam('v1');
            const projectId = serviceAccount.project_id;
            
            // List service accounts
            const serviceAccountsResponse = await iam.projects.serviceAccounts.list({
                name: `projects/${projectId}`
            });
            
            result.apiCalls.push('ListServiceAccounts');
            result.rawResponse = serviceAccountsResponse.data;
            
            if (serviceAccountsResponse.data.accounts) {
                result.resources = serviceAccountsResponse.data.accounts.map(account => 
                    account.displayName || account.email
                );
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
            } else {
                result.resources = [];
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
            }
            
            // Try to list roles
            try {
                const rolesResponse = await iam.projects.roles.list({
                    parent: `projects/${projectId}`
                });
                result.apiCalls.push('ListRoles');
            } catch (error) {
                // Roles not accessible
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'IAM');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan GCP Cloud Functions
     * @param {Object} serviceAccount - Service account object
     * @returns {Promise<Object>} - Cloud Functions scan result
     */
    async scanCloudFunctions(serviceAccount) {
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            const cloudfunctions = google.cloudfunctions('v1');
            const projectId = serviceAccount.project_id;
            
            // List functions
            const functionsResponse = await cloudfunctions.projects.locations.functions.list({
                parent: `projects/${projectId}/locations/-`
            });
            
            result.apiCalls.push('ListFunctions');
            result.rawResponse = functionsResponse.data;
            
            if (functionsResponse.data.functions) {
                result.resources = functionsResponse.data.functions.map(func => 
                    `${func.name.split('/').pop()} (${func.status})`
                );
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
                
                // Try to get details of first function
                if (result.resources.length > 0) {
                    try {
                        const functionName = functionsResponse.data.functions[0].name;
                        const functionResponse = await cloudfunctions.projects.locations.functions.get({
                            name: functionName
                        });
                        result.apiCalls.push('GetFunction');
                        result.permission = 'read';
                    } catch (error) {
                        // Can list but not get function details
                        result.permission = 'list';
                    }
                }
            } else {
                result.resources = [];
                result.permission = 'list';
                result.accessible = true;
                result.status = 'accessible';
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Cloud Functions');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    }
};

// Export for use in main application
window.GCPCloudScanner = GCPCloudScanner; 