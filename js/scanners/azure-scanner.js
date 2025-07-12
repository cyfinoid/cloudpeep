/**
 * Azure Cloud Scanner - Comprehensive Service Enumeration
 * Supports comprehensive Azure resource enumeration across all services
 */

class AzureScanner {
    constructor() {
        this.results = {};
        this.subscriptions = [];
        this.resourceGroups = [];
    }

    async scan(credentials, selectedServices = null) {
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        const scanStartTime = Date.now();
        
        console.log(`[${scanId}] 🏗️  Initializing Azure scanner...`);
        
        try {
            console.log(`[${scanId}] 🔐 Validating Azure credentials...`);
            this.validateCredentials(credentials);
            console.log(`[${scanId}] ✅ Azure credentials validated`);
            
            // Initialize Azure SDK
            console.log(`[${scanId}] 🔧 Initializing Azure SDK...`);
            await this.initializeSDK(credentials);
            console.log(`[${scanId}] ✅ Azure SDK initialized successfully`);
            
            // Get available services
            const services = selectedServices || this.getAvailableServices();
            console.log(`[${scanId}] 📋 Services to scan: ${services.length}`, {
                services: services,
                selectedServices: selectedServices ? selectedServices.length : 'ALL'
            });
            
            // Scan subscriptions and resources
            console.log(`[${scanId}] 🔍 Scanning Azure subscriptions...`);
            await this.scanSubscriptions();
            console.log(`[${scanId}] ✅ Subscriptions scanned: ${this.subscriptions.length} found`);
            
            console.log(`[${scanId}] 🔍 Scanning Azure resource groups...`);
            await this.scanResourceGroups();
            console.log(`[${scanId}] ✅ Resource groups scanned: ${this.resourceGroups.length} found`);
            
            // Scan each service
            let completedServices = 0;
            let successfulServices = 0;
            let failedServices = 0;
            
            console.log(`[${scanId}] 🔍 Starting Azure service enumeration...`);
            
            for (const service of services) {
                const serviceStartTime = Date.now();
                completedServices++;
                
                console.log(`[${scanId}] 🔍 [${completedServices}/${services.length}] Scanning ${service}...`);
                
                // Update progress for current service
                if (this.onProgressUpdate) {
                    this.onProgressUpdate(service, `Scanning ${service}...`);
                }
                
                try {
                    await this.scanService(service);
                    const serviceDuration = Date.now() - serviceStartTime;
                    successfulServices++;
                    console.log(`[${scanId}] ✅ [${completedServices}/${services.length}] ${service} completed in ${Utils.DataUtils.formatDuration(serviceDuration)}`);
                } catch (error) {
                    const serviceDuration = Date.now() - serviceStartTime;
                    failedServices++;
                    console.error(`[${scanId}] ❌ [${completedServices}/${services.length}] ${service} failed after ${Utils.DataUtils.formatDuration(serviceDuration)}:`, error);
                    this.addResult(service, { error: error.message });
                }
                
                // Progress update
                const progress = Math.round((completedServices / services.length) * 100);
                console.log(`[${scanId}] 📊 Progress: ${progress}% (${completedServices}/${services.length})`);
            }
            
            const totalDuration = Date.now() - scanStartTime;
            console.log(`[${scanId}] 🎉 Azure scan completed!`, {
                duration: Utils.DataUtils.formatDuration(totalDuration),
                totalServices: services.length,
                successfulServices: successfulServices,
                failedServices: failedServices,
                successRate: Math.round((successfulServices / services.length) * 100) + '%',
                subscriptions: this.subscriptions.length,
                resourceGroups: this.resourceGroups.length
            });
            
            return this.getFinalResults();
        } catch (error) {
            const totalDuration = Date.now() - scanStartTime;
            console.error(`[${scanId}] 💥 Azure scan failed after ${Utils.DataUtils.formatDuration(totalDuration)}:`, error);
            throw new Error(`Azure scan failed: ${error.message}`);
        }
    }

    validateCredentials(credentials) {
        if (!credentials.accessToken) {
            throw new Error('Azure Access Token is required');
        }
    }

    async initializeSDK(credentials) {
        // Load Azure SDK
        if (typeof Azure === 'undefined') {
            throw new Error('Azure SDK not loaded');
        }
        
        // Configure Azure
        this.accessToken = credentials.accessToken;
        this.headers = {
            'Authorization': `Bearer ${this.accessToken}`,
            'Content-Type': 'application/json'
        };
    }

    getAvailableServices() {
        return [
            // Compute Services
            'virtualmachines', 'appservices', 'containerinstances', 'functions', 'kubernetes',
            
            // Storage Services
            'blobstorage', 'filestorage', 'queuestorage', 'tablestorage', 'disks',
            
            // Database Services
            'sqldatabase', 'cosmosdb', 'rediscache', 'postgresql', 'mysql',
            
            // Networking Services
            'virtualnetworks', 'loadbalancers', 'applicationgateway', 'expressroute', 'dns', 'cdn',
            
            // Security Services
            'keyvault', 'securitycenter', 'activedirectory', 'sentinel',
            
            // AI/ML Services
            'cognitiveservices', 'machinelearning', 'botframework',
            
            // Development Services
            'devops', 'logicapps', 'apimanagement',
            
            // Analytics Services
            'databricks', 'synapse', 'streamanalytics',
            
            // Media Services
            'mediaservices',
            
            // Management Services
            'resourcegroups', 'subscriptions', 'policy', 'monitor'
        ];
    }

    async scanService(service) {
        const scanner = this.getServiceScanner(service);
        if (scanner) {
            await scanner.call(this);
        }
    }

    getServiceScanner(service) {
        const scanners = {
            // Compute Services
            virtualmachines: this.scanVirtualMachines,
            appservices: this.scanAppServices,
            containerinstances: this.scanContainerInstances,
            functions: this.scanFunctions,
            kubernetes: this.scanKubernetes,
            
            // Storage Services
            blobstorage: this.scanBlobStorage,
            filestorage: this.scanFileStorage,
            queuestorage: this.scanQueueStorage,
            tablestorage: this.scanTableStorage,
            disks: this.scanDisks,
            
            // Database Services
            sqldatabase: this.scanSQLDatabase,
            cosmosdb: this.scanCosmosDB,
            rediscache: this.scanRedisCache,
            postgresql: this.scanPostgreSQL,
            mysql: this.scanMySQL,
            
            // Networking Services
            virtualnetworks: this.scanVirtualNetworks,
            loadbalancers: this.scanLoadBalancers,
            applicationgateway: this.scanApplicationGateway,
            expressroute: this.scanExpressRoute,
            dns: this.scanDNS,
            cdn: this.scanCDN,
            
            // Security Services
            keyvault: this.scanKeyVault,
            securitycenter: this.scanSecurityCenter,
            activedirectory: this.scanActiveDirectory,
            sentinel: this.scanSentinel,
            
            // AI/ML Services
            cognitiveservices: this.scanCognitiveServices,
            machinelearning: this.scanMachineLearning,
            botframework: this.scanBotFramework,
            
            // Development Services
            devops: this.scanDevOps,
            logicapps: this.scanLogicApps,
            apimanagement: this.scanAPIManagement,
            
            // Analytics Services
            databricks: this.scanDatabricks,
            synapse: this.scanSynapse,
            streamanalytics: this.scanStreamAnalytics,
            
            // Media Services
            mediaservices: this.scanMediaServices,
            
            // Management Services
            resourcegroups: this.scanResourceGroups,
            subscriptions: this.scanSubscriptions,
            policy: this.scanPolicy,
            monitor: this.scanMonitor
        };
        
        return scanners[service];
    }

    async scanSubscriptions() {
        try {
            const url = 'https://management.azure.com/subscriptions?api-version=2020-01-01';
            const response = await this.makeRequest(url);
            
            if (response.value) {
                this.subscriptions = response.value.map(sub => ({
                    id: sub.subscriptionId,
                    name: sub.displayName,
                    state: sub.state
                }));
                
                this.addResult('subscriptions', { subscriptions: this.subscriptions });
            }
        } catch (error) {
            console.error('Error scanning subscriptions:', error);
            this.addResult('subscriptions', { error: error.message });
        }
    }

    async scanResourceGroups() {
        try {
            const resourceGroups = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/resourcegroups?api-version=2020-06-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const rg of response.value) {
                        resourceGroups.push({
                            name: rg.name,
                            location: rg.location,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.resourceGroups = resourceGroups;
            this.addResult('resourcegroups', { resourceGroups });
        } catch (error) {
            console.error('Error scanning resource groups:', error);
            this.addResult('resourcegroups', { error: error.message });
        }
    }

    async scanAllResources() {
        try {
            const allResources = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/resources?api-version=2020-06-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const resource of response.value) {
                        allResources.push({
                            id: resource.id,
                            name: resource.name,
                            type: resource.type,
                            location: resource.location,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.addResult('allresources', { resources: allResources });
        } catch (error) {
            console.error('Error scanning all resources:', error);
            this.addResult('allresources', { error: error.message });
        }
    }

    // Compute Services
    async scanVirtualMachines() {
        try {
            const vms = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.Compute/virtualMachines?api-version=2021-04-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const vm of response.value) {
                        vms.push({
                            id: vm.id,
                            name: vm.name,
                            location: vm.location,
                            size: vm.properties?.hardwareProfile?.vmSize,
                            osType: vm.properties?.storageProfile?.osDisk?.osType,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.addResult('virtualmachines', { virtualMachines: vms });
        } catch (error) {
            console.error('Error scanning virtual machines:', error);
            this.addResult('virtualmachines', { error: error.message });
        }
    }

    async scanAppServices() {
        try {
            const appServices = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.Web/sites?api-version=2021-02-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const app of response.value) {
                        appServices.push({
                            id: app.id,
                            name: app.name,
                            location: app.location,
                            kind: app.kind,
                            state: app.properties?.state,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.addResult('appservices', { appServices });
        } catch (error) {
            console.error('Error scanning app services:', error);
            this.addResult('appservices', { error: error.message });
        }
    }

    async scanFunctions() {
        try {
            const functions = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.Web/sites?api-version=2021-02-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const func of response.value) {
                        if (func.kind && func.kind.includes('functionapp')) {
                            functions.push({
                                id: func.id,
                                name: func.name,
                                location: func.location,
                                state: func.properties?.state,
                                subscriptionId: subscription.id,
                                subscriptionName: subscription.name
                            });
                        }
                    }
                }
            }
            
            this.addResult('functions', { functions });
        } catch (error) {
            console.error('Error scanning functions:', error);
            this.addResult('functions', { error: error.message });
        }
    }

    // Storage Services
    async scanBlobStorage() {
        try {
            const storageAccounts = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.Storage/storageAccounts?api-version=2021-04-01`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const account of response.value) {
                        storageAccounts.push({
                            id: account.id,
                            name: account.name,
                            location: account.location,
                            kind: account.kind,
                            sku: account.sku?.name,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.addResult('blobstorage', { storageAccounts });
        } catch (error) {
            console.error('Error scanning blob storage:', error);
            this.addResult('blobstorage', { error: error.message });
        }
    }

    // Database Services
    async scanSQLDatabase() {
        try {
            const databases = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.Sql/servers?api-version=2021-02-01-preview`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const server of response.value) {
                        const dbUrl = `https://management.azure.com${server.id}/databases?api-version=2021-02-01-preview`;
                        const dbResponse = await this.makeRequest(dbUrl);
                        
                        if (dbResponse.value) {
                            for (const db of dbResponse.value) {
                                databases.push({
                                    id: db.id,
                                    name: db.name,
                                    serverName: server.name,
                                    location: db.location,
                                    status: db.properties?.status,
                                    subscriptionId: subscription.id,
                                    subscriptionName: subscription.name
                                });
                            }
                        }
                    }
                }
            }
            
            this.addResult('sqldatabase', { databases });
        } catch (error) {
            console.error('Error scanning SQL databases:', error);
            this.addResult('sqldatabase', { error: error.message });
        }
    }

    // Security Services
    async scanKeyVault() {
        try {
            const keyVaults = [];
            
            for (const subscription of this.subscriptions) {
                const url = `https://management.azure.com/subscriptions/${subscription.id}/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview`;
                const response = await this.makeRequest(url);
                
                if (response.value) {
                    for (const vault of response.value) {
                        keyVaults.push({
                            id: vault.id,
                            name: vault.name,
                            location: vault.location,
                            sku: vault.properties?.sku?.name,
                            enabledForDeployment: vault.properties?.enabledForDeployment,
                            enabledForDiskEncryption: vault.properties?.enabledForDiskEncryption,
                            enabledForTemplateDeployment: vault.properties?.enabledForTemplateDeployment,
                            subscriptionId: subscription.id,
                            subscriptionName: subscription.name
                        });
                    }
                }
            }
            
            this.addResult('keyvault', { keyVaults });
        } catch (error) {
            console.error('Error scanning key vaults:', error);
            this.addResult('keyvault', { error: error.message });
        }
    }

    // Placeholder methods for other services - these will be grouped together
    async scanContainerInstances() { this.addUnimplementedService('containerinstances'); }
    async scanKubernetes() { this.addUnimplementedService('kubernetes'); }
    async scanFileStorage() { this.addUnimplementedService('filestorage'); }
    async scanQueueStorage() { this.addUnimplementedService('queuestorage'); }
    async scanTableStorage() { this.addUnimplementedService('tablestorage'); }
    async scanDisks() { this.addUnimplementedService('disks'); }
    async scanCosmosDB() { this.addUnimplementedService('cosmosdb'); }
    async scanRedisCache() { this.addUnimplementedService('rediscache'); }
    async scanPostgreSQL() { this.addUnimplementedService('postgresql'); }
    async scanMySQL() { this.addUnimplementedService('mysql'); }
    async scanVirtualNetworks() { this.addUnimplementedService('virtualnetworks'); }
    async scanLoadBalancers() { this.addUnimplementedService('loadbalancers'); }
    async scanApplicationGateway() { this.addUnimplementedService('applicationgateway'); }
    async scanExpressRoute() { this.addUnimplementedService('expressroute'); }
    async scanDNS() { this.addUnimplementedService('dns'); }
    async scanCDN() { this.addUnimplementedService('cdn'); }
    async scanSecurityCenter() { this.addUnimplementedService('securitycenter'); }
    async scanActiveDirectory() { this.addUnimplementedService('activedirectory'); }
    async scanSentinel() { this.addUnimplementedService('sentinel'); }
    async scanCognitiveServices() { this.addUnimplementedService('cognitiveservices'); }
    async scanMachineLearning() { this.addUnimplementedService('machinelearning'); }
    async scanBotFramework() { this.addUnimplementedService('botframework'); }
    async scanDevOps() { this.addUnimplementedService('devops'); }
    async scanLogicApps() { this.addUnimplementedService('logicapps'); }
    async scanAPIManagement() { this.addUnimplementedService('apimanagement'); }
    async scanDatabricks() { this.addUnimplementedService('databricks'); }
    async scanSynapse() { this.addUnimplementedService('synapse'); }
    async scanStreamAnalytics() { this.addUnimplementedService('streamanalytics'); }
    async scanMediaServices() { this.addUnimplementedService('mediaservices'); }
    async scanPolicy() { this.addUnimplementedService('policy'); }
    async scanMonitor() { this.addUnimplementedService('monitor'); }

    async makeRequest(url) {
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: this.headers
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            return await response.json();
        } catch (error) {
            throw new Error(`Request failed: ${error.message}`);
        }
    }

    /**
     * Add unimplemented service to the grouped list
     * @param {string} service - Service name
     */
    addUnimplementedService(service) {
        if (!this.unimplementedServices) {
            this.unimplementedServices = [];
        }
        this.unimplementedServices.push(service);
    }

    /**
     * Add result for a service
     * @param {string} service - Service name
     * @param {Object} data - Service data
     */
    addResult(service, data) {
        this.results[service] = data;
    }

    /**
     * Get final results with grouped unimplemented services
     * @returns {Object} Final results
     */
    getFinalResults() {
        const finalResults = { ...this.results };
        
        // Add grouped unimplemented services if any exist
        if (this.unimplementedServices && this.unimplementedServices.length > 0) {
            finalResults['unimplemented_services'] = {
                message: 'Services not implemented yet',
                services: this.unimplementedServices,
                count: this.unimplementedServices.length
            };
        }
        
        return finalResults;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AzureScanner;
} 