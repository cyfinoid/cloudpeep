/**
 * GCP Cloud Scanner - Comprehensive Service Enumeration
 * Supports comprehensive GCP resource enumeration across all services
 */

class GCPScanner {
    constructor() {
        this.results = {};
        this.projects = [];
        this.regions = [
            'us-central1', 'us-east1', 'us-west1', 'us-west2',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4',
            'asia-east1', 'asia-southeast1', 'australia-southeast1'
        ];
    }

    async scan(credentials, selectedServices = null) {
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        const scanStartTime = Date.now();
        
        console.log(`[${scanId}] 🏗️  Initializing GCP scanner...`);
        
        try {
            console.log(`[${scanId}] 🔐 Validating GCP credentials...`);
            this.validateCredentials(credentials);
            console.log(`[${scanId}] ✅ GCP credentials validated`);
            
            // Initialize GCP SDK
            console.log(`[${scanId}] 🔧 Initializing GCP SDK...`);
            await this.initializeSDK(credentials);
            console.log(`[${scanId}] ✅ GCP SDK initialized successfully`);
            
            // Get available services
            const services = selectedServices || this.getAvailableServices();
            console.log(`[${scanId}] 📋 Services to scan: ${services.length}`, {
                services: services,
                selectedServices: selectedServices ? selectedServices.length : 'ALL'
            });
            
            // Scan projects first
            console.log(`[${scanId}] 🔍 Scanning GCP projects...`);
            await this.scanProjects();
            console.log(`[${scanId}] ✅ Projects scanned: ${this.projects.length} found`);
            
            // Scan each service
            let completedServices = 0;
            let successfulServices = 0;
            let failedServices = 0;
            
            console.log(`[${scanId}] 🔍 Starting GCP service enumeration...`);
            
            for (const service of services) {
                const serviceStartTime = Date.now();
                completedServices++;
                
                console.log(`[${scanId}] 🔍 [${completedServices}/${services.length}] Scanning ${service}...`);
                
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
            console.log(`[${scanId}] 🎉 GCP scan completed!`, {
                duration: Utils.DataUtils.formatDuration(totalDuration),
                totalServices: services.length,
                successfulServices: successfulServices,
                failedServices: failedServices,
                successRate: Math.round((successfulServices / services.length) * 100) + '%',
                projects: this.projects.length
            });
            
            return this.results;
        } catch (error) {
            const totalDuration = Date.now() - scanStartTime;
            console.error(`[${scanId}] 💥 GCP scan failed after ${Utils.DataUtils.formatDuration(totalDuration)}:`, error);
            throw new Error(`GCP scan failed: ${error.message}`);
        }
    }

    validateCredentials(credentials) {
        if (!credentials.serviceAccountKey) {
            throw new Error('GCP Service Account Key is required');
        }
    }

    async initializeSDK(credentials) {
        // Load GCP SDK
        if (typeof google === 'undefined' || !google.auth) {
            throw new Error('Google Cloud SDK not loaded');
        }
        
        // Configure GCP
        this.credentials = credentials.serviceAccountKey;
        this.authClient = new google.auth.GoogleAuth({
            credentials: this.credentials,
            scopes: [
                'https://www.googleapis.com/auth/cloud-platform',
                'https://www.googleapis.com/auth/compute',
                'https://www.googleapis.com/auth/storage',
                'https://www.googleapis.com/auth/sqlservice',
                'https://www.googleapis.com/auth/datastore',
                'https://www.googleapis.com/auth/bigquery',
                'https://www.googleapis.com/auth/cloudfunctions',
                'https://www.googleapis.com/auth/run',
                'https://www.googleapis.com/auth/appengine',
                'https://www.googleapis.com/auth/cloudkms',
                'https://www.googleapis.com/auth/cloudiot',
                'https://www.googleapis.com/auth/cloudbuild',
                'https://www.googleapis.com/auth/source.read_only'
            ]
        });
    }

    getAvailableServices() {
        return [
            // Compute Services
            'computeengine', 'appengine', 'cloudrun', 'kubernetes', 'functions',
            
            // Storage Services
            'cloudstorage', 'cloudfilestore', 'persistentdisks',
            
            // Database Services
            'cloudsql', 'firestore', 'bigquery', 'spanner', 'datastore',
            
            // Networking Services
            'vpc', 'loadbalancing', 'cloudarmor', 'cloudcdn', 'clouddns',
            
            // Security Services
            'iam', 'securitycommandcenter', 'binaryauthorization', 'accesscontextmanager',
            
            // AI/ML Services
            'aiplatform', 'visionapi', 'speechapi', 'naturallanguage', 'translation',
            
            // Development Services
            'cloudbuild', 'sourcerepositories', 'clouddeploy', 'artifactregistry',
            
            // Analytics Services
            'dataproc', 'dataflow', 'pubsub', 'datacatalog',
            
            // Management Services
            'resourcemanager', 'cloudmonitoring', 'cloudlogging', 'cloudtrace',
            
            // Additional Services
            'cloudkms', 'cloudtasks', 'cloudscheduler', 'cloudiot'
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
            computeengine: this.scanComputeEngine,
            appengine: this.scanAppEngine,
            cloudrun: this.scanCloudRun,
            kubernetes: this.scanKubernetes,
            functions: this.scanFunctions,
            
            // Storage Services
            cloudstorage: this.scanCloudStorage,
            cloudfilestore: this.scanCloudFilestore,
            persistentdisks: this.scanPersistentDisks,
            
            // Database Services
            cloudsql: this.scanCloudSQL,
            firestore: this.scanFirestore,
            bigquery: this.scanBigQuery,
            spanner: this.scanSpanner,
            datastore: this.scanDatastore,
            
            // Networking Services
            vpc: this.scanVPC,
            loadbalancing: this.scanLoadBalancing,
            cloudarmor: this.scanCloudArmor,
            cloudcdn: this.scanCloudCDN,
            clouddns: this.scanCloudDNS,
            
            // Security Services
            iam: this.scanIAM,
            securitycommandcenter: this.scanSecurityCommandCenter,
            binaryauthorization: this.scanBinaryAuthorization,
            accesscontextmanager: this.scanAccessContextManager,
            
            // AI/ML Services
            aiplatform: this.scanAIPlatform,
            visionapi: this.scanVisionAPI,
            speechapi: this.scanSpeechAPI,
            naturallanguage: this.scanNaturalLanguage,
            translation: this.scanTranslation,
            
            // Development Services
            cloudbuild: this.scanCloudBuild,
            sourcerepositories: this.scanSourceRepositories,
            clouddeploy: this.scanCloudDeploy,
            artifactregistry: this.scanArtifactRegistry,
            
            // Analytics Services
            dataproc: this.scanDataproc,
            dataflow: this.scanDataflow,
            pubsub: this.scanPubSub,
            datacatalog: this.scanDataCatalog,
            
            // Management Services
            resourcemanager: this.scanResourceManager,
            cloudmonitoring: this.scanCloudMonitoring,
            cloudlogging: this.scanCloudLogging,
            cloudtrace: this.scanCloudTrace,
            
            // Additional Services
            cloudkms: this.scanCloudKMS,
            cloudtasks: this.scanCloudTasks,
            cloudscheduler: this.scanCloudScheduler,
            cloudiot: this.scanCloudIoT
        };
        
        return scanners[service];
    }

    async scanProjects() {
        try {
            const resourceManager = google.cloud.resourcemanager({
                version: 'v1',
                auth: this.authClient
            });
            
            const response = await resourceManager.projects.list();
            this.projects = response.data.projects || [];
            
            this.addResult('projects', { 
                projects: this.projects.map(p => ({
                    projectId: p.projectId,
                    name: p.name,
                    projectNumber: p.projectNumber,
                    lifecycleState: p.lifecycleState
                }))
            });
        } catch (error) {
            console.error('Error scanning projects:', error);
            this.addResult('projects', { error: error.message });
        }
    }

    // Compute Services
    async scanComputeEngine() {
        try {
            const instances = [];
            const disks = [];
            const networks = [];
            const firewalls = [];
            
            for (const project of this.projects) {
                const projectId = project.projectId;
                
                // Scan instances
                try {
                    const compute = google.compute({
                        version: 'v1',
                        auth: this.authClient
                    });
                    
                    for (const region of this.regions) {
                        try {
                            const zone = `${region}-a`;
                            const instancesResponse = await compute.instances.list({
                                project: projectId,
                                zone: zone
                            });
                            
                            if (instancesResponse.data.items) {
                                for (const instance of instancesResponse.data.items) {
                                    instances.push({
                                        name: instance.name,
                                        machineType: instance.machineType,
                                        status: instance.status,
                                        zone: zone,
                                        projectId: projectId
                                    });
                                }
                            }
                        } catch (error) {
                            console.error(`Error scanning instances in ${region}:`, error);
                        }
                    }
                    
                    // Scan disks
                    for (const region of this.regions) {
                        try {
                            const zone = `${region}-a`;
                            const disksResponse = await compute.disks.list({
                                project: projectId,
                                zone: zone
                            });
                            
                            if (disksResponse.data.items) {
                                for (const disk of disksResponse.data.items) {
                                    disks.push({
                                        name: disk.name,
                                        sizeGb: disk.sizeGb,
                                        type: disk.type,
                                        zone: zone,
                                        projectId: projectId
                                    });
                                }
                            }
                        } catch (error) {
                            console.error(`Error scanning disks in ${region}:`, error);
                        }
                    }
                    
                    // Scan networks
                    const networksResponse = await compute.networks.list({
                        project: projectId
                    });
                    
                    if (networksResponse.data.items) {
                        for (const network of networksResponse.data.items) {
                            networks.push({
                                name: network.name,
                                autoCreateSubnetworks: network.autoCreateSubnetworks,
                                mtu: network.mtu,
                                projectId: projectId
                            });
                        }
                    }
                    
                    // Scan firewalls
                    const firewallsResponse = await compute.firewalls.list({
                        project: projectId
                    });
                    
                    if (firewallsResponse.data.items) {
                        for (const firewall of firewallsResponse.data.items) {
                            firewalls.push({
                                name: firewall.name,
                                network: firewall.network,
                                direction: firewall.direction,
                                projectId: projectId
                            });
                        }
                    }
                    
                } catch (error) {
                    console.error(`Error scanning compute resources for project ${projectId}:`, error);
                }
            }
            
            this.addResult('computeengine', {
                instances,
                disks,
                networks,
                firewalls
            });
        } catch (error) {
            console.error('Error scanning compute engine:', error);
            this.addResult('computeengine', { error: error.message });
        }
    }

    async scanCloudStorage() {
        try {
            const buckets = [];
            
            for (const project of this.projects) {
                const projectId = project.projectId;
                
                try {
                    const storage = google.storage({
                        version: 'v1',
                        auth: this.authClient
                    });
                    
                    const bucketsResponse = await storage.buckets.list({
                        project: projectId
                    });
                    
                    if (bucketsResponse.data.items) {
                        for (const bucket of bucketsResponse.data.items) {
                            buckets.push({
                                name: bucket.name,
                                location: bucket.location,
                                storageClass: bucket.storageClass,
                                projectId: projectId
                            });
                        }
                    }
                } catch (error) {
                    console.error(`Error scanning storage for project ${projectId}:`, error);
                }
            }
            
            this.addResult('cloudstorage', { buckets });
        } catch (error) {
            console.error('Error scanning cloud storage:', error);
            this.addResult('cloudstorage', { error: error.message });
        }
    }

    async scanCloudSQL() {
        try {
            const instances = [];
            
            for (const project of this.projects) {
                const projectId = project.projectId;
                
                try {
                    const sqladmin = google.sqladmin({
                        version: 'v1beta4',
                        auth: this.authClient
                    });
                    
                    const instancesResponse = await sqladmin.instances.list({
                        project: projectId
                    });
                    
                    if (instancesResponse.data.items) {
                        for (const instance of instancesResponse.data.items) {
                            instances.push({
                                name: instance.name,
                                databaseVersion: instance.databaseVersion,
                                state: instance.state,
                                region: instance.region,
                                projectId: projectId
                            });
                        }
                    }
                } catch (error) {
                    console.error(`Error scanning Cloud SQL for project ${projectId}:`, error);
                }
            }
            
            this.addResult('cloudsql', { instances });
        } catch (error) {
            console.error('Error scanning Cloud SQL:', error);
            this.addResult('cloudsql', { error: error.message });
        }
    }

    async scanBigQuery() {
        try {
            const datasets = [];
            const tables = [];
            
            for (const project of this.projects) {
                const projectId = project.projectId;
                
                try {
                    const bigquery = google.bigquery({
                        version: 'v2',
                        auth: this.authClient
                    });
                    
                    // Scan datasets
                    const datasetsResponse = await bigquery.datasets.list({
                        projectId: projectId
                    });
                    
                    if (datasetsResponse.data.datasets) {
                        for (const dataset of datasetsResponse.data.datasets) {
                            datasets.push({
                                datasetId: dataset.datasetReference.datasetId,
                                projectId: dataset.datasetReference.projectId,
                                location: dataset.location
                            });
                        }
                    }
                    
                    // Scan tables for each dataset
                    for (const dataset of datasets) {
                        try {
                            const tablesResponse = await bigquery.tables.list({
                                projectId: dataset.projectId,
                                datasetId: dataset.datasetId
                            });
                            
                            if (tablesResponse.data.tables) {
                                for (const table of tablesResponse.data.tables) {
                                    tables.push({
                                        tableId: table.tableReference.tableId,
                                        datasetId: table.tableReference.datasetId,
                                        projectId: table.tableReference.projectId,
                                        type: table.type
                                    });
                                }
                            }
                        } catch (error) {
                            console.error(`Error scanning tables for dataset ${dataset.datasetId}:`, error);
                        }
                    }
                    
                } catch (error) {
                    console.error(`Error scanning BigQuery for project ${projectId}:`, error);
                }
            }
            
            this.addResult('bigquery', { datasets, tables });
        } catch (error) {
            console.error('Error scanning BigQuery:', error);
            this.addResult('bigquery', { error: error.message });
        }
    }

    async scanFunctions() {
        try {
            const functions = [];
            
            for (const project of this.projects) {
                const projectId = project.projectId;
                
                try {
                    const cloudfunctions = google.cloudfunctions({
                        version: 'v2',
                        auth: this.authClient
                    });
                    
                    for (const region of this.regions) {
                        try {
                            const functionsResponse = await cloudfunctions.projects.locations.functions.list({
                                parent: `projects/${projectId}/locations/${region}`
                            });
                            
                            if (functionsResponse.data.functions) {
                                for (const func of functionsResponse.data.functions) {
                                    functions.push({
                                        name: func.name,
                                        state: func.state,
                                        runtime: func.runtime,
                                        region: region,
                                        projectId: projectId
                                    });
                                }
                            }
                        } catch (error) {
                            console.error(`Error scanning functions in ${region}:`, error);
                        }
                    }
                } catch (error) {
                    console.error(`Error scanning Cloud Functions for project ${projectId}:`, error);
                }
            }
            
            this.addResult('functions', { functions });
        } catch (error) {
            console.error('Error scanning Cloud Functions:', error);
            this.addResult('functions', { error: error.message });
        }
    }

    // Placeholder methods for other services
    async scanAppEngine() { this.addResult('appengine', { message: 'Service not implemented yet' }); }
    async scanCloudRun() { this.addResult('cloudrun', { message: 'Service not implemented yet' }); }
    async scanKubernetes() { this.addResult('kubernetes', { message: 'Service not implemented yet' }); }
    async scanCloudFilestore() { this.addResult('cloudfilestore', { message: 'Service not implemented yet' }); }
    async scanPersistentDisks() { this.addResult('persistentdisks', { message: 'Service not implemented yet' }); }
    async scanFirestore() { this.addResult('firestore', { message: 'Service not implemented yet' }); }
    async scanSpanner() { this.addResult('spanner', { message: 'Service not implemented yet' }); }
    async scanDatastore() { this.addResult('datastore', { message: 'Service not implemented yet' }); }
    async scanVPC() { this.addResult('vpc', { message: 'Service not implemented yet' }); }
    async scanLoadBalancing() { this.addResult('loadbalancing', { message: 'Service not implemented yet' }); }
    async scanCloudArmor() { this.addResult('cloudarmor', { message: 'Service not implemented yet' }); }
    async scanCloudCDN() { this.addResult('cloudcdn', { message: 'Service not implemented yet' }); }
    async scanCloudDNS() { this.addResult('clouddns', { message: 'Service not implemented yet' }); }
    async scanIAM() { this.addResult('iam', { message: 'Service not implemented yet' }); }
    async scanSecurityCommandCenter() { this.addResult('securitycommandcenter', { message: 'Service not implemented yet' }); }
    async scanBinaryAuthorization() { this.addResult('binaryauthorization', { message: 'Service not implemented yet' }); }
    async scanAccessContextManager() { this.addResult('accesscontextmanager', { message: 'Service not implemented yet' }); }
    async scanAIPlatform() { this.addResult('aiplatform', { message: 'Service not implemented yet' }); }
    async scanVisionAPI() { this.addResult('visionapi', { message: 'Service not implemented yet' }); }
    async scanSpeechAPI() { this.addResult('speechapi', { message: 'Service not implemented yet' }); }
    async scanNaturalLanguage() { this.addResult('naturallanguage', { message: 'Service not implemented yet' }); }
    async scanTranslation() { this.addResult('translation', { message: 'Service not implemented yet' }); }
    async scanCloudBuild() { this.addResult('cloudbuild', { message: 'Service not implemented yet' }); }
    async scanSourceRepositories() { this.addResult('sourcerepositories', { message: 'Service not implemented yet' }); }
    async scanCloudDeploy() { this.addResult('clouddeploy', { message: 'Service not implemented yet' }); }
    async scanArtifactRegistry() { this.addResult('artifactregistry', { message: 'Service not implemented yet' }); }
    async scanDataproc() { this.addResult('dataproc', { message: 'Service not implemented yet' }); }
    async scanDataflow() { this.addResult('dataflow', { message: 'Service not implemented yet' }); }
    async scanPubSub() { this.addResult('pubsub', { message: 'Service not implemented yet' }); }
    async scanDataCatalog() { this.addResult('datacatalog', { message: 'Service not implemented yet' }); }
    async scanResourceManager() { this.addResult('resourcemanager', { message: 'Service not implemented yet' }); }
    async scanCloudMonitoring() { this.addResult('cloudmonitoring', { message: 'Service not implemented yet' }); }
    async scanCloudLogging() { this.addResult('cloudlogging', { message: 'Service not implemented yet' }); }
    async scanCloudTrace() { this.addResult('cloudtrace', { message: 'Service not implemented yet' }); }
    async scanCloudKMS() { this.addResult('cloudkms', { message: 'Service not implemented yet' }); }
    async scanCloudTasks() { this.addResult('cloudtasks', { message: 'Service not implemented yet' }); }
    async scanCloudScheduler() { this.addResult('cloudscheduler', { message: 'Service not implemented yet' }); }
    async scanCloudIoT() { this.addResult('cloudiot', { message: 'Service not implemented yet' }); }

    addResult(service, data) {
        this.results[service] = data;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = GCPScanner;
} 