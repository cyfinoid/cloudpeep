/**
 * AWS Cloud Scanner - Comprehensive Service Enumeration
 * Enhanced with aws-inventory coverage and parallel processing
 * Supports 100+ AWS services with multi-region scanning
 */

class AWSScanner {
    constructor() {
        this.regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'eu-north-1', 'ap-southeast-1', 'ap-southeast-2',
            'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
            'sa-east-1', 'ca-central-1'
        ];
        this.results = {};
        this.currentRegion = 'us-east-1';
        this.accountInfo = null;
        this.activeRegions = null;
        this.globalServices = this.getGlobalServices();
        this.serviceDefinitions = this.getServiceDefinitions();
    }

    /**
     * Get global services that don't need regional scanning
     */
    getGlobalServices() {
        return {
            'cloudfront': { region: 'global', skip_regions: [] },
            'route53': { region: 'global', skip_regions: [] },
            'route53domains': { region: 'us-east-1', skip_regions: [] },
            'iam': { region: 'global', skip_regions: [] },
            'organizations': { region: 'global', skip_regions: [] },
            'sts': { region: 'global', skip_regions: [] },
            'cur': { region: 'us-east-1', skip_regions: [] },
            'devicefarm': { region: 'us-west-2', skip_regions: [] }
        };
    }

    /**
     * Enhanced service definitions with global/regional marking
     */
    getServiceDefinitions() {
        return {
            // Certificate Management
            'acm': { 
                name: 'ACM Certificates', 
                category: 'Security',
                global: true,
                apis: ['listCertificates']
            },
            
            // Auto Scaling
            'applicationautoscaling': {
                name: 'Application Auto Scaling',
                category: 'Compute',
                global: false,
                apis: ['describeScalableTargets'],
                namespaces: ['ecs', 'elasticmapreduce', 'ec2', 'appstream', 'dynamodb', 'rds']
            },
            'autoscaling': {
                name: 'EC2 Auto Scaling',
                category: 'Compute',
                global: false,
                apis: ['describeAutoScalingGroups', 'describeLaunchConfigurations']
            },
            
            // CloudFront
            'cloudfront': {
                name: 'CloudFront Distributions',
                category: 'Networking',
                global: true,
                apis: ['listDistributions', 'listStreamingDistributions', 'listCloudFrontOriginAccessIdentities']
            },
            
            // CloudWatch
            'cloudwatch': {
                name: 'CloudWatch',
                category: 'Analytics',
                global: false,
                apis: ['describeAlarms', 'listDashboards', 'listMetrics']
            },
            'cloudwatchevents': {
                name: 'CloudWatch Events',
                category: 'Analytics',
                global: false,
                apis: ['listRules']
            },
            'cloudwatchlogs': {
                name: 'CloudWatch Logs',
                category: 'Analytics',
                global: false,
                apis: ['describeLogGroups', 'describeExportTasks', 'describeDestinations', 'describeMetricFilters', 'describeResourcePolicies']
            },
            
            // Code Services
            'codecommit': {
                name: 'CodeCommit Repositories',
                category: 'Development',
                global: false,
                skip_regions: ['eu-west-3'],
                apis: ['listRepositories']
            },
            'codedeploy': {
                name: 'CodeDeploy',
                category: 'Development',
                global: false,
                apis: ['listApplications', 'listGitHubAccountTokenNames', 'listOnPremisesInstances']
            },
            
            // Cognito
            'cognitoidentity': {
                name: 'Cognito Identity Pools',
                category: 'Security',
                global: false,
                skip_regions: ['ca-central-1', 'eu-west-3', 'sa-east-1', 'us-west-1', 'us-east-2'],
                apis: ['listIdentityPools']
            },
            'cognitoidentityserviceprovider': {
                name: 'Cognito User Pools',
                category: 'Security',
                global: false,
                skip_regions: ['ca-central-1', 'eu-west-3', 'sa-east-1', 'us-west-1', 'us-east-2'],
                apis: ['listUserPools']
            },
            
            // Config Service
            'configservice': {
                name: 'Config Service',
                category: 'Management',
                global: false,
                apis: ['describeConfigRules', 'describeConfigRuleEvaluationStatus', 'describeConfigurationRecorders', 'describeConfigurationRecorderStatus', 'describeDeliveryChannels', 'describeDeliveryChannelStatus']
            },
            
            // Cost & Usage
            'cur': {
                name: 'Cost and Usage Reports',
                category: 'Management',
                global: false,
                region: 'us-east-1',
                apis: ['describeReportDefinitions']
            },
            
            // Device Farm
            'devicefarm': {
                name: 'Device Farm',
                category: 'Development',
                global: false,
                region: 'us-west-2',
                apis: ['listProjects']
            },
            
            // Direct Connect
            'directconnect': {
                name: 'Direct Connect',
                category: 'Networking',
                global: false,
                apis: ['describeConnections', 'describeLags', 'describeVirtualGateways', 'describeVirtualInterfaces']
            },
            
            // DynamoDB
            'dynamodb': {
                name: 'DynamoDB',
                category: 'Database',
                global: false,
                skip_regions: ['ap-southeast-2', 'ap-southeast-1', 'ap-south-1', 'ap-northeast-2', 'ap-northeast-1', 'eu-central-1', 'eu-west-3', 'eu-west-2', 'ca-central-1', 'us-west-1', 'sa-east-1'],
                apis: ['listBackups', 'listGlobalTables', 'listTables']
            },
            'dynamodbstreams': {
                name: 'DynamoDB Streams',
                category: 'Database',
                global: false,
                apis: ['listStreams']
            },
            
            // Inspector
            'inspector': {
                name: 'Inspector',
                category: 'Security',
                global: false,
                skip_regions: ['ap-southeast-1', 'ca-central-1', 'eu-west-2', 'eu-west-3', 'sa-east-1'],
                apis: ['listRulesPackages', 'listAssessmentTargets']
            },
            
            // IoT
            'iot': {
                name: 'IoT',
                category: 'AI/ML',
                global: false,
                skip_regions: ['ap-south-1', 'ca-central-1', 'eu-west-3', 'sa-east-1', 'us-west-1'],
                apis: ['listAuthorizers', 'listCACertificates', 'listCertificates', 'listIndices', 'listJobs', 'listOutgoingCertificates', 'listPolicies', 'listRoleAliases', 'listThingGroups', 'listThingRegistrationTasks', 'listThings', 'listThingTypes', 'listTopicRules']
            },
            
            // Kinesis
            'kinesis': {
                name: 'Kinesis',
                category: 'Analytics',
                global: false,
                apis: ['describeLimits', 'listStreams']
            },
            
            // KMS
            'kms': {
                name: 'KMS',
                category: 'Security',
                global: false,
                apis: ['listAliases', 'listKeys']
            },
            
            // Lambda
            'lambda': {
                name: 'Lambda',
                category: 'Compute',
                global: false,
                apis: ['getAccountSettings', 'listEventSourceMappings', 'listFunctions']
            },
            
            // Machine Learning
            'machinelearning': {
                name: 'Machine Learning',
                category: 'AI/ML',
                global: false,
                skip_regions: ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 'us-east-2', 'us-west-1', 'us-west-2'],
                apis: ['describeBatchPredictions', 'describeEvaluations', 'describeDataSources', 'describeMLModels']
            },
            
            // OpsWorks
            'opsworks': {
                name: 'OpsWorks',
                category: 'Management',
                global: false,
                apis: ['describeStacks']
            },
            
            // Polly
            'polly': {
                name: 'Polly',
                category: 'AI/ML',
                global: false,
                apis: ['listLexicons']
            },
            
            // RDS
            'rds': {
                name: 'RDS',
                category: 'Database',
                global: false,
                apis: ['describeAccountAttributes', 'describeCertificates', 'describeDBClusterParameterGroups', 'describeDBClusters', 'describeDBInstances', 'describeDBParameterGroups', 'describeDBSecurityGroups', 'describeDBSnapshots', 'describeDBSubnetGroups', 'describeEventCategories', 'describeEventSubscriptions', 'describeOptionGroups', 'describeReservedDBInstances', 'describeSourceRegions']
            },
            
            // Redshift
            'redshift': {
                name: 'Redshift',
                category: 'Database',
                global: false,
                apis: ['describeClusterParameterGroups', 'describeClusters', 'describeClusterSecurityGroups', 'describeClusterSnapshots', 'describeClusterSubnetGroups', 'describeClusterVersions', 'describeEventCategories', 'describeEventSubscriptions', 'describeHsmClientCertificates', 'describeHsmConfigurations', 'describeReservedNodes', 'describeSnapshotCopyGrants', 'describeTags']
            },
            
            // Rekognition
            'rekognition': {
                name: 'Rekognition',
                category: 'AI/ML',
                global: false,
                apis: ['listCollections']
            },
            
            // Route53
            'route53': {
                name: 'Route53',
                category: 'Networking',
                global: true,
                apis: ['listHealthChecks', 'listHostedZones', 'listQueryLoggingConfigs', 'listReusableDelegationSets', 'listTrafficPolicies', 'listTrafficPolicyInstances']
            },
            'route53domains': {
                name: 'Route53 Domains',
                category: 'Networking',
                global: false,
                region: 'us-east-1',
                apis: ['listDomains', 'listOperations']
            },
            
            // SES
            'ses': {
                name: 'Simple Email Service',
                category: 'Messaging',
                global: false,
                skip_regions: ['eu-west-2', 'eu-west-3', 'ap-southeast-2', 'us-west-1', 'ap-south-1', 'ap-southeast-1', 'us-east-2', 'eu-central-1', 'ap-northeast-1', 'ca-central-1', 'ap-northeast-2', 'sa-east-1'],
                apis: ['describeActiveReceiptRuleSet', 'listConfigurationSets', 'listCustomVerificationEmailTemplates', 'listIdentities', 'listReceiptFilters', 'listReceiptRuleSets', 'listTemplates', 'listVerifiedEmailAddresses']
            },
            
            // SSM
            'ssm': {
                name: 'Systems Manager',
                category: 'Management',
                global: false,
                apis: ['describeActivations', 'describeAutomationExecutions', 'describeAvailablePatches', 'describeMaintenanceWindows', 'describeParameters', 'describePatchBaselines', 'describePatchGroups', 'listAssociations', 'listCommandInvocations', 'listCommands', 'listDocuments', 'listResourceDataSync']
            },
            
            // Storage Gateway
            'storagegateway': {
                name: 'Storage Gateway',
                category: 'Storage',
                global: false,
                apis: ['listFileShares', 'listGateways', 'listTapes']
            },
            
            // WAF
            'waf': {
                name: 'WAF',
                category: 'Security',
                global: false,
                apis: ['listByteMatchSets', 'listGeoMatchSets', 'listIPSets', 'listRateBasedRules', 'listRegexMatchSets', 'listRegexPatternSets', 'listRuleGroups', 'listRules', 'listSizeConstraintSets', 'listSqlInjectionMatchSets', 'listSubscribedRuleGroups', 'listWebACLs', 'listXssMatchSets']
            }
        };
    }

    async scan(credentials, selectedServices = null) {
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        const scanStartTime = Date.now();
        const scanStartDate = new Date().toISOString();
        
        console.log(`[${scanId}] 🏗️  Initializing enhanced AWS scanner...`);
        console.log(`[${scanId}] 🕐 Scan started at: ${scanStartDate}`);
        
        try {
            console.log(`[${scanId}] 🔐 Validating AWS credentials...`);
            this.validateCredentials(credentials);
            console.log(`[${scanId}] ✅ AWS credentials validated`);
            
            // Initialize AWS SDK
            console.log(`[${scanId}] 🔧 Initializing AWS SDK...`);
            await this.initializeSDK(credentials);
            console.log(`[${scanId}] ✅ AWS SDK initialized successfully`);
            
            // Extract account information
            console.log(`[${scanId}] 🔍 Extracting account information...`);
            await this.extractAccountInfo();
            console.log(`[${scanId}] ✅ Account information extracted:`, this.accountInfo);
            
            // Discover active regions
            console.log(`[${scanId}] 🌍 Discovering active regions...`);
            await this.discoverActiveRegions();
            console.log(`[${scanId}] ✅ Active regions discovered: ${this.regions.length} regions`);
            console.log(`[${scanId}] 📍 Active regions:`, this.activeRegions);
            console.log(`[${scanId}] 📍 Regions to scan:`, this.regions);
            
            // Get available services
            const services = selectedServices || this.getAvailableServices();
            console.log(`[${scanId}] 📋 Services to scan: ${services.length}`, {
                services: services,
                selectedServices: selectedServices ? selectedServices.length : 'ALL'
            });
            
            // Enhanced parallel scanning
            console.log(`[${scanId}] 🚀 Starting enhanced parallel service enumeration...`);
            await this.scanServicesParallel(services);
            
            const scanEndTime = Date.now();
            const scanEndDate = new Date().toISOString();
            const totalDuration = scanEndTime - scanStartTime;
            
            console.log(`[${scanId}] 🕐 Scan ended at: ${scanEndDate}`);
            console.log(`[${scanId}] 🎉 Enhanced AWS scan completed!`, {
                duration: Utils.DataUtils.formatDuration(totalDuration),
                totalServices: services.length,
                accountInfo: this.accountInfo
            });
            
            // Store timing information
            this.scanTiming = {
                startTime: scanStartTime,
                endTime: scanEndTime,
                startDate: scanStartDate,
                endDate: scanEndDate,
                totalDuration: totalDuration,
                formattedDuration: Utils.DataUtils.formatDuration(totalDuration)
            };
            
            return this.getFinalResults();
        } catch (error) {
            const scanEndTime = Date.now();
            const scanEndDate = new Date().toISOString();
            const totalDuration = scanEndTime - scanStartTime;
            
            console.log(`[${scanId}] 🕐 Scan ended at: ${scanEndDate}`);
            console.error(`[${scanId}] 💥 Enhanced AWS scan failed after ${Utils.DataUtils.formatDuration(totalDuration)}:`, error);
            
            // Store timing information even for failed scans
            this.scanTiming = {
                startTime: scanStartTime,
                endTime: scanEndTime,
                startDate: scanStartDate,
                endDate: scanEndDate,
                totalDuration: totalDuration,
                formattedDuration: Utils.DataUtils.formatDuration(totalDuration),
                status: 'failed'
            };
            
            throw new Error(`Enhanced AWS scan failed: ${error.message}`);
        }
    }

    /**
     * Enhanced parallel scanning with global/regional optimization
     */
    async scanServicesParallel(services) {
        const scanPromises = [];
        let completedServices = 0;
        let successfulServices = 0;
        let failedServices = 0;
        
        for (const service of services) {
            const serviceDefinition = this.serviceDefinitions[service];
            if (!serviceDefinition) {
                console.warn(`Service definition not found for: ${service}`);
                continue;
            }
            
            // Determine regions for this service
            const regionsToScan = this.getRegionsForService(service, serviceDefinition);
            
            // Create parallel scan promise for this service
            const servicePromise = this.scanServiceParallel(service, serviceDefinition, regionsToScan)
                .then(() => {
                    completedServices++;
                    successfulServices++;
                    console.log(`✅ [${completedServices}/${services.length}] ${service} completed successfully`);
                })
                .catch((error) => {
                    completedServices++;
                    failedServices++;
                    console.error(`❌ [${completedServices}/${services.length}] ${service} failed:`, error.message);
                    this.addResult(service, { error: error.message });
                });
            
            scanPromises.push(servicePromise);
        }
        
        // Execute all service scans in parallel
        console.log(`🚀 Starting parallel execution of ${scanPromises.length} services...`);
        await Promise.allSettled(scanPromises);
        
        console.log(`📊 Parallel scan completed: ${successfulServices} successful, ${failedServices} failed`);
    }

    /**
     * Get regions to scan for a specific service
     */
    getRegionsForService(service, serviceDefinition) {
        if (serviceDefinition.global) {
            // Global service - only scan in global region
            return ['global'];
        }
        
        if (serviceDefinition.region) {
            // Service restricted to specific region
            return [serviceDefinition.region];
        }
        
        // Regional service - scan all active regions except skipped ones
        const skipRegions = serviceDefinition.skip_regions || [];
        return this.regions.filter(region => !skipRegions.includes(region));
    }

    /**
     * Scan a single service in parallel across regions
     */
    async scanServiceParallel(service, serviceDefinition, regionsToScan) {
        const scanId = Utils.SecurityUtils.generateRandomString(6);
        const serviceStartTime = Date.now();
        
        console.log(`[${scanId}] 🔍 Starting parallel scan for ${service} across ${regionsToScan.length} regions...`);
        
        // Update progress for current service
        if (this.onProgressUpdate) {
            this.onProgressUpdate(service, `Scanning ${service} in parallel...`);
        }
        
        const regionPromises = [];
        const serviceResults = {
            regions: {},
            global: serviceDefinition.global || false,
            totalResources: 0,
            errors: []
        };
        
        for (const region of regionsToScan) {
            const regionPromise = this.scanServiceInRegion(service, serviceDefinition, region)
                .then((regionResult) => {
                    serviceResults.regions[region] = regionResult;
                    serviceResults.totalResources += regionResult.totalResources || 0;
                })
                .catch((error) => {
                    serviceResults.errors.push({
                        region: region,
                        error: error.message
                    });
                    serviceResults.regions[region] = { error: error.message };
                });
            
            regionPromises.push(regionPromise);
        }
        
        // Execute all region scans in parallel
        await Promise.allSettled(regionPromises);
        
        const serviceDuration = Date.now() - serviceStartTime;
        console.log(`[${scanId}] ✅ ${service} completed in ${Utils.DataUtils.formatDuration(serviceDuration)}`);
        
        this.addResult(service, serviceResults);
    }

    /**
     * Scan a service in a specific region
     */
    async scanServiceInRegion(service, serviceDefinition, region) {
        const regionStartTime = Date.now();
        
        // Update detailed progress for region
        if (this.onDetailedProgressUpdate) {
            this.onDetailedProgressUpdate(service, 'region', `Scanning ${region}`, '1/1');
        }
        
        const regionResult = {
            region: region,
            resources: {},
            totalResources: 0,
            scanTime: 0
        };
        
        try {
            // Get service scanner for this service
            const scanner = this.getServiceScanner(service);
            if (scanner) {
                // Temporarily set current region for the scanner
                const originalRegion = this.currentRegion;
                this.currentRegion = region;
                
                // Execute the scanner
                await scanner.call(this);
                
                // Restore original region
                this.currentRegion = originalRegion;
            } else {
                // Use generic API scanning for services without specific scanners
                await this.scanServiceGeneric(service, serviceDefinition, region, regionResult);
            }
            
            regionResult.scanTime = Date.now() - regionStartTime;
            console.log(`✅ ${service} in ${region}: ${regionResult.totalResources} resources in ${Utils.DataUtils.formatDuration(regionResult.scanTime)}`);
            
        } catch (error) {
            console.error(`❌ ${service} in ${region}: ${error.message}`);
            regionResult.error = error.message;
        }
        
        return regionResult;
    }

    /**
     * Generic service scanning using AWS SDK
     */
    async scanServiceGeneric(service, serviceDefinition, region, regionResult) {
        const apis = serviceDefinition.apis || [];
        
        for (const api of apis) {
            try {
                // Create AWS service client
                const awsService = new AWS[service.toUpperCase()]({ region: region });
                
                // Call the API
                const response = await awsService[api]().promise();
                
                // Extract resources from response
                const resources = this.extractResourcesFromResponse(response, api);
                
                regionResult.resources[api] = resources;
                regionResult.totalResources += resources.length;
                
            } catch (error) {
                console.error(`Error calling ${service}.${api} in ${region}:`, error.message);
                regionResult.resources[api] = { error: error.message };
            }
        }
    }

    /**
     * Extract resources from AWS API response
     */
    extractResourcesFromResponse(response, api) {
        // Common response patterns
        const resourceKeys = [
            'Items', 'Instances', 'Functions', 'Tables', 'Clusters',
            'Groups', 'Users', 'Roles', 'Policies', 'Buckets',
            'Distributions', 'Alarms', 'Rules', 'Topics', 'Queues'
        ];
        
        for (const key of resourceKeys) {
            if (response[key]) {
                return response[key];
            }
        }
        
        // If no common pattern found, return the response as-is
        return response;
    }

    getAvailableServices() {
        return Object.keys(this.serviceDefinitions);
    }

    validateCredentials(credentials) {
        if (!credentials.accessKeyId || !credentials.secretAccessKey) {
            throw new Error('AWS Access Key ID and Secret Access Key are required');
        }
    }

    async initializeSDK(credentials) {
        // Load AWS SDK
        if (typeof AWS === 'undefined') {
            throw new Error('AWS SDK not loaded');
        }
        
        // Configure AWS
        AWS.config.update({
            accessKeyId: credentials.accessKeyId,
            secretAccessKey: credentials.secretAccessKey,
            sessionToken: credentials.sessionToken || undefined,
            region: this.currentRegion
        });
    }

    async extractAccountInfo() {
        try {
            const sts = new AWS.STS();
            const callerIdentity = await sts.getCallerIdentity().promise();
            
            this.accountInfo = {
                accountId: callerIdentity.Account,
                userId: callerIdentity.UserId,
                arn: callerIdentity.Arn,
                userType: this.determineUserType(callerIdentity.Arn),
                extractedFromKey: Utils.HoneytokenUtils.extractAccountIdFromKey(AWS.config.credentials.accessKeyId)
            };
            
            console.log('Account information extracted:', this.accountInfo);
        } catch (error) {
            console.error('Error extracting account information:', error);
            // Fallback to extracting from access key
            const extractedAccountId = Utils.HoneytokenUtils.extractAccountIdFromKey(AWS.config.credentials.accessKeyId);
            this.accountInfo = {
                accountId: extractedAccountId,
                userId: 'Unknown',
                arn: 'Unknown',
                userType: 'Unknown',
                extractedFromKey: extractedAccountId,
                error: error.message
            };
        }
    }

    async discoverActiveRegions() {
        try {
            console.log('🔍 Discovering active regions for this account...');
            
            // Use EC2 to discover regions (most reliable method)
            const ec2 = new AWS.EC2();
            const regionsData = await ec2.describeRegions().promise();
            
            console.log('🔍 Raw regions data:', regionsData);
            console.log('🔍 Regions array:', regionsData.Regions);
            
            // Analyze the response structure
            this.analyzeRegionResponse(regionsData);
            
            if (regionsData.Regions && regionsData.Regions.length > 0) {
                console.log('🔍 First region example:', regionsData.Regions[0]);
            }
            
            // Filter regions based on actual response structure
            const activeRegions = regionsData.Regions
                .filter(region => {
                    // All regions with "opt-in-not-required" are available
                    if (region.OptInStatus === 'opt-in-not-required') {
                        console.log(`✅ Region ${region.RegionName} is available (opt-in-not-required)`);
                        return true;
                    }
                    // Log other opt-in statuses for debugging
                    console.log(`🔍 Region ${region.RegionName} has OptInStatus: ${region.OptInStatus}`);
                    return false;
                })
                .map(region => region.RegionName)
                .sort();
            
            console.log(`✅ Discovered ${activeRegions.length} active regions:`, activeRegions);
            
            // If no active regions found, use minimal fallback
            if (activeRegions.length === 0) {
                console.log('⚠️  No active regions found, using minimal fallback list');
                const minimalRegions = this.getMinimalRegionSet();
                
                this.activeRegions = minimalRegions;
                this.regions = minimalRegions;
                
                console.log('📋 Using minimal region set:', minimalRegions);
                return minimalRegions;
            }
            
            // Store the active regions
            this.activeRegions = activeRegions;
            
            // Update the regions list to use only active regions
            this.regions = activeRegions;
            
            return activeRegions;
        } catch (error) {
            console.error('Error discovering active regions:', error);
            console.log('⚠️  Falling back to hardcoded region list');
            
            // Store the original hardcoded list as active regions for fallback
            const fallbackRegions = [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
                'eu-north-1', 'ap-southeast-1', 'ap-southeast-2',
                'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
                'sa-east-1', 'ca-central-1'
            ];
            
            this.activeRegions = fallbackRegions;
            this.regions = fallbackRegions;
            
            return fallbackRegions;
        }
    }

    async getDetailedRegionInfo() {
        try {
            const ec2 = new AWS.EC2({ region: 'us-east-1' });
            const regionsData = await ec2.describeRegions().promise();
            
            const detailedRegions = regionsData.Regions.map(region => ({
                name: region.RegionName,
                endpoint: region.Endpoint,
                optInStatus: region.OptInStatus || 'unknown',
                isAvailable: region.OptInStatus === 'opt-in-not-required'
            }));
            
            return {
                totalRegions: detailedRegions.length,
                availableRegions: detailedRegions.filter(r => r.isAvailable),
                unavailableRegions: detailedRegions.filter(r => !r.isAvailable),
                optInRequiredRegions: detailedRegions.filter(r => r.optInStatus === 'opt-in-required'),
                optInNotRequiredRegions: detailedRegions.filter(r => r.optInStatus === 'opt-in-not-required')
            };
        } catch (error) {
            console.error('Error getting detailed region info:', error);
            return null;
        }
    }

    async testRegionAccess(region) {
        try {
            const ec2 = new AWS.EC2({ region });
            await ec2.describeRegions().promise();
            return true;
        } catch (error) {
            console.error(`❌ No access to region ${region}:`, error.message);
            return false;
        }
    }

    getMinimalRegionSet() {
        // Return a minimal set of commonly available regions
        return [
            'us-east-1',  // N. Virginia - most commonly available
            'us-west-2',  // Oregon - commonly available
            'eu-west-1'   // Ireland - commonly available
        ];
    }

    /**
     * Categorize AWS errors for better reporting
     * @param {Error} error - The AWS error
     * @param {string} region - The region where the error occurred
     * @returns {Object} Categorized error information
     */
    categorizeError(error, region) {
        const errorInfo = {
            region: region,
            error: error.message,
            code: error.code || 'Unknown',
            type: 'unknown'
        };

        // Categorize common AWS errors
        if (error.code === 'AccessDenied' || error.message.includes('Access Denied')) {
            errorInfo.type = 'access_denied';
            errorInfo.description = 'Insufficient permissions to access this service';
        } else if (error.code === 'UnauthorizedOperation') {
            errorInfo.type = 'unauthorized';
            errorInfo.description = 'Unauthorized operation';
        } else if (error.code === 'OptInRequired') {
            errorInfo.type = 'opt_in_required';
            errorInfo.description = 'Service requires opt-in for this region';
        } else if (error.code === 'ServiceUnavailable') {
            errorInfo.type = 'service_unavailable';
            errorInfo.description = 'Service temporarily unavailable';
        } else if (error.code === 'ThrottlingException') {
            errorInfo.type = 'throttling';
            errorInfo.description = 'API rate limit exceeded';
        } else if (error.code === 'InvalidClientTokenId') {
            errorInfo.type = 'invalid_credentials';
            errorInfo.description = 'Invalid or expired credentials';
        }

        return errorInfo;
    }

    analyzeRegionResponse(regionsData) {
        console.log('🔍 Analyzing region response structure...');
        
        if (!regionsData || !regionsData.Regions) {
            console.log('❌ No regions data found');
            return;
        }
        
        console.log(`🔍 Total regions found: ${regionsData.Regions.length}`);
        
        if (regionsData.Regions.length > 0) {
            const firstRegion = regionsData.Regions[0];
            console.log('🔍 First region properties:', Object.keys(firstRegion));
            console.log('🔍 First region full object:', firstRegion);
            
            // Check for common properties
            const properties = ['RegionName', 'Endpoint', 'State', 'OptInStatus'];
            properties.forEach(prop => {
                if (firstRegion.hasOwnProperty(prop)) {
                    console.log(`✅ Property '${prop}' found: ${firstRegion[prop]}`);
                } else {
                    console.log(`❌ Property '${prop}' not found`);
                }
            });
        }
    }

    determineUserType(arn) {
        if (!arn) return 'Unknown';
        
        if (arn.includes(':user/')) {
            return 'IAM User';
        } else if (arn.includes(':role/')) {
            return 'IAM Role';
        } else if (arn.includes(':assumed-role/')) {
            return 'Assumed Role';
        } else if (arn.includes(':root')) {
            return 'Root User';
        } else {
            return 'Unknown';
        }
    }

    async scanEC2() {
        const scanId = Utils.SecurityUtils.generateRandomString(6);
        const serviceStartTime = Date.now();
        
        console.log(`[${scanId}] 🖥️  Starting EC2 scan...`);
        
        const instances = [];
        const vpcs = [];
        const securityGroups = [];
        const subnets = [];
        const volumes = [];
        const snapshots = [];
        const amis = [];

        let regionsScanned = 0;
        let totalInstances = 0;
        let totalVpcs = 0;
        let totalSecurityGroups = 0;

        for (const region of this.regions) {
            const regionStartTime = Date.now();
            regionsScanned++;
            
            console.log(`[${scanId}] 🌍 [${regionsScanned}/${this.regions.length}] Scanning region: ${region}`);
            
            // Update detailed progress for region
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('ec2', 'region', `Scanning region ${region}`, `${regionsScanned}/${this.regions.length}`);
            }
            
            try {
                const ec2 = new AWS.EC2({ region });
                
                // Scan instances
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'instances', `Scanning instances in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning EC2 instances in ${region}...`);
                const instancesData = await ec2.describeInstances().promise();
                const regionInstances = [];
                for (const reservation of instancesData.Reservations) {
                    for (const instance of reservation.Instances) {
                        // Format block device mappings
                        const blockDeviceMappings = instance.BlockDeviceMappings ? 
                            instance.BlockDeviceMappings.map(device => 
                                `${device.DeviceName}: ${device.Ebs ? device.Ebs.VolumeId : 'N/A'}`
                            ).join(', ') : 'None';
                        
                        // Format security groups
                        const securityGroups = instance.SecurityGroups ? 
                            instance.SecurityGroups.map(sg => 
                                `${sg.GroupName} (${sg.GroupId})`
                            ).join(', ') : 'None';
                        
                        regionInstances.push({
                            instanceId: instance.InstanceId,
                            instanceType: instance.InstanceType,
                            state: instance.State.Name,
                            launchTime: instance.LaunchTime,
                            publicIpAddress: instance.PublicIpAddress,
                            privateIpAddress: instance.PrivateIpAddress,
                            iamInstanceProfile: instance.IamInstanceProfile ? instance.IamInstanceProfile.Arn : null,
                            blockDeviceMappings: blockDeviceMappings,
                            vpcId: instance.VpcId,
                            subnetId: instance.SubnetId,
                            securityGroups: securityGroups,
                            region: region
                        });
                    }
                }
                instances.push(...regionInstances);
                totalInstances += regionInstances.length;
                console.log(`[${scanId}] ✅ Found ${regionInstances.length} instances in ${region}`);

                // Scan VPCs
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'vpcs', `Scanning VPCs in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning VPCs in ${region}...`);
                const vpcsData = await ec2.describeVpcs().promise();
                const regionVpcs = [];
                for (const vpc of vpcsData.Vpcs) {
                    regionVpcs.push({
                        vpcId: vpc.VpcId,
                        cidrBlock: vpc.CidrBlock,
                        state: vpc.State,
                        isDefault: vpc.IsDefault,
                        flowLogs: [], // Will be populated separately if needed
                        region: region
                    });
                }
                vpcs.push(...regionVpcs);
                totalVpcs += regionVpcs.length;
                console.log(`[${scanId}] ✅ Found ${regionVpcs.length} VPCs in ${region}`);

                // Scan security groups
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'security-groups', `Scanning security groups in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning security groups in ${region}...`);
                const sgData = await ec2.describeSecurityGroups().promise();
                const regionSecurityGroups = [];
                for (const sg of sgData.SecurityGroups) {
                    regionSecurityGroups.push({
                        id: sg.GroupId,
                        name: sg.GroupName,
                        description: sg.Description,
                        region: region
                    });
                }
                securityGroups.push(...regionSecurityGroups);
                totalSecurityGroups += regionSecurityGroups.length;
                console.log(`[${scanId}] ✅ Found ${regionSecurityGroups.length} security groups in ${region}`);

                // Scan subnets
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'subnets', `Scanning subnets in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning subnets in ${region}...`);
                const subnetsData = await ec2.describeSubnets().promise();
                const regionSubnets = [];
                for (const subnet of subnetsData.Subnets) {
                    regionSubnets.push({
                        id: subnet.SubnetId,
                        cidr: subnet.CidrBlock,
                        availabilityZone: subnet.AvailabilityZone,
                        region: region
                    });
                }
                subnets.push(...regionSubnets);
                console.log(`[${scanId}] ✅ Found ${regionSubnets.length} subnets in ${region}`);

                // Scan volumes
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'volumes', `Scanning volumes in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning volumes in ${region}...`);
                const volumesData = await ec2.describeVolumes().promise();
                const regionVolumes = [];
                for (const volume of volumesData.Volumes) {
                    regionVolumes.push({
                        id: volume.VolumeId,
                        size: volume.Size,
                        type: volume.VolumeType,
                        state: volume.State,
                        region: region
                    });
                }
                volumes.push(...regionVolumes);
                console.log(`[${scanId}] ✅ Found ${regionVolumes.length} volumes in ${region}`);

                // Scan snapshots
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'snapshots', `Scanning snapshots in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning snapshots in ${region}...`);
                const snapshotsData = await ec2.describeSnapshots({ OwnerIds: ['self'] }).promise();
                const regionSnapshots = [];
                for (const snapshot of snapshotsData.Snapshots) {
                    regionSnapshots.push({
                        id: snapshot.SnapshotId,
                        volumeId: snapshot.VolumeId,
                        size: snapshot.VolumeSize,
                        state: snapshot.State,
                        region: region
                    });
                }
                snapshots.push(...regionSnapshots);
                console.log(`[${scanId}] ✅ Found ${regionSnapshots.length} snapshots in ${region}`);

                // Scan AMIs
                if (this.onDetailedProgressUpdate) {
                    this.onDetailedProgressUpdate('ec2', 'amis', `Scanning AMIs in ${region}`, `${regionsScanned}/${this.regions.length}`);
                }
                console.log(`[${scanId}] 🔍 Scanning AMIs in ${region}...`);
                const amisData = await ec2.describeImages({ Owners: ['self'] }).promise();
                const regionAmis = [];
                for (const ami of amisData.Images) {
                    regionAmis.push({
                        id: ami.ImageId,
                        name: ami.Name,
                        description: ami.Description,
                        architecture: ami.Architecture,
                        region: region
                    });
                }
                amis.push(...regionAmis);
                console.log(`[${scanId}] ✅ Found ${regionAmis.length} AMIs in ${region}`);

                const regionDuration = Date.now() - regionStartTime;
                console.log(`[${scanId}] ✅ Region ${region} completed in ${Utils.DataUtils.formatDuration(regionDuration)}`);

            } catch (error) {
                const regionDuration = Date.now() - regionStartTime;
                console.error(`[${scanId}] ❌ Error scanning EC2 in ${region} after ${Utils.DataUtils.formatDuration(regionDuration)}:`, error);
            }
        }

        const serviceDuration = Date.now() - serviceStartTime;
        console.log(`[${scanId}] 🎉 EC2 scan completed in ${Utils.DataUtils.formatDuration(serviceDuration)}`, {
            totalInstances: totalInstances,
            totalVpcs: totalVpcs,
            totalSecurityGroups: totalSecurityGroups,
            totalSubnets: subnets.length,
            totalVolumes: volumes.length,
            totalSnapshots: snapshots.length,
            totalAmis: amis.length,
            regionsScanned: regionsScanned
        });

        this.addResult('ec2', {
            instances,
            vpcs,
            securityGroups,
            subnets,
            volumes,
            snapshots,
            amis
        });
    }

    async scanLambda() {
        const functions = [];
        
        for (const region of this.regions) {
            try {
                const lambda = new AWS.Lambda({ region });
                const functionsData = await lambda.listFunctions().promise();
                
                for (const func of functionsData.Functions) {
                    try {
                        // Get detailed function configuration including environment variables
                        const functionConfig = await lambda.getFunctionConfiguration({
                            FunctionName: func.FunctionName
                        }).promise();
                        
                        // Extract environment variables
                        const environmentVariables = functionConfig.Environment ? 
                            functionConfig.Environment.Variables || {} : {};
                        
                        // Check for potentially sensitive environment variables
                        const sensitiveVars = [];
                        const sensitivePatterns = [
                            /password/i, /secret/i, /key/i, /token/i, /credential/i,
                            /api_key/i, /api_secret/i, /access_key/i, /secret_key/i,
                            /auth/i, /login/i, /private/i, /internal/i
                        ];
                        
                        Object.keys(environmentVariables).forEach(key => {
                            if (sensitivePatterns.some(pattern => pattern.test(key))) {
                                sensitiveVars.push(key);
                            }
                        });
                        
                        // Format environment variables for display
                        const envVarCount = Object.keys(environmentVariables).length;
                        const envVarSummary = envVarCount > 0 ? 
                            `${envVarCount} variables` : 'None';
                        
                        // Format environment variables as a readable string
                        const envVarString = Object.keys(environmentVariables).length > 0 ? 
                            Object.entries(environmentVariables)
                                .map(([key, value]) => `${key}=${value}`)
                                .join(', ') : 'None';
                        
                        functions.push({
                            functionName: func.FunctionName,
                            runtime: func.Runtime,
                            handler: func.Handler,
                            codeSize: func.CodeSize,
                            description: func.Description,
                            timeout: functionConfig.Timeout,
                            memorySize: functionConfig.MemorySize,
                            role: functionConfig.Role,
                            environmentVariables: envVarString,
                            sensitiveEnvironmentVariables: sensitiveVars.length > 0 ? sensitiveVars.join(', ') : 'None',
                            hasEnvironmentVariables: Object.keys(environmentVariables).length > 0,
                            region: region
                        });
                    } catch (error) {
                        // If we can't get detailed config, still include basic function info
                        console.warn(`Could not get detailed config for Lambda function ${func.FunctionName}:`, error);
                        functions.push({
                            functionName: func.FunctionName,
                            runtime: func.Runtime,
                            handler: func.Handler,
                            codeSize: func.CodeSize,
                            description: func.Description,
                            timeout: null,
                            memorySize: null,
                            role: null,
                            environmentVariables: 'None',
                            sensitiveEnvironmentVariables: 'None',
                            hasEnvironmentVariables: false,
                            region: region
                        });
                    }
                }
            } catch (error) {
                console.error(`Error scanning Lambda in ${region}:`, error);
            }
        }

        this.addResult('lambda', { functions });
    }

    async scanECS() {
        const clusters = [];
        
        for (const region of this.regions) {
            try {
                const ecs = new AWS.ECS({ region });
                const clustersData = await ecs.listClusters().promise();
                
                for (const clusterArn of clustersData.clusterArns) {
                    const clusterDetails = await ecs.describeClusters({ clusters: [clusterArn] }).promise();
                    const cluster = clusterDetails.clusters[0];
                    
                    clusters.push({
                        name: cluster.clusterName,
                        arn: cluster.clusterArn,
                        status: cluster.status,
                        runningTasksCount: cluster.runningTasksCount,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning ECS in ${region}:`, error);
            }
        }

        this.addResult('ecs', { clusters });
    }

    async scanEKS() {
        // Check if EKS is available in the AWS SDK
        if (typeof AWS.EKS !== "function") {
            console.warn("AWS.EKS is not available in the loaded AWS SDK.");
            this.addUnimplementedService('eks');
            return;
        }
        const clusters = [];
        
        for (const region of this.regions) {
            try {
                const eks = new AWS.EKS({ region });
                const clustersData = await eks.listClusters().promise();
                
                for (const clusterName of clustersData.clusters) {
                    const clusterDetails = await eks.describeCluster({ name: clusterName }).promise();
                    const cluster = clusterDetails.cluster;
                    
                    clusters.push({
                        name: cluster.name,
                        arn: cluster.arn,
                        version: cluster.version,
                        status: cluster.status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning EKS in ${region}:`, error);
            }
        }

        this.addResult('eks', { clusters });
    }

    // Storage Services
    /**
     * S3 SCANNING IS OUT OF SCOPE
     * 
     * S3 (Simple Storage Service) scanning has been intentionally excluded from this project
     * due to the following considerations:
     * 
     * 1. **Security Complexity**: S3 buckets can contain sensitive data and require
     *    specialized security scanning approaches
     * 2. **Compliance Requirements**: S3 scanning may require specific compliance
     *    considerations (GDPR, HIPAA, etc.)
     * 3. **Data Privacy**: Automated scanning of S3 buckets could potentially access
     *    or expose sensitive customer data
     * 4. **Legal Implications**: Scanning S3 buckets without proper authorization
     *    could have legal consequences
     * 5. **Scope Management**: This project focuses on infrastructure enumeration
     *    rather than data scanning
     * 
     * For S3 security assessment, consider using specialized tools like:
     * - AWS Config
     * - S3 Security Best Practices
     * - Dedicated S3 security scanners
     * - Manual security reviews
     */
    
    /**
     * Get information about out-of-scope services
     * @returns {Object} Out-of-scope services information
     */
    getOutOfScopeServices() {
        return {
            s3: {
                service: 'Simple Storage Service (S3)',
                reason: 'Data privacy and security considerations',
                description: 'S3 buckets may contain sensitive data requiring specialized security assessment',
                risks: [
                    'Potential access to sensitive customer data',
                    'Legal and compliance implications',
                    'Data privacy violations',
                    'Unauthorized data exposure'
                ],
                alternatives: [
                    'AWS Config for S3 compliance monitoring',
                    'Manual security reviews and audits',
                    'Dedicated S3 security scanners',
                    'AWS S3 Security Best Practices',
                    'S3 bucket policy analysis tools'
                ],
                scope_note: 'This project focuses on infrastructure enumeration rather than data scanning'
            }
        };
    }

    /**
     * Get S3 exclusion notice for display
     * @returns {Object} S3 exclusion notice
     */
    getS3ExclusionNotice() {
        return {
            type: 'exclusion_notice',
            service: 'S3 (Simple Storage Service)',
            title: '⚠️ S3 Scanning Excluded',
            message: 'S3 bucket scanning is out of scope for this project at this point due to implementational limitations.',
            details: [
                'S3 buckets may contain sensitive customer data',
                'Automated scanning could violate data privacy regulations',
                'Legal and compliance implications of data access',
                'This tool focuses on infrastructure enumeration, not data scanning'
            ],
            recommendations: [
                'Use AWS Config for S3 compliance monitoring',
                'Perform manual security reviews and audits',
                'Use dedicated S3 security assessment tools',
                'Follow AWS S3 Security Best Practices'
            ],
            icon: '🛡️'
        };
    }



    parseXML(xmlString) {
        // Simple XML parser - in production you'd want a proper XML parser
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, 'text/xml');
        
        // Convert XML to JSON
        return this.xmlToJson(xmlDoc);
    }

    xmlToJson(xml) {
        // Simple XML to JSON converter
        const obj = {};
        
        if (xml.nodeType === 1) { // element
            if (xml.attributes.length > 0) {
                obj['@attributes'] = {};
                for (let j = 0; j < xml.attributes.length; j++) {
                    const attribute = xml.attributes.item(j);
                    obj['@attributes'][attribute.nodeName] = attribute.nodeValue;
                }
            }
        } else if (xml.nodeType === 3) { // text
            obj = xml.nodeValue;
        }
        
        if (xml.hasChildNodes()) {
            for (let i = 0; i < xml.childNodes.length; i++) {
                const item = xml.childNodes.item(i);
                const nodeName = item.nodeName;
                
                if (typeof(obj[nodeName]) === 'undefined') {
                    obj[nodeName] = this.xmlToJson(item);
                } else {
                    if (typeof(obj[nodeName].push) === 'undefined') {
                        const old = obj[nodeName];
                        obj[nodeName] = [];
                        obj[nodeName].push(old);
                    }
                    obj[nodeName].push(this.xmlToJson(item));
                }
            }
        }
        
        return obj;
    }

    async scanEFS() {
        const fileSystems = [];
        
        for (const region of this.regions) {
            try {
                const efs = new AWS.EFS({ region });
                const fileSystemsData = await efs.describeFileSystems().promise();
                
                for (const fs of fileSystemsData.FileSystems) {
                    fileSystems.push({
                        id: fs.FileSystemId,
                        name: fs.Name,
                        sizeInBytes: fs.SizeInBytes,
                        state: fs.LifeCycleState,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning EFS in ${region}:`, error);
            }
        }

        this.addResult('efs', { fileSystems });
    }

    // Database Services
    async scanRDS() {
        const instances = [];
        
        for (const region of this.regions) {
            try {
                const rds = new AWS.RDS({ region });
                const instancesData = await rds.describeDBInstances().promise();
                
                for (const instance of instancesData.DBInstances) {
                    instances.push({
                        dbInstanceIdentifier: instance.DBInstanceIdentifier,
                        engine: instance.Engine,
                        dbInstanceStatus: instance.DBInstanceStatus,
                        dbInstanceClass: instance.DBInstanceClass,
                        publiclyAccessible: instance.PubliclyAccessible,
                        storageEncrypted: instance.StorageEncrypted,
                        backupRetentionPeriod: instance.BackupRetentionPeriod,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning RDS in ${region}:`, error);
            }
        }

        this.addResult('rds', { instances });
    }

    async scanDynamoDB() {
        const tables = [];
        
        for (const region of this.regions) {
            try {
                const dynamodb = new AWS.DynamoDB({ region });
                const tablesData = await dynamodb.listTables().promise();
                
                for (const tableName of tablesData.TableNames) {
                    const tableDetails = await dynamodb.describeTable({ TableName: tableName }).promise();
                    const table = tableDetails.Table;
                    
                    tables.push({
                        name: table.TableName,
                        status: table.TableStatus,
                        itemCount: table.ItemCount,
                        sizeBytes: table.TableSizeBytes,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning DynamoDB in ${region}:`, error);
            }
        }

        this.addResult('dynamodb', { tables });
    }

    // Security Services
    async scanIAM() {
        try {
            const iam = new AWS.IAM();
            const results = {
                users: [],
                roles: [],
                groups: [],
                policies: [],
                accessKeys: []
            };

            // Scan users
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('iam', 'users', 'Scanning IAM users', '1/5');
            }
            const usersData = await iam.listUsers().promise();
            for (const user of usersData.Users) {
                results.users.push({
                    userName: user.UserName,
                    arn: user.Arn,
                    createDate: user.CreateDate
                });
            }

            // Scan roles
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('iam', 'roles', 'Scanning IAM roles', '2/5');
            }
            const rolesData = await iam.listRoles().promise();
            for (const role of rolesData.Roles) {
                results.roles.push({
                    roleName: role.RoleName,
                    arn: role.Arn,
                    createDate: role.CreateDate
                });
            }

            // Scan groups
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('iam', 'groups', 'Scanning IAM groups', '3/5');
            }
            const groupsData = await iam.listGroups().promise();
            for (const group of groupsData.Groups) {
                results.groups.push({
                    groupName: group.GroupName,
                    arn: group.Arn,
                    createDate: group.CreateDate
                });
            }

            // Scan policies
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('iam', 'policies', 'Scanning IAM policies', '4/5');
            }
            const policiesData = await iam.listPolicies({ Scope: 'Local' }).promise();
            for (const policy of policiesData.Policies) {
                try {
                    // Get policy document for security analysis
                    const policyVersion = await iam.getPolicyVersion({
                        PolicyArn: policy.Arn,
                        VersionId: policy.DefaultVersionId
                    }).promise();
                    
                    results.policies.push({
                        policyName: policy.PolicyName,
                        arn: policy.Arn,
                        createDate: policy.CreateDate,
                        document: policyVersion.PolicyVersion.Document
                    });
                } catch (error) {
                    // If we can't get the policy document, still include the policy
                    results.policies.push({
                        policyName: policy.PolicyName,
                        arn: policy.Arn,
                        createDate: policy.CreateDate,
                        document: null
                    });
                }
            }

            // Scan access keys for each user
            if (this.onDetailedProgressUpdate) {
                this.onDetailedProgressUpdate('iam', 'access-keys', 'Scanning access keys', '5/5');
            }
            for (const user of results.users) {
                try {
                    const accessKeysData = await iam.listAccessKeys({ UserName: user.userName }).promise();
                    for (const key of accessKeysData.AccessKeyMetadata) {
                        results.accessKeys.push({
                            accessKeyId: key.AccessKeyId,
                            userName: key.UserName,
                            status: key.Status,
                            createDate: key.CreateDate
                        });
                    }
                } catch (error) {
                    console.error(`Error scanning access keys for user ${user.userName}:`, error);
                }
            }

            this.addResult('iam', results);
        } catch (error) {
            console.error('Error scanning IAM:', error);
            this.addResult('iam', { error: error.message });
        }
    }



    async scanCloudFront() {
        try {
            const cloudfront = new AWS.CloudFront();
            const distributionsData = await cloudfront.listDistributions().promise();
            const distributions = [];
            
            for (const dist of distributionsData.DistributionList.Items) {
                distributions.push({
                    id: dist.Id,
                    domainName: dist.DomainName,
                    status: dist.Status,
                    enabled: dist.Enabled
                });
            }

            this.addResult('cloudfront', { distributions });
        } catch (error) {
            this.addResult('cloudfront', { error: error.message });
        }
    }

    async scanSNS() {
        const topics = [];
        
        for (const region of this.regions) {
            try {
                const sns = new AWS.SNS({ region });
                const topicsData = await sns.listTopics().promise();
                
                for (const topic of topicsData.Topics) {
                    topics.push({
                        arn: topic.TopicArn,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning SNS in ${region}:`, error);
            }
        }

        this.addResult('sns', { topics });
    }

    async scanSQS() {
        const queues = [];
        
        for (const region of this.regions) {
            try {
                const sqs = new AWS.SQS({ region });
                const queuesData = await sqs.listQueues().promise();
                
                for (const queueUrl of queuesData.QueueUrls) {
                    queues.push({
                        url: queueUrl,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning SQS in ${region}:`, error);
            }
        }

        this.addResult('sqs', { queues });
    }

    // Implemented AWS Service Scanners
    async scanElasticBeanstalk() {
        const environments = [];
        
        for (const region of this.regions) {
            try {
                const elasticbeanstalk = new AWS.ElasticBeanstalk({ region });
                const environmentsData = await elasticbeanstalk.describeEnvironments().promise();
                
                for (const env of environmentsData.Environments) {
                    environments.push({
                        environmentId: env.EnvironmentId,
                        environmentName: env.EnvironmentName,
                        applicationName: env.ApplicationName,
                        status: env.Status,
                        health: env.Health,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Elastic Beanstalk in ${region}:`, error);
            }
        }

        this.addResult('elasticbeanstalk', { environments });
    }

    async scanRoute53() {
        try {
            const route53 = new AWS.Route53();
            const results = {
                hostedZones: [],
                healthChecks: []
            };

            // Scan hosted zones
            const hostedZonesData = await route53.listHostedZones().promise();
            for (const zone of hostedZonesData.HostedZones) {
                results.hostedZones.push({
                    id: zone.Id,
                    name: zone.Name,
                    callerReference: zone.CallerReference,
                    config: zone.Config
                });
            }

            // Scan health checks
            const healthChecksData = await route53.listHealthChecks().promise();
            for (const check of healthChecksData.HealthChecks) {
                results.healthChecks.push({
                    id: check.Id,
                    callerReference: check.CallerReference,
                    healthCheckConfig: check.HealthCheckConfig
                });
            }

            this.addResult('route53', results);
        } catch (error) {
            console.error('Error scanning Route53:', error);
            this.addResult('route53', { error: error.message });
        }
    }

    async scanCloudWatch() {
        const alarms = [];
        const dashboards = [];
        
        for (const region of this.regions) {
            try {
                const cloudwatch = new AWS.CloudWatch({ region });
                
                // Scan alarms
                const alarmsData = await cloudwatch.describeAlarms().promise();
                for (const alarm of alarmsData.MetricAlarms) {
                    alarms.push({
                        alarmName: alarm.AlarmName,
                        metricName: alarm.MetricName,
                        namespace: alarm.Namespace,
                        stateValue: alarm.StateValue,
                        region: region
                    });
                }

                // Scan dashboards
                const dashboardsData = await cloudwatch.listDashboards().promise();
                for (const dashboard of dashboardsData.DashboardEntries) {
                    dashboards.push({
                        dashboardName: dashboard.DashboardName,
                        dashboardArn: dashboard.DashboardArn,
                        lastModified: dashboard.LastModified,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning CloudWatch in ${region}:`, error);
            }
        }

        this.addResult('cloudwatch', { alarms, dashboards });
    }

    async scanCodePipeline() {
        const pipelines = [];
        
        for (const region of this.regions) {
            try {
                const codepipeline = new AWS.CodePipeline({ region });
                const pipelinesData = await codepipeline.listPipelines().promise();
                
                for (const pipeline of pipelinesData.pipelines) {
                    pipelines.push({
                        name: pipeline.name,
                        version: pipeline.version,
                        created: pipeline.created,
                        updated: pipeline.updated,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning CodePipeline in ${region}:`, error);
            }
        }

        this.addResult('codepipeline', { pipelines });
    }

    async scanSageMaker() {
        // Check if SageMaker is available in the AWS SDK
        if (typeof AWS.SageMaker !== "function") {
            console.warn("AWS.SageMaker is not available in the loaded AWS SDK.");
            this.addUnimplementedService('sagemaker');
            return;
        }
        
        const notebooks = [];
        const models = [];
        
        for (const region of this.regions) {
            try {
                const sagemaker = new AWS.SageMaker({ region });
                
                // Scan notebook instances
                const notebooksData = await sagemaker.listNotebookInstances().promise();
                for (const notebook of notebooksData.NotebookInstances) {
                    notebooks.push({
                        notebookInstanceName: notebook.NotebookInstanceName,
                        notebookInstanceStatus: notebook.NotebookInstanceStatus,
                        instanceType: notebook.InstanceType,
                        region: region
                    });
                }

                // Scan models
                const modelsData = await sagemaker.listModels().promise();
                for (const model of modelsData.Models) {
                    models.push({
                        modelName: model.ModelName,
                        modelArn: model.ModelArn,
                        creationTime: model.CreationTime,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning SageMaker in ${region}:`, error);
            }
        }

        this.addResult('sagemaker', { notebooks, models });
    }

    async scanSecretsManager() {
        const secrets = [];
        
        for (const region of this.regions) {
            try {
                const secretsmanager = new AWS.SecretsManager({ region });
                const secretsData = await secretsmanager.listSecrets().promise();
                
                for (const secret of secretsData.SecretList) {
                    secrets.push({
                        arn: secret.ARN,
                        name: secret.Name,
                        description: secret.Description,
                        lastChangedDate: secret.LastChangedDate,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Secrets Manager in ${region}:`, error);
            }
        }

        this.addResult('secretsmanager', { secrets });
    }

    async scanGlue() {
        // Check if Glue is available in the AWS SDK
        if (typeof AWS.Glue !== "function") {
            console.warn("AWS.Glue is not available in the loaded AWS SDK.");
            this.addUnimplementedService('glue');
            return;
        }
        
        const databases = [];
        const crawlers = [];
        
        for (const region of this.regions) {
            try {
                const glue = new AWS.Glue({ region });
                
                // Scan databases
                const databasesData = await glue.getDatabases().promise();
                for (const database of databasesData.DatabaseList) {
                    databases.push({
                        name: database.Name,
                        description: database.Description,
                        locationUri: database.LocationUri,
                        region: region
                    });
                }

                // Scan crawlers
                const crawlersData = await glue.getCrawlers().promise();
                for (const crawler of crawlersData.Crawlers) {
                    crawlers.push({
                        name: crawler.Name,
                        role: crawler.Role,
                        state: crawler.State,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Glue in ${region}:`, error);
            }
        }

        this.addResult('glue', { databases, crawlers });
    }

    async scanStepFunctions() {
        // Check if StepFunctions is available in the AWS SDK
        if (typeof AWS.StepFunctions !== "function") {
            console.warn("AWS.StepFunctions is not available in the loaded AWS SDK.");
            this.addUnimplementedService('stepfunctions');
            return;
        }
        
        const stateMachines = [];
        
        for (const region of this.regions) {
            try {
                const stepfunctions = new AWS.StepFunctions({ region });
                const stateMachinesData = await stepfunctions.listStateMachines().promise();
                
                for (const stateMachine of stateMachinesData.stateMachines) {
                    stateMachines.push({
                        name: stateMachine.name,
                        stateMachineArn: stateMachine.stateMachineArn,
                        type: stateMachine.type,
                        creationDate: stateMachine.creationDate,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Step Functions in ${region}:`, error);
            }
        }

        this.addResult('stepfunctions', { stateMachines });
    }

    async scanCloudTrail() {
        try {
            const cloudtrail = new AWS.CloudTrail({ region: 'us-east-1' });
            const trails = [];

            const trailsData = await cloudtrail.describeTrails().promise();
            for (const trail of trailsData.trailList) {
                trails.push({
                    name: trail.Name,
                    s3BucketName: trail.S3BucketName,
                    s3KeyPrefix: trail.S3KeyPrefix,
                    isMultiRegionTrail: trail.IsMultiRegionTrail,
                    homeRegion: trail.HomeRegion
                });
            }

            this.addResult('cloudtrail', { trails });
        } catch (error) {
            console.error('Error scanning CloudTrail:', error);
            this.addResult('cloudtrail', { error: error.message });
        }
    }

    async scanKinesis() {
        const streams = [];
        
        for (const region of this.regions) {
            try {
                const kinesis = new AWS.Kinesis({ region });
                const streamsData = await kinesis.listStreams().promise();
                
                for (const streamName of streamsData.StreamNames) {
                    const streamDetails = await kinesis.describeStream({ StreamName: streamName }).promise();
                    const stream = streamDetails.StreamDescription;
                    
                    streams.push({
                        streamName: stream.StreamName,
                        streamArn: stream.StreamARN,
                        streamStatus: stream.StreamStatus,
                        shardCount: stream.Shards.length,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Kinesis in ${region}:`, error);
            }
        }

        this.addResult('kinesis', { streams });
    }

    async scanRedshift() {
        const clusters = [];
        
        for (const region of this.regions) {
            try {
                const redshift = new AWS.Redshift({ region });
                const clustersData = await redshift.describeClusters().promise();
                
                for (const cluster of clustersData.Clusters) {
                    clusters.push({
                        clusterIdentifier: cluster.ClusterIdentifier,
                        nodeType: cluster.NodeType,
                        clusterStatus: cluster.ClusterStatus,
                        numberOfNodes: cluster.NumberOfNodes,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Redshift in ${region}:`, error);
            }
        }

        this.addResult('redshift', { clusters });
    }

    async scanElastiCache() {
        const clusters = [];
        
        for (const region of this.regions) {
            try {
                const elasticache = new AWS.ElastiCache({ region });
                const clustersData = await elasticache.describeCacheClusters().promise();
                
                for (const cluster of clustersData.CacheClusters) {
                    clusters.push({
                        cacheClusterId: cluster.CacheClusterId,
                        engine: cluster.Engine,
                        cacheClusterStatus: cluster.CacheClusterStatus,
                        numCacheNodes: cluster.NumCacheNodes,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning ElastiCache in ${region}:`, error);
            }
        }

        this.addResult('elasticache', { clusters });
    }

    async scanAPIGateway() {
        const restApis = [];
        
        for (const region of this.regions) {
            try {
                const apigateway = new AWS.APIGateway({ region });
                const apisData = await apigateway.getRestApis().promise();
                
                for (const api of apisData.items) {
                    restApis.push({
                        id: api.id,
                        name: api.name,
                        description: api.description,
                        createdDate: api.createdDate,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning API Gateway in ${region}:`, error);
            }
        }

        this.addResult('apigateway', { restApis });
    }

    async scanCloudFormation() {
        const stacks = [];
        
        for (const region of this.regions) {
            try {
                const cloudformation = new AWS.CloudFormation({ region });
                const stacksData = await cloudformation.listStacks().promise();
                
                for (const stack of stacksData.StackSummaries) {
                    stacks.push({
                        stackId: stack.StackId,
                        stackName: stack.StackName,
                        stackStatus: stack.StackStatus,
                        creationTime: stack.CreationTime,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning CloudFormation in ${region}:`, error);
            }
        }

        this.addResult('cloudformation', { stacks });
    }

    async scanAppSync() {
        // Check if AppSync is available in the AWS SDK
        if (typeof AWS.AppSync !== "function") {
            console.warn("AWS.AppSync is not available in the loaded AWS SDK.");
            this.addUnimplementedService('appsync');
            return;
        }
        
        const apis = [];
        
        for (const region of this.regions) {
            try {
                const appsync = new AWS.AppSync({ region });
                const apisData = await appsync.listGraphqlApis().promise();
                
                for (const api of apisData.graphqlApis) {
                    apis.push({
                        apiId: api.apiId,
                        name: api.name,
                        authenticationType: api.authenticationType,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning AppSync in ${region}:`, error);
            }
        }

        this.addResult('appsync', { apis });
    }

    async scanSSM() {
        const parameters = [];
        const documents = [];
        
        for (const region of this.regions) {
            try {
                const ssm = new AWS.SSM({ region });
                
                // Scan parameters
                const parametersData = await ssm.describeParameters().promise();
                for (const parameter of parametersData.Parameters) {
                    parameters.push({
                        name: parameter.Name,
                        type: parameter.Type,
                        description: parameter.Description,
                        region: region
                    });
                }

                // Scan documents
                const documentsData = await ssm.listDocuments().promise();
                for (const document of documentsData.DocumentIdentifiers) {
                    documents.push({
                        name: document.Name,
                        owner: document.Owner,
                        documentType: document.DocumentType,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning SSM in ${region}:`, error);
            }
        }

        this.addResult('ssm', { parameters, documents });
    }

    async scanElasticTranscoder() {
        const pipelines = [];
        
        for (const region of this.regions) {
            try {
                const elastictranscoder = new AWS.ElasticTranscoder({ region });
                const pipelinesData = await elastictranscoder.listPipelines().promise();
                
                for (const pipeline of pipelinesData.Pipelines) {
                    pipelines.push({
                        id: pipeline.Id,
                        name: pipeline.Name,
                        status: pipeline.Status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Elastic Transcoder in ${region}:`, error);
            }
        }

        this.addResult('elastictranscoder', { pipelines });
    }

    async scanDataPipeline() {
        // Check if DataPipeline is available in the AWS SDK
        if (typeof AWS.DataPipeline !== "function") {
            console.warn("AWS.DataPipeline is not available in the loaded AWS SDK.");
            this.addUnimplementedService('datapipeline');
            return;
        }
        
        const pipelines = [];
        
        for (const region of this.regions) {
            try {
                const datapipeline = new AWS.DataPipeline({ region });
                const pipelinesData = await datapipeline.listPipelines().promise();
                
                for (const pipeline of pipelinesData.pipelineIdList) {
                    pipelines.push({
                        id: pipeline.id,
                        name: pipeline.name,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Data Pipeline in ${region}:`, error);
            }
        }

        this.addResult('datapipeline', { pipelines });
    }

    async scanMediaConvert() {
        // Check if MediaConvert is available in the AWS SDK
        if (typeof AWS.MediaConvert !== "function") {
            console.warn("AWS.MediaConvert is not available in the loaded AWS SDK.");
            this.addUnimplementedService('mediaconvert');
            return;
        }
        
        const queues = [];
        
        for (const region of this.regions) {
            try {
                const mediaconvert = new AWS.MediaConvert({ region });
                const queuesData = await mediaconvert.listQueues().promise();
                
                for (const queue of queuesData.Queues) {
                    queues.push({
                        name: queue.Name,
                        arn: queue.Arn,
                        type: queue.Type,
                        status: queue.Status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning MediaConvert in ${region}:`, error);
            }
        }

        this.addResult('mediaconvert', { queues });
    }

    async scanStorageGateway() {
        const gateways = [];
        
        for (const region of this.regions) {
            try {
                const storagegateway = new AWS.StorageGateway({ region });
                const gatewaysData = await storagegateway.listGateways().promise();
                
                for (const gateway of gatewaysData.Gateways) {
                    gateways.push({
                        gatewayId: gateway.GatewayId,
                        gatewayName: gateway.GatewayName,
                        gatewayType: gateway.GatewayType,
                        gatewayState: gateway.GatewayState,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Storage Gateway in ${region}:`, error);
            }
        }

        this.addResult('storagegateway', { gateways });
    }

    async scanWorkSpaces() {
        // Check if WorkSpaces is available in the AWS SDK
        if (typeof AWS.WorkSpaces !== "function") {
            console.warn("AWS.WorkSpaces is not available in the loaded AWS SDK.");
            this.addUnimplementedService('workspaces');
            return;
        }
        
        const workspaces = [];
        
        for (const region of this.regions) {
            try {
                const workspacesClient = new AWS.WorkSpaces({ region });
                const workspacesData = await workspacesClient.describeWorkspaces().promise();
                
                for (const workspace of workspacesData.Workspaces) {
                    workspaces.push({
                        workspaceId: workspace.WorkspaceId,
                        userName: workspace.UserName,
                        workspaceState: workspace.State,
                        bundleId: workspace.BundleId,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning WorkSpaces in ${region}:`, error);
            }
        }

        this.addResult('workspaces', { workspaces });
    }

    async scanCloud9() {
        // Check if Cloud9 is available in the AWS SDK
        if (typeof AWS.Cloud9 !== "function") {
            console.warn("AWS.Cloud9 is not available in the loaded AWS SDK.");
            this.addUnimplementedService('cloud9');
            return;
        }
        
        const environments = [];
        
        for (const region of this.regions) {
            try {
                const cloud9 = new AWS.Cloud9({ region });
                const environmentsData = await cloud9.listEnvironments().promise();
                
                for (const environmentId of environmentsData.environmentIds) {
                    const environmentDetails = await cloud9.describeEnvironments({ environmentIds: [environmentId] }).promise();
                    const environment = environmentDetails.environments[0];
                    
                    environments.push({
                        id: environment.id,
                        name: environment.name,
                        description: environment.description,
                        type: environment.type,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Cloud9 in ${region}:`, error);
            }
        }

        this.addResult('cloud9', { environments });
    }

    async scanLex() {
        // Check if Lex is available in the AWS SDK
        if (typeof AWS.LexModelBuildingService !== "function") {
            console.warn("AWS.LexModelBuildingService is not available in the loaded AWS SDK.");
            this.addUnimplementedService('lex');
            return;
        }
        
        const bots = [];
        const accessDeniedRegions = [];
        const errorRegions = [];
        
        for (const region of this.regions) {
            try {
                const lex = new AWS.LexModelBuildingService({ region });
                const botsData = await lex.getBots().promise();
                
                for (const bot of botsData.bots) {
                    bots.push({
                        name: bot.name,
                        version: bot.version,
                        status: bot.status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Lex in ${region}:`, error);
                
                // Categorize errors using the utility method
                const categorizedError = this.categorizeError(error, region);
                
                if (categorizedError.type === 'access_denied') {
                    accessDeniedRegions.push(categorizedError);
                } else {
                    errorRegions.push(categorizedError);
                }
            }
        }

        this.addResult('lex', { 
            bots,
            accessDeniedRegions: accessDeniedRegions.length > 0 ? accessDeniedRegions : undefined,
            errorRegions: errorRegions.length > 0 ? errorRegions : undefined,
            accessIssues: accessDeniedRegions.length > 0,
            totalErrors: accessDeniedRegions.length + errorRegions.length
        });
    }

    async scanIoT() {
        const things = [];
        const policies = [];
        
        for (const region of this.regions) {
            try {
                const iot = new AWS.Iot({ region });
                
                // Scan things
                const thingsData = await iot.listThings().promise();
                for (const thing of thingsData.things) {
                    things.push({
                        thingName: thing.thingName,
                        thingArn: thing.thingArn,
                        region: region
                    });
                }

                // Scan policies
                const policiesData = await iot.listPolicies().promise();
                for (const policy of policiesData.policies) {
                    policies.push({
                        policyName: policy.policyName,
                        policyArn: policy.policyArn,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning IoT in ${region}:`, error);
            }
        }

        this.addResult('iot', { things, policies });
    }

    async scanMediaLive() {
        // Check if MediaLive is available in the AWS SDK
        if (typeof AWS.MediaLive !== "function") {
            console.warn("AWS.MediaLive is not available in the loaded AWS SDK.");
            this.addUnimplementedService('medialive');
            return;
        }
        
        const channels = [];
        
        for (const region of this.regions) {
            try {
                const medialive = new AWS.MediaLive({ region });
                const channelsData = await medialive.listChannels().promise();
                
                for (const channel of channelsData.channels) {
                    channels.push({
                        id: channel.id,
                        name: channel.name,
                        state: channel.state,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning MediaLive in ${region}:`, error);
            }
        }

        this.addResult('medialive', { channels });
    }

    async scanDataSync() {
        // Check if DataSync is available in the AWS SDK
        if (typeof AWS.DataSync !== "function") {
            console.warn("AWS.DataSync is not available in the loaded AWS SDK.");
            this.addUnimplementedService('datasync');
            return;
        }
        
        const tasks = [];
        
        for (const region of this.regions) {
            try {
                const datasync = new AWS.DataSync({ region });
                const tasksData = await datasync.listTasks().promise();
                
                for (const task of tasksData.Tasks) {
                    tasks.push({
                        taskArn: task.TaskArn,
                        name: task.Name,
                        status: task.Status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning DataSync in ${region}:`, error);
            }
        }

        this.addResult('datasync', { tasks });
    }

    async scanEMR() {
        const clusters = [];
        
        for (const region of this.regions) {
            try {
                const emr = new AWS.EMR({ region });
                const clustersData = await emr.listClusters().promise();
                
                for (const cluster of clustersData.Clusters) {
                    clusters.push({
                        id: cluster.Id,
                        name: cluster.Name,
                        status: cluster.Status.State,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning EMR in ${region}:`, error);
            }
        }

        this.addResult('emr', { clusters });
    }

    async scanAthena() {
        const workgroups = [];
        
        for (const region of this.regions) {
            try {
                const athena = new AWS.Athena({ region });
                const workgroupsData = await athena.listWorkGroups().promise();
                
                for (const workgroup of workgroupsData.WorkGroups) {
                    workgroups.push({
                        name: workgroup.Name,
                        state: workgroup.State,
                        description: workgroup.Description,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Athena in ${region}:`, error);
            }
        }

        this.addResult('athena', { workgroups });
    }

    async scanPinpoint() {
        // Check if Pinpoint is available in the AWS SDK
        if (typeof AWS.Pinpoint !== "function") {
            console.warn("AWS.Pinpoint is not available in the loaded AWS SDK.");
            this.addUnimplementedService('pinpoint');
            return;
        }
        
        const applications = [];
        
        for (const region of this.regions) {
            try {
                const pinpoint = new AWS.Pinpoint({ region });
                const applicationsData = await pinpoint.getApps().promise();
                
                for (const app of applicationsData.ApplicationsResponse.Item) {
                    applications.push({
                        id: app.Id,
                        name: app.Name,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Pinpoint in ${region}:`, error);
            }
        }

        this.addResult('pinpoint', { applications });
    }

    async scanMediaPackage() {
        // Check if MediaPackage is available in the AWS SDK
        if (typeof AWS.MediaPackage !== "function") {
            console.warn("AWS.MediaPackage is not available in the loaded AWS SDK.");
            this.addUnimplementedService('mediapackage');
            return;
        }
        
        const channels = [];
        
        for (const region of this.regions) {
            try {
                const mediapackage = new AWS.MediaPackage({ region });
                const channelsData = await mediapackage.listChannels().promise();
                
                for (const channel of channelsData.channels) {
                    channels.push({
                        id: channel.id,
                        description: channel.description,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning MediaPackage in ${region}:`, error);
            }
        }

        this.addResult('mediapackage', { channels });
    }

    async scanMQ() {
        // Check if MQ is available in the AWS SDK
        if (typeof AWS.MQ !== "function") {
            console.warn("AWS.MQ is not available in the loaded AWS SDK.");
            this.addUnimplementedService('mq');
            return;
        }
        
        const brokers = [];
        
        for (const region of this.regions) {
            try {
                const mq = new AWS.MQ({ region });
                const brokersData = await mq.listBrokers().promise();
                
                for (const broker of brokersData.BrokerSummaries) {
                    brokers.push({
                        brokerId: broker.BrokerId,
                        brokerName: broker.BrokerName,
                        brokerState: broker.BrokerState,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning MQ in ${region}:`, error);
            }
        }

        this.addResult('mq', { brokers });
    }

    async scanOrganizations() {
        try {
            const organizations = new AWS.Organizations({ region: 'us-east-1' });
            const accounts = [];

            const accountsData = await organizations.listAccounts().promise();
            for (const account of accountsData.Accounts) {
                accounts.push({
                    id: account.Id,
                    name: account.Name,
                    status: account.Status,
                    email: account.Email
                });
            }

            this.addResult('organizations', { accounts });
        } catch (error) {
            console.error('Error scanning Organizations:', error);
            this.addResult('organizations', { error: error.message });
        }
    }

    async scanDetective() {
        // Check if Detective is available in the AWS SDK
        if (typeof AWS.Detective !== "function") {
            console.warn("AWS.Detective is not available in the loaded AWS SDK.");
            this.addUnimplementedService('detective');
            return;
        }
        
        const graphs = [];
        
        for (const region of this.regions) {
            try {
                const detective = new AWS.Detective({ region });
                const graphsData = await detective.listGraphs().promise();
                
                for (const graph of graphsData.GraphList) {
                    graphs.push({
                        arn: graph.Arn,
                        createdTime: graph.CreatedTime,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Detective in ${region}:`, error);
            }
        }

        this.addResult('detective', { graphs });
    }

    async scanOpsWorks() {
        // Check if OpsWorks is available in the AWS SDK
        if (typeof AWS.OpsWorks !== "function") {
            console.warn("AWS.OpsWorks is not available in the loaded AWS SDK.");
            this.addUnimplementedService('opsworks');
            return;
        }
        
        const stacks = [];
        
        for (const region of this.regions) {
            try {
                const opsworks = new AWS.OpsWorks({ region });
                const stacksData = await opsworks.describeStacks().promise();
                
                for (const stack of stacksData.Stacks) {
                    stacks.push({
                        stackId: stack.StackId,
                        name: stack.Name,
                        stackRegion: stack.Region,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning OpsWorks in ${region}:`, error);
            }
        }

        this.addResult('opsworks', { stacks });
    }

    async scanCodeCommit() {
        const repositories = [];
        
        for (const region of this.regions) {
            try {
                const codecommit = new AWS.CodeCommit({ region });
                const repositoriesData = await codecommit.listRepositories().promise();
                
                for (const repo of repositoriesData.repositories) {
                    repositories.push({
                        repositoryName: repo.repositoryName,
                        repositoryId: repo.repositoryId,
                        arn: repo.arn,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning CodeCommit in ${region}:`, error);
            }
        }

        this.addResult('codecommit', { repositories });
    }

    async scanAppMesh() {
        // Check if AppMesh is available in the AWS SDK
        if (typeof AWS.AppMesh !== "function") {
            console.warn("AWS.AppMesh is not available in the loaded AWS SDK.");
            this.addUnimplementedService('appmesh');
            return;
        }
        
        const meshes = [];
        
        for (const region of this.regions) {
            try {
                const appmesh = new AWS.AppMesh({ region });
                const meshesData = await appmesh.listMeshes().promise();
                
                for (const mesh of meshesData.meshes) {
                    meshes.push({
                        meshName: mesh.meshName,
                        meshOwner: mesh.meshOwner,
                        resourceOwner: mesh.resourceOwner,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning AppMesh in ${region}:`, error);
            }
        }

        this.addResult('appmesh', { meshes });
    }

    async scanBackup() {
        // Check if Backup is available in the AWS SDK
        if (typeof AWS.Backup !== "function") {
            console.warn("AWS.Backup is not available in the loaded AWS SDK.");
            this.addUnimplementedService('backup');
            return;
        }
        
        const vaults = [];
        
        for (const region of this.regions) {
            try {
                const backup = new AWS.Backup({ region });
                const vaultsData = await backup.listBackupVaults().promise();
                
                for (const vault of vaultsData.BackupVaultList) {
                    vaults.push({
                        backupVaultName: vault.BackupVaultName,
                        backupVaultArn: vault.BackupVaultArn,
                        creationDate: vault.CreationDate,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Backup in ${region}:`, error);
            }
        }

        this.addResult('backup', { vaults });
    }

    async scanMediaStore() {
        // Check if MediaStore is available in the AWS SDK
        if (typeof AWS.MediaStore !== "function") {
            console.warn("AWS.MediaStore is not available in the loaded AWS SDK.");
            this.addUnimplementedService('mediastore');
            return;
        }
        
        const containers = [];
        
        for (const region of this.regions) {
            try {
                const mediastore = new AWS.MediaStore({ region });
                const containersData = await mediastore.listContainers().promise();
                
                for (const container of containersData.Containers) {
                    containers.push({
                        name: container.Name,
                        arn: container.ARN,
                        status: container.Status,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning MediaStore in ${region}:`, error);
            }
        }

        this.addResult('mediastore', { containers });
    }

    async scanECR() {
        const repositories = [];
        
        for (const region of this.regions) {
            try {
                const ecr = new AWS.ECR({ region });
                const repositoriesData = await ecr.describeRepositories().promise();
                
                for (const repo of repositoriesData.repositories) {
                    repositories.push({
                        repositoryName: repo.repositoryName,
                        repositoryArn: repo.repositoryArn,
                        repositoryUri: repo.repositoryUri,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning ECR in ${region}:`, error);
            }
        }

        this.addResult('ecr', { repositories });
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
        const finalResults = {};
        
        // 1. S3 EXCLUSION NOTICE (at the very top)
        finalResults['s3_exclusion_notice'] = this.getS3ExclusionNotice();
        
        // 2. ACCOUNT INFORMATION
        if (this.accountInfo) {
            finalResults['account_info'] = this.accountInfo;
        }
        
        // 3. SCAN TIMING INFORMATION
        if (this.scanTiming) {
            finalResults['scan_timing'] = {
                startTime: this.scanTiming.startTime,
                endTime: this.scanTiming.endTime,
                startDate: this.scanTiming.startDate,
                endDate: this.scanTiming.endDate,
                totalDuration: this.scanTiming.totalDuration,
                formattedDuration: this.scanTiming.formattedDuration,
                status: this.scanTiming.status || 'completed'
            };
        }
        
        // 4. SCAN RESULTS (service-specific data)
        Object.assign(finalResults, this.results);
        
        // 5. UNIMPLEMENTED SERVICES (at the bottom)
        if (this.unimplementedServices && this.unimplementedServices.length > 0) {
            finalResults['unimplemented_services'] = {
                message: 'Services not implemented yet',
                services: this.unimplementedServices,
                count: this.unimplementedServices.length
            };
        }
        
        return finalResults;
    }

    getServiceScanner(service) {
        const scanners = {
            // Original services with enhanced scanners
            ec2: this.scanEC2,
            lambda: this.scanLambda,
            ecs: this.scanECS,
            eks: this.scanEKS,
            elasticbeanstalk: this.scanElasticBeanstalk,
            emr: this.scanEMR,
            
            // Storage Services
            efs: this.scanEFS,
            storagegateway: this.scanStorageGateway,
            
            // Database Services
            rds: this.scanRDS,
            dynamodb: this.scanDynamoDB,
            redshift: this.scanRedshift,
            elasticache: this.scanElastiCache,
            athena: this.scanAthena,
            
            // Networking Services
            route53: this.scanRoute53,
            apigateway: this.scanAPIGateway,
            cloudfront: this.scanCloudFront,
            
            // Security Services
            iam: this.scanIAM,
            cloudtrail: this.scanCloudTrail,
            secretsmanager: this.scanSecretsManager,
            detective: this.scanDetective,
            
            // Analytics Services
            kinesis: this.scanKinesis,
            glue: this.scanGlue,
            stepfunctions: this.scanStepFunctions,
            cloudwatch: this.scanCloudWatch,
            
            // Media Services
            mediaconvert: this.scanMediaConvert,
            medialive: this.scanMediaLive,
            mediapackage: this.scanMediaPackage,
            elastictranscoder: this.scanElasticTranscoder,
            
            // AI/ML Services
            sagemaker: this.scanSageMaker,
            lex: this.scanLex,
            iot: this.scanIoT,
            
            // Development Services
            codepipeline: this.scanCodePipeline,
            codecommit: this.scanCodeCommit,
            cloud9: this.scanCloud9,
            ssm: this.scanSSM,
            
            // Management Services
            cloudformation: this.scanCloudFormation,
            organizations: this.scanOrganizations,
            backup: this.scanBackup,
            
            // Messaging Services
            sns: this.scanSNS,
            sqs: this.scanSQS,
            mq: this.scanMQ,
            
            // Container Services
            ecr: this.scanECR,
            
            // Additional Services
            appsync: this.scanAppSync,
            datapipeline: this.scanDataPipeline,
            workspaces: this.scanWorkSpaces,
            datasync: this.scanDataSync,
            pinpoint: this.scanPinpoint,
            opsworks: this.scanOpsWorks,
            appmesh: this.scanAppMesh,
            mediastore: this.scanMediaStore,
            
            // New services from aws-inventory
            acm: this.scanACM,
            applicationautoscaling: this.scanApplicationAutoScaling,
            autoscaling: this.scanAutoScaling,
            cloudwatchevents: this.scanCloudWatchEvents,
            cloudwatchlogs: this.scanCloudWatchLogs,
            codedeploy: this.scanCodeDeploy,
            cognitoidentity: this.scanCognitoIdentity,
            cognitoidentityserviceprovider: this.scanCognitoIdentityServiceProvider,
            configservice: this.scanConfigService,
            cur: this.scanCUR,
            devicefarm: this.scanDeviceFarm,
            directconnect: this.scanDirectConnect,
            dynamodbstreams: this.scanDynamoDBStreams,
            inspector: this.scanInspector,
            kms: this.scanKMS,
            machinelearning: this.scanMachineLearning,
            opsworks: this.scanOpsWorks,
            polly: this.scanPolly,
            rekognition: this.scanRekognition,
            route53domains: this.scanRoute53Domains,
            ses: this.scanSES,
            waf: this.scanWAF
        };
        
        return scanners[service];
    }

    // New service scanners for aws-inventory coverage
    
    async scanACM() {
        const certificates = [];
        
        try {
            const acm = new AWS.ACM();
            const certificatesData = await acm.listCertificates().promise();
            
            for (const cert of certificatesData.CertificateSummaryList) {
                certificates.push({
                    domainName: cert.DomainName,
                    certificateArn: cert.CertificateArn,
                    status: cert.Status,
                    type: cert.Type,
                    notAfter: cert.NotAfter,
                    notBefore: cert.NotBefore
                });
            }
        } catch (error) {
            console.error('Error scanning ACM:', error);
        }
        
        this.addResult('acm', { certificates });
    }

    async scanApplicationAutoScaling() {
        const scalableTargets = {};
        
        const namespaces = ['ecs', 'elasticmapreduce', 'ec2', 'appstream', 'dynamodb', 'rds'];
        
        for (const namespace of namespaces) {
            try {
                const autoscaling = new AWS.ApplicationAutoScaling();
                const targetsData = await autoscaling.describeScalableTargets({
                    ServiceNamespace: namespace
                }).promise();
                
                scalableTargets[namespace] = targetsData.ScalableTargets || [];
            } catch (error) {
                console.error(`Error scanning Application Auto Scaling for ${namespace}:`, error);
                scalableTargets[namespace] = [];
            }
        }
        
        this.addResult('applicationautoscaling', { scalableTargets });
    }

    async scanAutoScaling() {
        const autoScalingGroups = [];
        const launchConfigurations = [];
        
        for (const region of this.regions) {
            try {
                const autoscaling = new AWS.AutoScaling({ region });
                
                // Scan Auto Scaling Groups
                const groupsData = await autoscaling.describeAutoScalingGroups().promise();
                for (const group of groupsData.AutoScalingGroups) {
                    autoScalingGroups.push({
                        autoScalingGroupName: group.AutoScalingGroupName,
                        minSize: group.MinSize,
                        maxSize: group.MaxSize,
                        desiredCapacity: group.DesiredCapacity,
                        availabilityZones: group.AvailabilityZones,
                        healthCheckType: group.HealthCheckType,
                        createdTime: group.CreatedTime,
                        region: region
                    });
                }
                
                // Scan Launch Configurations
                const configsData = await autoscaling.describeLaunchConfigurations().promise();
                for (const config of configsData.LaunchConfigurations) {
                    launchConfigurations.push({
                        launchConfigurationName: config.LaunchConfigurationName,
                        imageId: config.ImageId,
                        instanceType: config.InstanceType,
                        createdTime: config.CreatedTime,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Auto Scaling in ${region}:`, error);
            }
        }
        
        this.addResult('autoscaling', { autoScalingGroups, launchConfigurations });
    }

    async scanCloudWatchEvents() {
        const rules = [];
        
        for (const region of this.regions) {
            try {
                const events = new AWS.CloudWatchEvents({ region });
                const rulesData = await events.listRules().promise();
                
                for (const rule of rulesData.Rules) {
                    rules.push({
                        name: rule.Name,
                        arn: rule.Arn,
                        eventPattern: rule.EventPattern,
                        state: rule.State,
                        description: rule.Description,
                        scheduleExpression: rule.ScheduleExpression,
                        roleArn: rule.RoleArn,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning CloudWatch Events in ${region}:`, error);
            }
        }
        
        this.addResult('cloudwatchevents', { rules });
    }

    async scanCloudWatchLogs() {
        const logGroups = [];
        const exportTasks = [];
        const destinations = [];
        const metricFilters = [];
        const resourcePolicies = [];
        
        for (const region of this.regions) {
            try {
                const logs = new AWS.CloudWatchLogs({ region });
                
                // Scan Log Groups
                const groupsData = await logs.describeLogGroups().promise();
                for (const group of groupsData.logGroups) {
                    logGroups.push({
                        logGroupName: group.logGroupName,
                        creationTime: group.creationTime,
                        retentionInDays: group.retentionInDays,
                        metricFilterCount: group.metricFilterCount,
                        storedBytes: group.storedBytes,
                        region: region
                    });
                }
                
                // Scan Export Tasks
                try {
                    const exportData = await logs.describeExportTasks().promise();
                    for (const task of exportData.exportTasks) {
                        exportTasks.push({
                            taskId: task.taskId,
                            taskName: task.taskName,
                            logGroupName: task.logGroupName,
                            from: task.from,
                            to: task.to,
                            destination: task.destination,
                            status: task.status,
                            region: region
                        });
                    }
                } catch (error) {
                    // Export tasks might not be available in all regions
                }
                
                // Scan Destinations
                try {
                    const destData = await logs.describeDestinations().promise();
                    for (const dest of destData.destinations) {
                        destinations.push({
                            destinationName: dest.destinationName,
                            targetArn: dest.targetArn,
                            roleArn: dest.roleArn,
                            arn: dest.arn,
                            creationTime: dest.creationTime,
                            region: region
                        });
                    }
                } catch (error) {
                    // Destinations might not be available in all regions
                }
                
                // Scan Metric Filters
                try {
                    const filterData = await logs.describeMetricFilters().promise();
                    for (const filter of filterData.metricFilters) {
                        metricFilters.push({
                            filterName: filter.filterName,
                            filterPattern: filter.filterPattern,
                            creationTime: filter.creationTime,
                            logGroupName: filter.logGroupName,
                            metricTransformations: filter.metricTransformations,
                            region: region
                        });
                    }
                } catch (error) {
                    // Metric filters might not be available in all regions
                }
                
                // Scan Resource Policies
                try {
                    const policyData = await logs.describeResourcePolicies().promise();
                    for (const policy of policyData.resourcePolicies) {
                        resourcePolicies.push({
                            policyName: policy.policyName,
                            lastUpdatedTime: policy.lastUpdatedTime,
                            policyDocument: policy.policyDocument,
                            region: region
                        });
                    }
                } catch (error) {
                    // Resource policies might not be available in all regions
                }
                
            } catch (error) {
                console.error(`Error scanning CloudWatch Logs in ${region}:`, error);
            }
        }
        
        this.addResult('cloudwatchlogs', { 
            logGroups, 
            exportTasks, 
            destinations, 
            metricFilters, 
            resourcePolicies 
        });
    }

    async scanCodeDeploy() {
        const applications = [];
        const githubTokens = [];
        const onPremisesInstances = [];
        
        for (const region of this.regions) {
            try {
                const codedeploy = new AWS.CodeDeploy({ region });
                
                // Scan Applications
                const appsData = await codedeploy.listApplications().promise();
                for (const app of appsData.applications) {
                    applications.push({
                        applicationName: app,
                        region: region
                    });
                }
                
                // Scan GitHub Account Tokens
                try {
                    const tokensData = await codedeploy.listGitHubAccountTokenNames().promise();
                    for (const token of tokensData.tokenNameList) {
                        githubTokens.push({
                            tokenName: token,
                            region: region
                        });
                    }
                } catch (error) {
                    // GitHub tokens might not be available in all regions
                }
                
                // Scan On-Premises Instances
                try {
                    const instancesData = await codedeploy.listOnPremisesInstances().promise();
                    for (const instance of instancesData.instanceNames) {
                        onPremisesInstances.push({
                            instanceName: instance,
                            region: region
                        });
                    }
                } catch (error) {
                    // On-premises instances might not be available in all regions
                }
                
            } catch (error) {
                console.error(`Error scanning CodeDeploy in ${region}:`, error);
            }
        }
        
        this.addResult('codedeploy', { applications, githubTokens, onPremisesInstances });
    }

    async scanCognitoIdentity() {
        const identityPools = [];
        
        for (const region of this.regions) {
            // Skip regions where Cognito Identity is not available
            const skipRegions = ['ca-central-1', 'eu-west-3', 'sa-east-1', 'us-west-1', 'us-east-2'];
            if (skipRegions.includes(region)) continue;
            
            try {
                const cognito = new AWS.CognitoIdentity({ region });
                const poolsData = await cognito.listIdentityPools({ MaxResults: 60 }).promise();
                
                for (const pool of poolsData.IdentityPools) {
                    identityPools.push({
                        identityPoolId: pool.IdentityPoolId,
                        identityPoolName: pool.IdentityPoolName,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Cognito Identity in ${region}:`, error);
            }
        }
        
        this.addResult('cognitoidentity', { identityPools });
    }

    async scanCognitoIdentityServiceProvider() {
        const userPools = [];
        
        for (const region of this.regions) {
            // Skip regions where Cognito Identity Service Provider is not available
            const skipRegions = ['ca-central-1', 'eu-west-3', 'sa-east-1', 'us-west-1', 'us-east-2'];
            if (skipRegions.includes(region)) continue;
            
            try {
                const cognito = new AWS.CognitoIdentityServiceProvider({ region });
                const poolsData = await cognito.listUserPools({ MaxResults: 60 }).promise();
                
                for (const pool of poolsData.UserPools) {
                    userPools.push({
                        id: pool.Id,
                        name: pool.Name,
                        status: pool.Status,
                        lastModifiedDate: pool.LastModifiedDate,
                        creationDate: pool.CreationDate,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Cognito Identity Service Provider in ${region}:`, error);
            }
        }
        
        this.addResult('cognitoidentityserviceprovider', { userPools });
    }

    async scanConfigService() {
        const configRules = [];
        const configurationRecorders = [];
        const deliveryChannels = [];
        
        for (const region of this.regions) {
            try {
                const config = new AWS.ConfigService({ region });
                
                // Scan Config Rules
                const rulesData = await config.describeConfigRules().promise();
                for (const rule of rulesData.ConfigRules) {
                    configRules.push({
                        configRuleName: rule.ConfigRuleName,
                        configRuleArn: rule.ConfigRuleArn,
                        configRuleId: rule.ConfigRuleId,
                        description: rule.Description,
                        sourceOwner: rule.Source?.Owner,
                        configRuleState: rule.ConfigRuleState,
                        maximumExecutionFrequency: rule.MaximumExecutionFrequency,
                        region: region
                    });
                }
                
                // Scan Configuration Recorders
                const recordersData = await config.describeConfigurationRecorders().promise();
                for (const recorder of recordersData.ConfigurationRecorders) {
                    configurationRecorders.push({
                        name: recorder.name,
                        roleARN: recorder.roleARN,
                        allSupported: recorder.recordingGroup?.allSupported,
                        resourceTypes: recorder.recordingGroup?.resourceTypes,
                        region: region
                    });
                }
                
                // Scan Delivery Channels
                const channelsData = await config.describeDeliveryChannels().promise();
                for (const channel of channelsData.DeliveryChannels) {
                    deliveryChannels.push({
                        name: channel.name,
                        s3BucketName: channel.s3BucketName,
                        s3KeyPrefix: channel.s3KeyPrefix,
                        snsTopicARN: channel.snsTopicARN,
                        deliveryFrequency: channel.configSnapshotDeliveryProperties?.deliveryFrequency,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning Config Service in ${region}:`, error);
            }
        }
        
        this.addResult('configservice', { configRules, configurationRecorders, deliveryChannels });
    }

    async scanCUR() {
        const reportDefinitions = [];
        
        try {
            const cur = new AWS.CUR({ region: 'us-east-1' });
            const reportsData = await cur.describeReportDefinitions().promise();
            
            for (const report of reportsData.ReportDefinitions) {
                reportDefinitions.push({
                    reportName: report.ReportName,
                    timeUnit: report.TimeUnit,
                    format: report.Format,
                    compression: report.Compression,
                    s3Region: report.S3Region,
                    s3Bucket: report.S3Bucket,
                    s3Prefix: report.S3Prefix,
                    additionalArtifacts: report.AdditionalArtifacts
                });
            }
        } catch (error) {
            console.error('Error scanning Cost and Usage Reports:', error);
        }
        
        this.addResult('cur', { reportDefinitions });
    }

    async scanDeviceFarm() {
        const projects = [];
        
        try {
            const devicefarm = new AWS.DeviceFarm({ region: 'us-west-2' });
            const projectsData = await devicefarm.listProjects().promise();
            
            for (const project of projectsData.projects) {
                projects.push({
                    arn: project.arn,
                    name: project.name,
                    defaultJobTimeoutMinutes: project.defaultJobTimeoutMinutes,
                    created: project.created
                });
            }
        } catch (error) {
            console.error('Error scanning Device Farm:', error);
        }
        
        this.addResult('devicefarm', { projects });
    }

    async scanDirectConnect() {
        const connections = [];
        const lags = [];
        const virtualGateways = [];
        const virtualInterfaces = [];
        
        for (const region of this.regions) {
            try {
                const directconnect = new AWS.DirectConnect({ region });
                
                // Scan Connections
                const connectionsData = await directconnect.describeConnections().promise();
                for (const conn of connectionsData.connections) {
                    connections.push({
                        ownerAccount: conn.ownerAccount,
                        connectionId: conn.connectionId,
                        connectionName: conn.connectionName,
                        connectionState: conn.connectionState,
                        region: conn.region,
                        location: conn.location,
                        bandwidth: conn.bandwidth,
                        partnerName: conn.partnerName,
                        awsDevice: conn.awsDevice
                    });
                }
                
                // Scan LAGs
                const lagsData = await directconnect.describeLags().promise();
                for (const lag of lagsData.lags) {
                    lags.push({
                        connectionsBandwidth: lag.connectionsBandwidth,
                        numberOfConnections: lag.numberOfConnections,
                        lagId: lag.lagId,
                        ownerAccount: lag.ownerAccount,
                        lagName: lag.lagName,
                        lagState: lag.lagState,
                        location: lag.location,
                        region: lag.region,
                        minimumLinks: lag.minimumLinks,
                        awsDevice: lag.awsDevice
                    });
                }
                
                // Scan Virtual Gateways
                const gatewaysData = await directconnect.describeVirtualGateways().promise();
                for (const gateway of gatewaysData.virtualGateways) {
                    virtualGateways.push({
                        virtualGatewayId: gateway.virtualGatewayId,
                        virtualGatewayState: gateway.virtualGatewayState,
                        region: region
                    });
                }
                
                // Scan Virtual Interfaces
                const interfacesData = await directconnect.describeVirtualInterfaces().promise();
                for (const vif of interfacesData.virtualInterfaces) {
                    virtualInterfaces.push({
                        ownerAccount: vif.ownerAccount,
                        virtualInterfaceId: vif.virtualInterfaceId,
                        location: vif.location,
                        connectionId: vif.connectionId,
                        virtualInterfaceType: vif.virtualInterfaceType,
                        virtualInterfaceName: vif.virtualInterfaceName,
                        amazonAddress: vif.amazonAddress,
                        customerAddress: vif.customerAddress,
                        virtualInterfaceState: vif.virtualInterfaceState,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning Direct Connect in ${region}:`, error);
            }
        }
        
        this.addResult('directconnect', { connections, lags, virtualGateways, virtualInterfaces });
    }

    async scanDynamoDBStreams() {
        const streams = [];
        
        for (const region of this.regions) {
            try {
                const dynamodbstreams = new AWS.DynamoDBStreams({ region });
                const streamsData = await dynamodbstreams.listStreams().promise();
                
                for (const stream of streamsData.Streams) {
                    streams.push({
                        streamArn: stream.StreamArn,
                        tableName: stream.TableName,
                        streamLabel: stream.StreamLabel,
                        lastEvaluatedStreamArn: stream.LastEvaluatedStreamArn,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning DynamoDB Streams in ${region}:`, error);
            }
        }
        
        this.addResult('dynamodbstreams', { streams });
    }

    async scanInspector() {
        const rulesPackages = [];
        const assessmentTargets = [];
        
        for (const region of this.regions) {
            // Skip regions where Inspector is not available
            const skipRegions = ['ap-southeast-1', 'ca-central-1', 'eu-west-2', 'eu-west-3', 'sa-east-1'];
            if (skipRegions.includes(region)) continue;
            
            try {
                const inspector = new AWS.Inspector({ region });
                
                // Scan Rules Packages
                const rulesData = await inspector.listRulesPackages().promise();
                for (const rule of rulesData.rulesPackageArns) {
                    rulesPackages.push({
                        arn: rule,
                        region: region
                    });
                }
                
                // Scan Assessment Targets
                const targetsData = await inspector.listAssessmentTargets({ maxResults: 500 }).promise();
                for (const target of targetsData.assessmentTargetArns) {
                    assessmentTargets.push({
                        arn: target,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning Inspector in ${region}:`, error);
            }
        }
        
        this.addResult('inspector', { rulesPackages, assessmentTargets });
    }

    async scanKMS() {
        const aliases = [];
        const keys = [];
        
        for (const region of this.regions) {
            try {
                const kms = new AWS.KMS({ region });
                
                // Scan Aliases
                const aliasesData = await kms.listAliases().promise();
                for (const alias of aliasesData.Aliases) {
                    aliases.push({
                        aliasArn: alias.AliasArn,
                        aliasName: alias.AliasName,
                        targetKeyId: alias.TargetKeyId,
                        region: region
                    });
                }
                
                // Scan Keys
                const keysData = await kms.listKeys().promise();
                for (const key of keysData.Keys) {
                    keys.push({
                        keyId: key.KeyId,
                        keyArn: key.KeyArn,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning KMS in ${region}:`, error);
            }
        }
        
        this.addResult('kms', { aliases, keys });
    }

    async scanMachineLearning() {
        const batchPredictions = [];
        const evaluations = [];
        const dataSources = [];
        const models = [];
        
        for (const region of this.regions) {
            // Skip regions where Machine Learning is not available
            const skipRegions = ['ap-northeast-1', 'ap-northeast-2', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 'us-east-2', 'us-west-1', 'us-west-2'];
            if (skipRegions.includes(region)) continue;
            
            try {
                const ml = new AWS.MachineLearning({ region });
                
                // Scan Batch Predictions
                const predictionsData = await ml.describeBatchPredictions().promise();
                for (const prediction of predictionsData.Results) {
                    batchPredictions.push({
                        batchPredictionId: prediction.BatchPredictionId,
                        mlModelId: prediction.MLModelId,
                        batchPredictionDataSourceId: prediction.BatchPredictionDataSourceId,
                        inputDataLocationS3: prediction.InputDataLocationS3,
                        createdByIamUser: prediction.CreatedByIamUser,
                        createdAt: prediction.CreatedAt,
                        name: prediction.Name,
                        status: prediction.Status,
                        message: prediction.Message,
                        region: region
                    });
                }
                
                // Scan Evaluations
                const evaluationsData = await ml.describeEvaluations().promise();
                for (const evaluation of evaluationsData.Results) {
                    evaluations.push({
                        evaluationId: evaluation.EvaluationId,
                        mlModelId: evaluation.MLModelId,
                        evaluationDataSourceId: evaluation.EvaluationDataSourceId,
                        createdAt: evaluation.CreatedAt,
                        name: evaluation.Name,
                        region: region
                    });
                }
                
                // Scan Data Sources
                const sourcesData = await ml.describeDataSources().promise();
                for (const source of sourcesData.Results) {
                    dataSources.push({
                        dataSourceId: source.DataSourceId,
                        dataLocationS3: source.DataLocationS3,
                        createdByIamUser: source.CreatedByIamUser,
                        createdAt: source.CreatedAt,
                        dataSizeInBytes: source.DataSizeInBytes,
                        name: source.Name,
                        status: source.Status,
                        region: region
                    });
                }
                
                // Scan Models
                const modelsData = await ml.describeMLModels().promise();
                for (const model of modelsData.Results) {
                    models.push({
                        mlModelId: model.MLModelId,
                        trainingDataSourceId: model.TrainingDataSourceId,
                        createdByIamUser: model.CreatedByIamUser,
                        createdAt: model.CreatedAt,
                        name: model.Name,
                        status: model.Status,
                        sizeInBytes: model.SizeInBytes,
                        mlModelType: model.MLModelType,
                        message: model.Message,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning Machine Learning in ${region}:`, error);
            }
        }
        
        this.addResult('machinelearning', { batchPredictions, evaluations, dataSources, models });
    }

    async scanPolly() {
        const lexicons = [];
        
        for (const region of this.regions) {
            try {
                const polly = new AWS.Polly({ region });
                const lexiconsData = await polly.listLexicons().promise();
                
                for (const lexicon of lexiconsData.Lexicons) {
                    lexicons.push({
                        name: lexicon.Name,
                        size: lexicon.Attributes?.Size,
                        languageCode: lexicon.Attributes?.LanguageCode,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Polly in ${region}:`, error);
            }
        }
        
        this.addResult('polly', { lexicons });
    }

    async scanRekognition() {
        const collections = [];
        
        for (const region of this.regions) {
            try {
                const rekognition = new AWS.Rekognition({ region });
                const collectionsData = await rekognition.listCollections().promise();
                
                for (const collection of collectionsData.CollectionIds) {
                    collections.push({
                        collectionId: collection,
                        region: region
                    });
                }
            } catch (error) {
                console.error(`Error scanning Rekognition in ${region}:`, error);
            }
        }
        
        this.addResult('rekognition', { collections });
    }

    async scanRoute53Domains() {
        const domains = [];
        const operations = [];
        
        try {
            const route53domains = new AWS.Route53Domains({ region: 'us-east-1' });
            
            // Scan Domains
            const domainsData = await route53domains.listDomains().promise();
            for (const domain of domainsData.Domains) {
                domains.push({
                    domainName: domain.DomainName,
                    autoRenew: domain.AutoRenew,
                    transferLock: domain.TransferLock,
                    expiry: domain.Expiry
                });
            }
            
            // Scan Operations
            const operationsData = await route53domains.listOperations().promise();
            for (const operation of operationsData.Operations) {
                operations.push({
                    operationId: operation.OperationId,
                    status: operation.Status,
                    type: operation.Type,
                    submittedDate: operation.SubmittedDate
                });
            }
            
        } catch (error) {
            console.error('Error scanning Route53 Domains:', error);
        }
        
        this.addResult('route53domains', { domains, operations });
    }

    async scanSES() {
        const identities = [];
        const receiptFilters = [];
        const receiptRuleSets = [];
        const templates = [];
        const verifiedEmailAddresses = [];
        
        for (const region of this.regions) {
            // Skip regions where SES is not available
            const skipRegions = ['eu-west-2', 'eu-west-3', 'ap-southeast-2', 'us-west-1', 'ap-south-1', 'ap-southeast-1', 'us-east-2', 'eu-central-1', 'ap-northeast-1', 'ca-central-1', 'ap-northeast-2', 'sa-east-1'];
            if (skipRegions.includes(region)) continue;
            
            try {
                const ses = new AWS.SES({ region });
                
                // Scan Identities
                const identitiesData = await ses.listIdentities().promise();
                for (const identity of identitiesData.Identities) {
                    identities.push({
                        identity: identity,
                        region: region
                    });
                }
                
                // Scan Receipt Filters
                try {
                    const filtersData = await ses.listReceiptFilters().promise();
                    for (const filter of filtersData.Filters) {
                        receiptFilters.push({
                            name: filter.Name,
                            policy: filter.IpFilter?.Policy,
                            cidr: filter.IpFilter?.Cidr,
                            region: region
                        });
                    }
                } catch (error) {
                    // Receipt filters might not be available in all regions
                }
                
                // Scan Receipt Rule Sets
                try {
                    const ruleSetsData = await ses.listReceiptRuleSets().promise();
                    for (const ruleSet of ruleSetsData.RuleSets) {
                        receiptRuleSets.push({
                            name: ruleSet.Name,
                            createdTimestamp: ruleSet.CreatedTimestamp,
                            region: region
                        });
                    }
                } catch (error) {
                    // Receipt rule sets might not be available in all regions
                }
                
                // Scan Templates
                try {
                    const templatesData = await ses.listTemplates().promise();
                    for (const template of templatesData.TemplatesMetadata) {
                        templates.push({
                            name: template.Name,
                            createdTimestamp: template.CreatedTimestamp,
                            region: region
                        });
                    }
                } catch (error) {
                    // Templates might not be available in all regions
                }
                
                // Scan Verified Email Addresses
                try {
                    const verifiedData = await ses.listVerifiedEmailAddresses().promise();
                    for (const email of verifiedData.VerifiedEmailAddresses) {
                        verifiedEmailAddresses.push({
                            address: email,
                            region: region
                        });
                    }
                } catch (error) {
                    // Verified email addresses might not be available in all regions
                }
                
            } catch (error) {
                console.error(`Error scanning SES in ${region}:`, error);
            }
        }
        
        this.addResult('ses', { identities, receiptFilters, receiptRuleSets, templates, verifiedEmailAddresses });
    }

    async scanWAF() {
        const byteMatchSets = [];
        const geoMatchSets = [];
        const ipSets = [];
        const rateBasedRules = [];
        const regexMatchSets = [];
        const regexPatternSets = [];
        const ruleGroups = [];
        const rules = [];
        const sizeConstraintSets = [];
        const sqlInjectionMatchSets = [];
        const subscribedRuleGroups = [];
        const webACLs = [];
        const xssMatchSets = [];
        
        for (const region of this.regions) {
            try {
                const waf = new AWS.WAF({ region });
                
                // Scan Byte Match Sets
                const byteMatchData = await waf.listByteMatchSets().promise();
                for (const set of byteMatchData.ByteMatchSets) {
                    byteMatchSets.push({
                        byteMatchSetId: set.ByteMatchSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan Geo Match Sets
                const geoMatchData = await waf.listGeoMatchSets().promise();
                for (const set of geoMatchData.GeoMatchSets) {
                    geoMatchSets.push({
                        geoMatchSetId: set.GeoMatchSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan IP Sets
                const ipSetsData = await waf.listIPSets().promise();
                for (const set of ipSetsData.IPSets) {
                    ipSets.push({
                        ipSetId: set.IPSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan Rate Based Rules
                const rateRulesData = await waf.listRateBasedRules().promise();
                for (const rule of rateRulesData.Rules) {
                    rateBasedRules.push({
                        ruleId: rule.RuleId,
                        name: rule.Name,
                        region: region
                    });
                }
                
                // Scan Regex Match Sets
                const regexMatchData = await waf.listRegexMatchSets().promise();
                for (const set of regexMatchData.RegexMatchSets) {
                    regexMatchSets.push({
                        regexMatchSetId: set.RegexMatchSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan Regex Pattern Sets
                const regexPatternData = await waf.listRegexPatternSets().promise();
                for (const set of regexPatternData.RegexPatternSets) {
                    regexPatternSets.push({
                        regexPatternSetId: set.RegexPatternSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan Rule Groups
                const ruleGroupsData = await waf.listRuleGroups().promise();
                for (const group of ruleGroupsData.RuleGroups) {
                    ruleGroups.push({
                        ruleGroupId: group.RuleGroupId,
                        name: group.Name,
                        region: region
                    });
                }
                
                // Scan Rules
                const rulesData = await waf.listRules().promise();
                for (const rule of rulesData.Rules) {
                    rules.push({
                        ruleId: rule.RuleId,
                        name: rule.Name,
                        region: region
                    });
                }
                
                // Scan Size Constraint Sets
                const sizeConstraintData = await waf.listSizeConstraintSets().promise();
                for (const set of sizeConstraintData.SizeConstraintSets) {
                    sizeConstraintSets.push({
                        sizeConstraintSetId: set.SizeConstraintSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan SQL Injection Match Sets
                const sqlInjectionData = await waf.listSqlInjectionMatchSets().promise();
                for (const set of sqlInjectionData.SqlInjectionMatchSets) {
                    sqlInjectionMatchSets.push({
                        sqlInjectionMatchSetId: set.SqlInjectionMatchSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
                // Scan Subscribed Rule Groups
                const subscribedGroupsData = await waf.listSubscribedRuleGroups().promise();
                for (const group of subscribedGroupsData.RuleGroups) {
                    subscribedRuleGroups.push({
                        ruleGroupId: group.RuleGroupId,
                        name: group.Name,
                        metricName: group.MetricName,
                        region: region
                    });
                }
                
                // Scan Web ACLs
                const webACLsData = await waf.listWebACLs().promise();
                for (const acl of webACLsData.WebACLs) {
                    webACLs.push({
                        webACLId: acl.WebACLId,
                        name: acl.Name,
                        region: region
                    });
                }
                
                // Scan XSS Match Sets
                const xssMatchData = await waf.listXssMatchSets().promise();
                for (const set of xssMatchData.XssMatchSets) {
                    xssMatchSets.push({
                        xssMatchSetId: set.XssMatchSetId,
                        name: set.Name,
                        region: region
                    });
                }
                
            } catch (error) {
                console.error(`Error scanning WAF in ${region}:`, error);
            }
        }
        
        this.addResult('waf', { 
            byteMatchSets, 
            geoMatchSets, 
            ipSets, 
            rateBasedRules, 
            regexMatchSets, 
            regexPatternSets, 
            ruleGroups, 
            rules, 
            sizeConstraintSets, 
            sqlInjectionMatchSets, 
            subscribedRuleGroups, 
            webACLs, 
            xssMatchSets 
        });
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AWSScanner;
} 