/**
 * AWS Cloud Scanner - Comprehensive Service Enumeration
 * Supports 50+ AWS services with multi-region scanning
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
    }

    async scan(credentials, selectedServices = null) {
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        const scanStartTime = Date.now();
        const scanStartDate = new Date().toISOString();
        
        console.log(`[${scanId}] 🏗️  Initializing AWS scanner...`);
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
            
            // Scan each service
            let completedServices = 0;
            let successfulServices = 0;
            let failedServices = 0;
            
            console.log(`[${scanId}] 🔍 Starting service enumeration...`);
            
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
            
            const scanEndTime = Date.now();
            const scanEndDate = new Date().toISOString();
            const totalDuration = scanEndTime - scanStartTime;
            
            console.log(`[${scanId}] 🕐 Scan ended at: ${scanEndDate}`);
            console.log(`[${scanId}] 🎉 AWS scan completed!`, {
                duration: Utils.DataUtils.formatDuration(totalDuration),
                totalServices: services.length,
                successfulServices: successfulServices,
                failedServices: failedServices,
                successRate: Math.round((successfulServices / services.length) * 100) + '%',
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
            console.error(`[${scanId}] 💥 AWS scan failed after ${Utils.DataUtils.formatDuration(totalDuration)}:`, error);
            
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
            
            throw new Error(`AWS scan failed: ${error.message}`);
        }
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

    getAvailableServices() {
        return [
            'ec2', 'rds', 'lambda', 'cloudfront', 'dynamodb', 'iam',
            'sns', 'sqs', 'ecr', 'elasticbeanstalk', 'route53', 'cloudwatch',
            'codepipeline', 'sagemaker', 'secretsmanager', 'glue', 'stepfunctions',
            'eks', 'cloudtrail', 'kinesis', 'redshift', 'elasticache', 'ecs',
            'apigateway', 'cloudformation', 'appsync', 'ssm', 'elastictranscoder',
            'datapipeline', 'mediaconvert', 'storagegateway', 'workspaces',
            'cloud9', 'lex', 'iot', 'medialive', 'datasync', 'emr', 'athena',
            'pinpoint', 'efs', 'mediapackage', 'mq', 'organizations', 'detective',
            'opsworks', 'codecommit', 'appmesh', 'backup', 'mediastore'
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
            mediastore: this.scanMediaStore
        };
        
        return scanners[service];
    }

    // Compute Services
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
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AWSScanner;
} 