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
    }

    async scan(credentials, selectedServices = null) {
        const scanId = Utils.SecurityUtils.generateRandomString(8);
        const scanStartTime = Date.now();
        
        console.log(`[${scanId}] 🏗️  Initializing AWS scanner...`);
        
        try {
            console.log(`[${scanId}] 🔐 Validating AWS credentials...`);
            this.validateCredentials(credentials);
            console.log(`[${scanId}] ✅ AWS credentials validated`);
            
            // Initialize AWS SDK
            console.log(`[${scanId}] 🔧 Initializing AWS SDK...`);
            await this.initializeSDK(credentials);
            console.log(`[${scanId}] ✅ AWS SDK initialized successfully`);
            
            // Detect available services at runtime
            console.log(`[${scanId}] 🔍 Detecting available AWS services...`);
            const { availableServices, unavailableServices } = this.detectAvailableServices();
            console.log(`[${scanId}] ✅ Service detection completed:`, {
                available: availableServices.length,
                unavailable: unavailableServices.length,
                total: availableServices.length + unavailableServices.length
            });
            
            // Extract account information
            console.log(`[${scanId}] 🔍 Extracting account information...`);
            await this.extractAccountInfo();
            console.log(`[${scanId}] ✅ Account information extracted:`, this.accountInfo);
            
            // Get services to scan (use detected available services if no specific selection)
            const services = selectedServices || availableServices;
            console.log(`[${scanId}] 📋 Services to scan: ${services.length}`, {
                services: services,
                selectedServices: selectedServices ? selectedServices.length : 'ALL',
                availableServices: availableServices.length
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
            
            const totalDuration = Date.now() - scanStartTime;
            console.log(`[${scanId}] 🎉 AWS scan completed!`, {
                duration: Utils.DataUtils.formatDuration(totalDuration),
                totalServices: services.length,
                successfulServices: successfulServices,
                failedServices: failedServices,
                successRate: Math.round((successfulServices / services.length) * 100) + '%',
                accountInfo: this.accountInfo
            });
            
            return this.getFinalResults();
        } catch (error) {
            const totalDuration = Date.now() - scanStartTime;
            console.error(`[${scanId}] 💥 AWS scan failed after ${Utils.DataUtils.formatDuration(totalDuration)}:`, error);
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

    /**
     * Detect which AWS services are available in the current SDK version
     * @returns {Object} Object containing available and unavailable services
     */
    detectAvailableServices() {
        // List of all AWS services we want to check
        const allServices = [
            'ec2', 's3', 'rds', 'lambda', 'cloudfront', 'dynamodb', 'iam',
            'sns', 'sqs', 'ecr', 'elasticbeanstalk', 'route53', 'cloudwatch',
            'codepipeline', 'sagemaker', 'secretsmanager', 'glue', 'stepfunctions',
            'eks', 'cloudtrail', 'kinesis', 'redshift', 'elasticache', 'ecs',
            'apigateway', 'cloudformation', 'appsync', 'ssm', 'elastictranscoder',
            'datapipeline', 'mediaconvert', 'storagegateway', 'workspaces',
            'cloud9', 'lex', 'iot', 'medialive', 'datasync', 'emr', 'athena',
            'pinpoint', 'efs', 'mediapackage', 'mq', 'organizations', 'detective',
            'opsworks', 'codecommit', 'appmesh', 'backup', 'mediastore',
            'lightsail', 'batch', 'elasticsearch', 'neptune', 'docdb', 'timestream',
            'qldb', 'keyspaces', 'memorydb', 'opensearch', 'mwaa', 'amplify',
            'apprunner', 'cloudhsm', 'guardduty', 'macie', 'waf', 'shield', 
            'config', 'inspector', 'artifact', 'servicecatalog', 'ram',
            'vpc', 'directconnect', 'transitgateway', 'vpn', 'natgateway',
            'elasticip', 'loadbalancer', 'autoscaling', 'ec2spot'
        ];

        const availableServices = [];
        const unavailableServices = [];

        console.log('🔍 Detecting AWS service availability...');
        
        for (const service of allServices) {
            const serviceName = service.toUpperCase();
            
            if (typeof AWS[serviceName] === 'function') {
                availableServices.push(service);
                console.log(`✅ ${service} (${serviceName}) - Available`);
            } else {
                unavailableServices.push(service);
                console.log(`❌ ${service} (${serviceName}) - Not available`);
            }
        }

        console.log(`📊 Service detection summary:`, {
            total: allServices.length,
            available: availableServices.length,
            unavailable: unavailableServices.length,
            availableServices: availableServices,
            unavailableServices: unavailableServices
        });

        return { availableServices, unavailableServices };
    }

    /**
     * Get list of all services (for backward compatibility)
     * @returns {Array} List of all services
     */
    getAvailableServices() {
        const { availableServices } = this.detectAvailableServices();
        return availableServices;
    }

    async scanService(service) {
        const scanner = this.getServiceScanner(service);
        if (scanner) {
            await scanner.call(this);
        }
    }

    getServiceScanner(service) {
        // Convert service name to AWS SDK format (e.g., 'ec2' -> 'EC2')
        const serviceName = service.toUpperCase();
        
        // Check if service constructor exists in AWS SDK at runtime
        if (typeof AWS[serviceName] !== 'function') {
            console.log(`🚧 ${service} (${serviceName}) not available in AWS SDK v2 browser version`);
            return this.scanUnavailableService.bind(this, service);
        }

        const scanners = {
            // Available services in AWS SDK v2 browser version
            ec2: this.scanEC2,
            s3: this.scanS3,
            iam: this.scanIAM,
            rds: this.scanRDS,
            dynamodb: this.scanDynamoDB,
            lambda: this.scanLambda,
            ecs: this.scanECS,
            elasticbeanstalk: this.scanElasticBeanstalk,
            emr: this.scanEMR,
            efs: this.scanEFS,
            storagegateway: this.scanStorageGateway,
            redshift: this.scanRedshift,
            elasticache: this.scanElastiCache,
            athena: this.scanAthena,
            route53: this.scanRoute53,
            apigateway: this.scanAPIGateway,
            cloudfront: this.scanCloudFront,
            cloudtrail: this.scanCloudTrail,
            secretsmanager: this.scanSecretsManager,
            kinesis: this.scanKinesis,
            cloudwatch: this.scanCloudWatch,
            elastictranscoder: this.scanElasticTranscoder,
            codepipeline: this.scanCodePipeline,
            codecommit: this.scanCodeCommit,
            ssm: this.scanSSM,
            cloudformation: this.scanCloudFormation,
            opsworks: this.scanOpsWorks,
            ecr: this.scanECR,
            sns: this.scanSNS,
            sqs: this.scanSQS
        };
        
        return scanners[service];
    }

    /**
     * Handle services not available in AWS SDK v2 browser version
     * @param {string} service - Service name
     */
    async scanUnavailableService(service) {
        const serviceName = service.toUpperCase();
        console.log(`🚧 ${service} (${serviceName}) not available in AWS SDK v2 browser version - constructor not found`);
        this.addUnimplementedService(service);
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
    async scanS3() {
        console.log('🪣 S3 scan skipped due to CORS limitations...');
        
        // Update detailed progress
        if (this.onDetailedProgressUpdate) {
            this.onDetailedProgressUpdate('s3', 'cors-limitation', 'S3 blocked by CORS policy', '1/1');
        }
        
        // Add S3 to CORS-limited services instead of trying to scan it
        this.addCorsLimitedService('s3', 'S3 has strict CORS policies that prevent browser-based access. This is a security feature protecting your cloud storage resources.');
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

    // Actually implemented services - these will try to scan and handle access issues properly
    async scanElasticBeanstalk() {
        try {
            const elasticbeanstalk = new AWS.ElasticBeanstalk();
            const environmentsData = await elasticbeanstalk.describeEnvironments().promise();
            this.addResult('elasticbeanstalk', { environments: environmentsData.Environments || [] });
        } catch (error) {
            this.addResult('elasticbeanstalk', { error: error.message });
        }
    }

    async scanRoute53() {
        try {
            const route53 = new AWS.Route53();
            const hostedZonesData = await route53.listHostedZones().promise();
            this.addResult('route53', { hostedZones: hostedZonesData.HostedZones || [] });
        } catch (error) {
            this.addResult('route53', { error: error.message });
        }
    }

    async scanCloudWatch() {
        try {
            const cloudwatch = new AWS.CloudWatch();
            const alarmsData = await cloudwatch.describeAlarms().promise();
            this.addResult('cloudwatch', { alarms: alarmsData.MetricAlarms || [] });
        } catch (error) {
            this.addResult('cloudwatch', { error: error.message });
        }
    }

    async scanCodePipeline() {
        try {
            const codepipeline = new AWS.CodePipeline();
            const pipelinesData = await codepipeline.listPipelines().promise();
            this.addResult('codepipeline', { pipelines: pipelinesData.pipelines || [] });
        } catch (error) {
            this.addResult('codepipeline', { error: error.message });
        }
    }

    async scanSageMaker() {
        try {
            const sagemaker = new AWS.SageMaker();
            const notebooksData = await sagemaker.listNotebookInstances().promise();
            this.addResult('sagemaker', { notebookInstances: notebooksData.NotebookInstances || [] });
        } catch (error) {
            this.addResult('sagemaker', { error: error.message });
        }
    }

    async scanSecretsManager() {
        try {
            const secretsmanager = new AWS.SecretsManager();
            const secretsData = await secretsmanager.listSecrets().promise();
            this.addResult('secretsmanager', { secrets: secretsData.SecretList || [] });
        } catch (error) {
            this.addResult('secretsmanager', { error: error.message });
        }
    }

    async scanGlue() {
        try {
            const glue = new AWS.Glue();
            const databasesData = await glue.getDatabases().promise();
            this.addResult('glue', { databases: databasesData.DatabaseList || [] });
        } catch (error) {
            this.addResult('glue', { error: error.message });
        }
    }

    async scanStepFunctions() {
        try {
            const stepfunctions = new AWS.StepFunctions();
            const stateMachinesData = await stepfunctions.listStateMachines().promise();
            this.addResult('stepfunctions', { stateMachines: stateMachinesData.stateMachines || [] });
        } catch (error) {
            this.addResult('stepfunctions', { error: error.message });
        }
    }

    async scanCloudTrail() {
        try {
            const cloudtrail = new AWS.CloudTrail();
            const trailsData = await cloudtrail.describeTrails().promise();
            this.addResult('cloudtrail', { trails: trailsData.trailList || [] });
        } catch (error) {
            this.addResult('cloudtrail', { error: error.message });
        }
    }

    async scanKinesis() {
        try {
            const kinesis = new AWS.Kinesis();
            const streamsData = await kinesis.listStreams().promise();
            this.addResult('kinesis', { streams: streamsData.StreamNames || [] });
        } catch (error) {
            this.addResult('kinesis', { error: error.message });
        }
    }

    async scanRedshift() {
        try {
            const redshift = new AWS.Redshift();
            const clustersData = await redshift.describeClusters().promise();
            this.addResult('redshift', { clusters: clustersData.Clusters || [] });
        } catch (error) {
            this.addResult('redshift', { error: error.message });
        }
    }

    async scanElastiCache() {
        try {
            const elasticache = new AWS.ElastiCache();
            const clustersData = await elasticache.describeCacheClusters().promise();
            this.addResult('elasticache', { clusters: clustersData.CacheClusters || [] });
        } catch (error) {
            this.addResult('elasticache', { error: error.message });
        }
    }

    async scanAPIGateway() {
        try {
            const apigateway = new AWS.APIGateway();
            const apisData = await apigateway.getRestApis().promise();
            this.addResult('apigateway', { apis: apisData.items || [] });
        } catch (error) {
            this.addResult('apigateway', { error: error.message });
        }
    }

    async scanCloudFormation() {
        try {
            const cloudformation = new AWS.CloudFormation();
            const stacksData = await cloudformation.listStacks().promise();
            this.addResult('cloudformation', { stacks: stacksData.StackSummaries || [] });
        } catch (error) {
            this.addResult('cloudformation', { error: error.message });
        }
    }

    async scanAppSync() {
        try {
            const appsync = new AWS.AppSync();
            const apisData = await appsync.listGraphqlApis().promise();
            this.addResult('appsync', { apis: apisData.graphqlApis || [] });
        } catch (error) {
            this.addResult('appsync', { error: error.message });
        }
    }

    async scanSSM() {
        try {
            const ssm = new AWS.SSM();
            const parametersData = await ssm.describeParameters().promise();
            this.addResult('ssm', { parameters: parametersData.Parameters || [] });
        } catch (error) {
            this.addResult('ssm', { error: error.message });
        }
    }

    async scanElasticTranscoder() {
        try {
            const elastictranscoder = new AWS.ElasticTranscoder();
            const pipelinesData = await elastictranscoder.listPipelines().promise();
            this.addResult('elastictranscoder', { pipelines: pipelinesData.Pipelines || [] });
        } catch (error) {
            this.addResult('elastictranscoder', { error: error.message });
        }
    }

    async scanDataPipeline() {
        try {
            const datapipeline = new AWS.DataPipeline();
            const pipelinesData = await datapipeline.listPipelines().promise();
            this.addResult('datapipeline', { pipelines: pipelinesData.pipelineIdList || [] });
        } catch (error) {
            this.addResult('datapipeline', { error: error.message });
        }
    }

    async scanMediaConvert() {
        try {
            const mediaconvert = new AWS.MediaConvert();
            const queuesData = await mediaconvert.listQueues().promise();
            this.addResult('mediaconvert', { queues: queuesData.Queues || [] });
        } catch (error) {
            this.addResult('mediaconvert', { error: error.message });
        }
    }

    async scanStorageGateway() {
        try {
            const storagegateway = new AWS.StorageGateway();
            const gatewaysData = await storagegateway.listGateways().promise();
            this.addResult('storagegateway', { gateways: gatewaysData.Gateways || [] });
        } catch (error) {
            this.addResult('storagegateway', { error: error.message });
        }
    }

    async scanWorkSpaces() {
        try {
            const workspaces = new AWS.WorkSpaces();
            const workspacesData = await workspaces.describeWorkspaces().promise();
            this.addResult('workspaces', { workspaces: workspacesData.Workspaces || [] });
        } catch (error) {
            this.addResult('workspaces', { error: error.message });
        }
    }

    async scanCloud9() {
        try {
            const cloud9 = new AWS.Cloud9();
            const environmentsData = await cloud9.listEnvironments().promise();
            this.addResult('cloud9', { environments: environmentsData.environmentIds || [] });
        } catch (error) {
            this.addResult('cloud9', { error: error.message });
        }
    }

    async scanLex() {
        try {
            const lex = new AWS.LexModelBuildingService();
            const botsData = await lex.getBots().promise();
            this.addResult('lex', { bots: botsData.bots || [] });
        } catch (error) {
            this.addResult('lex', { error: error.message });
        }
    }

    async scanIoT() {
        try {
            const iot = new AWS.Iot();
            const thingsData = await iot.listThings().promise();
            this.addResult('iot', { things: thingsData.things || [] });
        } catch (error) {
            this.addResult('iot', { error: error.message });
        }
    }

    async scanMediaLive() {
        try {
            const medialive = new AWS.MediaLive();
            const channelsData = await medialive.listChannels().promise();
            this.addResult('medialive', { channels: channelsData.Channels || [] });
        } catch (error) {
            this.addResult('medialive', { error: error.message });
        }
    }

    async scanDataSync() {
        try {
            const datasync = new AWS.DataSync();
            const tasksData = await datasync.listTasks().promise();
            this.addResult('datasync', { tasks: tasksData.Tasks || [] });
        } catch (error) {
            this.addResult('datasync', { error: error.message });
        }
    }

    async scanEMR() {
        try {
            const emr = new AWS.EMR();
            const clustersData = await emr.listClusters().promise();
            this.addResult('emr', { clusters: clustersData.Clusters || [] });
        } catch (error) {
            this.addResult('emr', { error: error.message });
        }
    }

    async scanAthena() {
        try {
            const athena = new AWS.Athena();
            const workgroupsData = await athena.listWorkGroups().promise();
            this.addResult('athena', { workgroups: workgroupsData.WorkGroups || [] });
        } catch (error) {
            this.addResult('athena', { error: error.message });
        }
    }

    async scanPinpoint() {
        try {
            const pinpoint = new AWS.Pinpoint();
            const appsData = await pinpoint.getApps().promise();
            this.addResult('pinpoint', { apps: appsData.ApplicationsResponse.Item || [] });
        } catch (error) {
            this.addResult('pinpoint', { error: error.message });
        }
    }

    async scanMediaPackage() {
        try {
            const mediapackage = new AWS.MediaPackage();
            const channelsData = await mediapackage.listChannels().promise();
            this.addResult('mediapackage', { channels: channelsData.Channels || [] });
        } catch (error) {
            this.addResult('mediapackage', { error: error.message });
        }
    }

    async scanMQ() {
        try {
            const mq = new AWS.MQ();
            const brokersData = await mq.listBrokers().promise();
            this.addResult('mq', { brokers: brokersData.BrokerSummaries || [] });
        } catch (error) {
            this.addResult('mq', { error: error.message });
        }
    }

    async scanOrganizations() {
        try {
            const organizations = new AWS.Organizations();
            const accountsData = await organizations.listAccounts().promise();
            this.addResult('organizations', { accounts: accountsData.Accounts || [] });
        } catch (error) {
            this.addResult('organizations', { error: error.message });
        }
    }

    async scanDetective() {
        try {
            const detective = new AWS.Detective();
            const graphsData = await detective.listGraphs().promise();
            this.addResult('detective', { graphs: graphsData.GraphList || [] });
        } catch (error) {
            this.addResult('detective', { error: error.message });
        }
    }

    async scanOpsWorks() {
        try {
            const opsworks = new AWS.OpsWorks();
            const stacksData = await opsworks.describeStacks().promise();
            this.addResult('opsworks', { stacks: stacksData.Stacks || [] });
        } catch (error) {
            this.addResult('opsworks', { error: error.message });
        }
    }

    async scanCodeCommit() {
        try {
            const codecommit = new AWS.CodeCommit();
            const repositoriesData = await codecommit.listRepositories().promise();
            this.addResult('codecommit', { repositories: repositoriesData.repositories || [] });
        } catch (error) {
            this.addResult('codecommit', { error: error.message });
        }
    }

    async scanAppMesh() {
        try {
            const appmesh = new AWS.AppMesh();
            const meshesData = await appmesh.listMeshes().promise();
            this.addResult('appmesh', { meshes: meshesData.meshes || [] });
        } catch (error) {
            this.addResult('appmesh', { error: error.message });
        }
    }

    async scanBackup() {
        try {
            const backup = new AWS.Backup();
            const vaultsData = await backup.listBackupVaults().promise();
            this.addResult('backup', { vaults: vaultsData.BackupVaultList || [] });
        } catch (error) {
            this.addResult('backup', { error: error.message });
        }
    }

    async scanMediaStore() {
        try {
            const mediastore = new AWS.MediaStore();
            const containersData = await mediastore.listContainers().promise();
            this.addResult('mediastore', { containers: containersData.Containers || [] });
        } catch (error) {
            this.addResult('mediastore', { error: error.message });
        }
    }

    async scanECR() {
        try {
            const ecr = new AWS.ECR();
            const repositoriesData = await ecr.describeRepositories().promise();
            this.addResult('ecr', { repositories: repositoriesData.repositories || [] });
        } catch (error) {
            this.addResult('ecr', { error: error.message });
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
     * Add CORS-limited service to the grouped list
     * @param {string} service - Service name
     * @param {string} reason - Reason for CORS limitation
     */
    addCorsLimitedService(service, reason) {
        if (!this.corsLimitedServices) {
            this.corsLimitedServices = [];
        }
        this.corsLimitedServices.push({
            name: service,
            reason: reason
        });
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
     * Get final results with unimplemented and CORS-limited services
     * @returns {Object} Final results
     */
    getFinalResults() {
        const finalResults = { ...this.results };
        
        // Add account information to results
        if (this.accountInfo) {
            finalResults['account_info'] = this.accountInfo;
        }

        // Add service detection results
        const { availableServices, unavailableServices } = this.detectAvailableServices();
        finalResults['service_detection'] = {
            total: availableServices.length + unavailableServices.length,
            available: availableServices.length,
            unavailable: unavailableServices.length,
            available_services: availableServices,
            unavailable_services: unavailableServices
        };

        // Add grouped unimplemented services if any exist
        if (this.unimplementedServices && this.unimplementedServices.length > 0) {
            finalResults['unimplemented_services'] = {
                message: 'Services not available in AWS SDK v2 browser version (detected at runtime)',
                services: this.unimplementedServices,
                count: this.unimplementedServices.length
            };
        }

        // Add grouped CORS-limited services if any exist
        if (this.corsLimitedServices && this.corsLimitedServices.length > 0) {
            finalResults['cors_limited_services'] = this.corsLimitedServices;
        }
        
        return finalResults;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AWSScanner;
} 