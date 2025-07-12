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
            
            // Extract account information
            console.log(`[${scanId}] 🔍 Extracting account information...`);
            await this.extractAccountInfo();
            console.log(`[${scanId}] ✅ Account information extracted:`, this.accountInfo);
            
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

    getAvailableServices() {
        return [
            'ec2', 's3', 'rds', 'lambda', 'cloudfront', 'dynamodb', 'iam',
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
            s3: this.scanS3,
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
            
            try {
                const ec2 = new AWS.EC2({ region });
                
                // Scan instances
                console.log(`[${scanId}] 🔍 Scanning EC2 instances in ${region}...`);
                const instancesData = await ec2.describeInstances().promise();
                const regionInstances = [];
                for (const reservation of instancesData.Reservations) {
                    for (const instance of reservation.Instances) {
                        regionInstances.push({
                            instanceId: instance.InstanceId,
                            instanceType: instance.InstanceType,
                            state: instance.State.Name,
                            launchTime: instance.LaunchTime,
                            publicIpAddress: instance.PublicIpAddress,
                            privateIpAddress: instance.PrivateIpAddress,
                            iamInstanceProfile: instance.IamInstanceProfile ? instance.IamInstanceProfile.Arn : null,
                            blockDeviceMappings: instance.BlockDeviceMappings,
                            vpcId: instance.VpcId,
                            subnetId: instance.SubnetId,
                            securityGroups: instance.SecurityGroups,
                            region: region
                        });
                    }
                }
                instances.push(...regionInstances);
                totalInstances += regionInstances.length;
                console.log(`[${scanId}] ✅ Found ${regionInstances.length} instances in ${region}`);

                // Scan VPCs
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
                        
                        functions.push({
                            functionName: func.FunctionName,
                            runtime: func.Runtime,
                            handler: func.Handler,
                            codeSize: func.CodeSize,
                            description: func.Description,
                            timeout: functionConfig.Timeout,
                            memorySize: functionConfig.MemorySize,
                            role: functionConfig.Role,
                            environmentVariables: environmentVariables,
                            sensitiveEnvironmentVariables: sensitiveVars,
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
                            environmentVariables: {},
                            sensitiveEnvironmentVariables: [],
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
        try {
            const s3 = new AWS.S3();
            const bucketsData = await s3.listBuckets().promise();
            const buckets = [];
            
            for (const bucket of bucketsData.Buckets) {
                try {
                    const location = await s3.getBucketLocation({ Bucket: bucket.Name }).promise();
                    
                    // Get additional bucket details for security analysis
                    let encryption = null;
                    let versioning = null;
                    let publicAccessBlock = null;
                    
                    try {
                        // Check encryption
                        const encryptionData = await s3.getBucketEncryption({ Bucket: bucket.Name }).promise();
                        encryption = encryptionData.ServerSideEncryptionConfiguration;
                    } catch (error) {
                        // Bucket might not have encryption configured
                        encryption = null;
                    }
                    
                    try {
                        // Check versioning
                        const versioningData = await s3.getBucketVersioning({ Bucket: bucket.Name }).promise();
                        versioning = versioningData.Status === 'Enabled';
                    } catch (error) {
                        versioning = false;
                    }
                    
                    try {
                        // Check public access block
                        const publicAccessData = await s3.getPublicAccessBlock({ Bucket: bucket.Name }).promise();
                        publicAccessBlock = publicAccessData.PublicAccessBlockConfiguration;
                    } catch (error) {
                        // Use default values if public access block is not configured
                        publicAccessBlock = {
                            BlockPublicAcls: false,
                            IgnorePublicAcls: false,
                            BlockPublicPolicy: false,
                            RestrictPublicBuckets: false
                        };
                    }
                    
                    buckets.push({
                        name: bucket.Name,
                        creationDate: bucket.CreationDate,
                        location: location.LocationConstraint || 'us-east-1',
                        encryption: encryption,
                        versioning: versioning,
                        publicAccessBlock: publicAccessBlock
                    });
                } catch (error) {
                    buckets.push({
                        name: bucket.Name,
                        creationDate: bucket.CreationDate,
                        location: 'Unknown',
                        encryption: null,
                        versioning: false,
                        publicAccessBlock: {
                            BlockPublicAcls: false,
                            IgnorePublicAcls: false,
                            BlockPublicPolicy: false,
                            RestrictPublicBuckets: false
                        }
                    });
                }
            }

            this.addResult('s3', { buckets });
        } catch (error) {
            console.error('Error scanning S3:', error);
            this.addResult('s3', { error: error.message });
        }
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
            const usersData = await iam.listUsers().promise();
            for (const user of usersData.Users) {
                results.users.push({
                    userName: user.UserName,
                    arn: user.Arn,
                    createDate: user.CreateDate
                });
            }

            // Scan roles
            const rolesData = await iam.listRoles().promise();
            for (const role of rolesData.Roles) {
                results.roles.push({
                    roleName: role.RoleName,
                    arn: role.Arn,
                    createDate: role.CreateDate
                });
            }

            // Scan groups
            const groupsData = await iam.listGroups().promise();
            for (const group of groupsData.Groups) {
                results.groups.push({
                    groupName: group.GroupName,
                    arn: group.Arn,
                    createDate: group.CreateDate
                });
            }

            // Scan policies
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

    // Additional service scanners (simplified for brevity)
    async scanS3() {
        try {
            const s3 = new AWS.S3();
            const bucketsData = await s3.listBuckets().promise();
            const buckets = [];
            
            for (const bucket of bucketsData.Buckets) {
                buckets.push({
                    name: bucket.Name,
                    creationDate: bucket.CreationDate
                });
            }

            this.addResult('s3', { buckets });
        } catch (error) {
            this.addResult('s3', { error: error.message });
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

    // Placeholder methods for other services - these will be grouped together
    async scanElasticBeanstalk() { this.addUnimplementedService('elasticbeanstalk'); }
    async scanRoute53() { this.addUnimplementedService('route53'); }
    async scanCloudWatch() { this.addUnimplementedService('cloudwatch'); }
    async scanCodePipeline() { this.addUnimplementedService('codepipeline'); }
    async scanSageMaker() { this.addUnimplementedService('sagemaker'); }
    async scanSecretsManager() { this.addUnimplementedService('secretsmanager'); }
    async scanGlue() { this.addUnimplementedService('glue'); }
    async scanStepFunctions() { this.addUnimplementedService('stepfunctions'); }
    async scanCloudTrail() { this.addUnimplementedService('cloudtrail'); }
    async scanKinesis() { this.addUnimplementedService('kinesis'); }
    async scanRedshift() { this.addUnimplementedService('redshift'); }
    async scanElastiCache() { this.addUnimplementedService('elasticache'); }
    async scanAPIGateway() { this.addUnimplementedService('apigateway'); }
    async scanCloudFormation() { this.addUnimplementedService('cloudformation'); }
    async scanAppSync() { this.addUnimplementedService('appsync'); }
    async scanSSM() { this.addUnimplementedService('ssm'); }
    async scanElasticTranscoder() { this.addUnimplementedService('elastictranscoder'); }
    async scanDataPipeline() { this.addUnimplementedService('datapipeline'); }
    async scanMediaConvert() { this.addUnimplementedService('mediaconvert'); }
    async scanStorageGateway() { this.addUnimplementedService('storagegateway'); }
    async scanWorkSpaces() { this.addUnimplementedService('workspaces'); }
    async scanCloud9() { this.addUnimplementedService('cloud9'); }
    async scanLex() { this.addUnimplementedService('lex'); }
    async scanIoT() { this.addUnimplementedService('iot'); }
    async scanMediaLive() { this.addUnimplementedService('medialive'); }
    async scanDataSync() { this.addUnimplementedService('datasync'); }
    async scanEMR() { this.addUnimplementedService('emr'); }
    async scanAthena() { this.addUnimplementedService('athena'); }
    async scanPinpoint() { this.addUnimplementedService('pinpoint'); }
    async scanMediaPackage() { this.addUnimplementedService('mediapackage'); }
    async scanMQ() { this.addUnimplementedService('mq'); }
    async scanOrganizations() { this.addUnimplementedService('organizations'); }
    async scanDetective() { this.addUnimplementedService('detective'); }
    async scanOpsWorks() { this.addUnimplementedService('opsworks'); }
    async scanCodeCommit() { this.addUnimplementedService('codecommit'); }
    async scanAppMesh() { this.addUnimplementedService('appmesh'); }
    async scanBackup() { this.addUnimplementedService('backup'); }
    async scanMediaStore() { this.addUnimplementedService('mediastore'); }
    async scanECR() { this.addUnimplementedService('ecr'); }

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
        
        // Add account information to results
        if (this.accountInfo) {
            finalResults['account_info'] = this.accountInfo;
        }
        
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
    module.exports = AWSScanner;
} 