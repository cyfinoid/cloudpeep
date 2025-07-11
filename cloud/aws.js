/**
 * AWS Cloud Scanner for PeekInTheCloud
 * Handles AWS service scanning and permission checking
 */

const AWSCloudScanner = {
    /**
     * Scan all AWS services with the provided credentials
     * @param {Object} credentials - AWS credentials object
     * @returns {Promise<Object>} - Scan results
     */
    async scanServices(credentials) {
        console.log('Starting AWS service scan...');
        
        const results = {};
        const services = ['s3', 'ec2', 'iam', 'sts', 'lambda'];
        
        // Configure AWS SDK
        AWS.config.update({
            accessKeyId: credentials.accessKeyId,
            secretAccessKey: credentials.secretAccessKey,
            region: credentials.region
        });
        
        if (credentials.sessionToken) {
            AWS.config.update({
                sessionToken: credentials.sessionToken
            });
        }
        
        // Scan each service
        for (const service of services) {
            try {
                console.log(`Scanning ${service}...`);
                results[service] = await this.scanService(service, credentials);
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
        
        console.log('AWS service scan completed');
        return results;
    },
    
    /**
     * Scan a specific AWS service
     * @param {string} service - Service name
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - Service scan result
     */
    async scanService(service, credentials) {
        switch (service) {
            case 's3':
                return await this.scanS3(credentials);
            case 'ec2':
                return await this.scanEC2(credentials);
            case 'iam':
                return await this.scanIAM(credentials);
            case 'sts':
                return await this.scanSTS(credentials);
            case 'lambda':
                return await this.scanLambda(credentials);
            default:
                throw new Error(`Unsupported AWS service: ${service}`);
        }
    },
    
    /**
     * Scan S3 service
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - S3 scan result
     */
    async scanS3(credentials) {
        const s3 = new AWS.S3();
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Test ListBuckets
            const listBucketsResult = await s3.listBuckets().promise();
            result.apiCalls.push('ListBuckets');
            result.resources = listBucketsResult.Buckets.map(bucket => bucket.Name);
            result.rawResponse = listBucketsResult;
            result.permission = 'list';
            result.accessible = true;
            result.status = 'accessible';
            
            // Test GetObject on first bucket if available
            if (result.resources.length > 0) {
                try {
                    const testBucket = result.resources[0];
                    const listObjectsResult = await s3.listObjectsV2({
                        Bucket: testBucket,
                        MaxKeys: 1
                    }).promise();
                    result.apiCalls.push('ListObjectsV2');
                    
                    if (listObjectsResult.Contents && listObjectsResult.Contents.length > 0) {
                        try {
                            const testObject = listObjectsResult.Contents[0].Key;
                            await s3.getObject({
                                Bucket: testBucket,
                                Key: testObject
                            }).promise();
                            result.apiCalls.push('GetObject');
                            result.permission = 'read';
                        } catch (error) {
                            if (error.code === 'AccessDenied') {
                                // Can list but not read objects
                                result.permission = 'list';
                            }
                        }
                    }
                } catch (error) {
                    // Can list buckets but not objects
                    result.permission = 'list';
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'S3');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan EC2 service
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - EC2 scan result
     */
    async scanEC2(credentials) {
        const ec2 = new AWS.EC2();
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Test DescribeInstances
            const describeInstancesResult = await ec2.describeInstances().promise();
            result.apiCalls.push('DescribeInstances');
            result.rawResponse = describeInstancesResult;
            
            // Extract instance information
            const instances = [];
            describeInstancesResult.Reservations.forEach(reservation => {
                reservation.Instances.forEach(instance => {
                    instances.push({
                        id: instance.InstanceId,
                        type: instance.InstanceType,
                        state: instance.State.Name,
                        launchTime: instance.LaunchTime
                    });
                });
            });
            
            result.resources = instances.map(instance => `${instance.id} (${instance.type})`);
            result.permission = 'read';
            result.accessible = true;
            result.status = 'accessible';
            
            // Test additional EC2 APIs
            try {
                const describeSecurityGroupsResult = await ec2.describeSecurityGroups().promise();
                result.apiCalls.push('DescribeSecurityGroups');
            } catch (error) {
                // Security groups not accessible
            }
            
            try {
                const describeVolumesResult = await ec2.describeVolumes().promise();
                result.apiCalls.push('DescribeVolumes');
            } catch (error) {
                // Volumes not accessible
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'EC2');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan IAM service
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - IAM scan result
     */
    async scanIAM(credentials) {
        const iam = new AWS.IAM();
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Test ListUsers
            const listUsersResult = await iam.listUsers().promise();
            result.apiCalls.push('ListUsers');
            result.resources = listUsersResult.Users.map(user => user.UserName);
            result.rawResponse = listUsersResult;
            result.permission = 'list';
            result.accessible = true;
            result.status = 'accessible';
            
            // Test ListRoles
            try {
                const listRolesResult = await iam.listRoles().promise();
                result.apiCalls.push('ListRoles');
                result.resources.push(...listRolesResult.Roles.map(role => `Role: ${role.RoleName}`));
            } catch (error) {
                // Roles not accessible
            }
            
            // Test ListPolicies
            try {
                const listPoliciesResult = await iam.listPolicies().promise();
                result.apiCalls.push('ListPolicies');
                result.resources.push(...listPoliciesResult.Policies.map(policy => `Policy: ${policy.PolicyName}`));
            } catch (error) {
                // Policies not accessible
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
     * Scan STS service
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - STS scan result
     */
    async scanSTS(credentials) {
        const sts = new AWS.STS();
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Test GetCallerIdentity
            const getCallerIdentityResult = await sts.getCallerIdentity().promise();
            result.apiCalls.push('GetCallerIdentity');
            result.rawResponse = getCallerIdentityResult;
            result.resources = [
                `Account: ${getCallerIdentityResult.Account}`,
                `User: ${getCallerIdentityResult.UserId}`,
                `ARN: ${getCallerIdentityResult.Arn}`
            ];
            result.permission = 'read';
            result.accessible = true;
            result.status = 'accessible';
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'STS');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    },
    
    /**
     * Scan Lambda service
     * @param {Object} credentials - AWS credentials
     * @returns {Promise<Object>} - Lambda scan result
     */
    async scanLambda(credentials) {
        const lambda = new AWS.Lambda();
        const result = {
            status: 'unknown',
            accessible: false,
            permission: 'none',
            resources: [],
            apiCalls: [],
            rawResponse: null
        };
        
        try {
            // Test ListFunctions
            const listFunctionsResult = await lambda.listFunctions().promise();
            result.apiCalls.push('ListFunctions');
            result.resources = listFunctionsResult.Functions.map(func => func.FunctionName);
            result.rawResponse = listFunctionsResult;
            result.permission = 'list';
            result.accessible = true;
            result.status = 'accessible';
            
            // Test GetFunction for first function if available
            if (result.resources.length > 0) {
                try {
                    const testFunction = result.resources[0];
                    const getFunctionResult = await lambda.getFunction({
                        FunctionName: testFunction
                    }).promise();
                    result.apiCalls.push('GetFunction');
                    result.permission = 'read';
                } catch (error) {
                    // Can list but not get function details
                    result.permission = 'list';
                }
            }
            
        } catch (error) {
            const errorInfo = Utils.ErrorHandler.handleAPIError(error, 'Lambda');
            result.status = 'inaccessible';
            result.error = errorInfo.message;
            result.permission = 'none';
        }
        
        return result;
    }
};

// Export for use in main application
window.AWSCloudScanner = AWSCloudScanner; 