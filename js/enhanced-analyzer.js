/**
 * PeekInTheCloud - Enhanced Resource Analysis Engine
 * Provides detailed security analysis of individual resources
 * Inspired by ScoutSuite's detailed resource analysis capabilities
 */

class EnhancedAnalyzer {
    constructor() {
        this.analysisResults = {};
        this.securityPosture = {};
    }

    /**
     * Perform enhanced analysis on scan results
     */
    performEnhancedAnalysis(provider, scanResults) {
        console.log(`[EnhancedAnalyzer] Starting enhanced analysis for ${provider}`);
        
        this.analysisResults = {
            provider: provider,
            timestamp: new Date().toISOString(),
            resources: {},
            securityPosture: {},
            recommendations: {}
        };

        switch (provider) {
            case 'aws':
                this.analyzeAWSResources(scanResults);
                break;
            case 'azure':
                this.analyzeAzureResources(scanResults);
                break;
            case 'gcp':
                this.analyzeGCPResources(scanResults);
                break;
        }

        this.calculateSecurityPosture();
        this.generateRecommendations();
        
        console.log(`[EnhancedAnalyzer] Enhanced analysis completed for ${Object.keys(this.analysisResults.resources).length} resources`);
        return this.analysisResults;
    }

    /**
     * Analyze AWS resources in detail
     */
    analyzeAWSResources(scanResults) {
        // Enhanced S3 Bucket Analysis
        if (scanResults.s3 && scanResults.s3.buckets) {
            scanResults.s3.buckets.forEach(bucket => {
                const analysis = this.analyzeS3Bucket(bucket);
                this.analysisResults.resources[`s3-${bucket.Name}`] = {
                    type: 'S3 Bucket',
                    name: bucket.Name,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced EC2 Instance Analysis
        if (scanResults.ec2 && scanResults.ec2.instances) {
            scanResults.ec2.instances.forEach(instance => {
                const analysis = this.analyzeEC2Instance(instance);
                this.analysisResults.resources[`ec2-${instance.InstanceId}`] = {
                    type: 'EC2 Instance',
                    name: instance.InstanceId,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced IAM User Analysis
        if (scanResults.iam && scanResults.iam.users) {
            scanResults.iam.users.forEach(user => {
                const analysis = this.analyzeIAMUser(user);
                this.analysisResults.resources[`iam-user-${user.UserName}`] = {
                    type: 'IAM User',
                    name: user.UserName,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced IAM Role Analysis
        if (scanResults.iam && scanResults.iam.roles) {
            scanResults.iam.roles.forEach(role => {
                const analysis = this.analyzeIAMRole(role);
                this.analysisResults.resources[`iam-role-${role.RoleName}`] = {
                    type: 'IAM Role',
                    name: role.RoleName,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced RDS Instance Analysis
        if (scanResults.rds && scanResults.rds.instances) {
            scanResults.rds.instances.forEach(instance => {
                const analysis = this.analyzeRDSInstance(instance);
                this.analysisResults.resources[`rds-${instance.DBInstanceIdentifier}`] = {
                    type: 'RDS Instance',
                    name: instance.DBInstanceIdentifier,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }
    }

    /**
     * Analyze Azure resources in detail
     */
    analyzeAzureResources(scanResults) {
        // Enhanced Virtual Machine Analysis
        if (scanResults.compute && scanResults.compute.virtual_machines) {
            scanResults.compute.virtual_machines.forEach(vm => {
                const analysis = this.analyzeAzureVM(vm);
                this.analysisResults.resources[`vm-${vm.id}`] = {
                    type: 'Virtual Machine',
                    name: vm.name,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced Storage Account Analysis
        if (scanResults.storage && scanResults.storage.storage_accounts) {
            scanResults.storage.storage_accounts.forEach(account => {
                const analysis = this.analyzeAzureStorageAccount(account);
                this.analysisResults.resources[`storage-${account.id}`] = {
                    type: 'Storage Account',
                    name: account.name,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }
    }

    /**
     * Analyze GCP resources in detail
     */
    analyzeGCPResources(scanResults) {
        // Enhanced Compute Instance Analysis
        if (scanResults.compute && scanResults.compute.instances) {
            scanResults.compute.instances.forEach(instance => {
                const analysis = this.analyzeGCPInstance(instance);
                this.analysisResults.resources[`gcp-instance-${instance.id}`] = {
                    type: 'Compute Instance',
                    name: instance.name,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }

        // Enhanced Cloud Storage Bucket Analysis
        if (scanResults.storage && scanResults.storage.buckets) {
            scanResults.storage.buckets.forEach(bucket => {
                const analysis = this.analyzeGCPBucket(bucket);
                this.analysisResults.resources[`gcp-bucket-${bucket.id}`] = {
                    type: 'Cloud Storage Bucket',
                    name: bucket.name,
                    analysis: analysis,
                    securityScore: this.calculateResourceSecurityScore(analysis),
                    riskLevel: this.determineRiskLevel(analysis)
                };
            });
        }
    }

    /**
     * Enhanced S3 Bucket Analysis
     */
    analyzeS3Bucket(bucket) {
        const analysis = {
            encryption: {
                enabled: bucket.ServerSideEncryptionConfiguration?.Rules?.some(rule => 
                    rule.ApplyServerSideEncryptionByDefault?.SSEAlgorithm
                ) || false,
                algorithm: bucket.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm || 'None',
                kmsKeyId: bucket.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.KMSMasterKeyID || null
            },
            versioning: {
                enabled: bucket.Versioning?.Status === 'Enabled',
                mfaDelete: bucket.Versioning?.MFADelete === 'Enabled'
            },
            logging: {
                enabled: bucket.Logging?.LoggingEnabled?.TargetBucket !== undefined,
                targetBucket: bucket.Logging?.LoggingEnabled?.TargetBucket || null,
                targetPrefix: bucket.Logging?.LoggingEnabled?.TargetPrefix || null
            },
            publicAccess: {
                blocked: bucket.PublicAccessBlockConfiguration?.BlockPublicAcls === true &&
                         bucket.PublicAccessBlockConfiguration?.IgnorePublicAcls === true &&
                         bucket.PublicAccessBlockConfiguration?.BlockPublicPolicy === true &&
                         bucket.PublicAccessBlockConfiguration?.RestrictPublicBuckets === true,
                blockPublicAcls: bucket.PublicAccessBlockConfiguration?.BlockPublicAcls || false,
                ignorePublicAcls: bucket.PublicAccessBlockConfiguration?.IgnorePublicAcls || false,
                blockPublicPolicy: bucket.PublicAccessBlockConfiguration?.BlockPublicPolicy || false,
                restrictPublicBuckets: bucket.PublicAccessBlockConfiguration?.RestrictPublicBuckets || false
            },
            policy: {
                hasPolicy: !!bucket.Policy,
                allowsPublicAccess: bucket.Policy?.includes('"Principal": "*"') || false,
                allowsCrossAccountAccess: bucket.Policy?.includes('"Principal": {"AWS":') || false
            },
            lifecycle: {
                hasRules: !!bucket.LifecycleConfiguration?.Rules?.length,
                rules: bucket.LifecycleConfiguration?.Rules || []
            },
            tags: bucket.Tags || [],
            findings: []
        };

        // Generate findings
        if (!analysis.encryption.enabled) {
            analysis.findings.push({
                severity: 'high',
                category: 'encryption',
                title: 'S3 Bucket Not Encrypted',
                description: 'Bucket does not have server-side encryption enabled',
                remediation: 'Enable server-side encryption for the bucket'
            });
        }

        if (!analysis.publicAccess.blocked) {
            analysis.findings.push({
                severity: 'critical',
                category: 'access',
                title: 'S3 Bucket Public Access Not Blocked',
                description: 'Bucket allows public access',
                remediation: 'Enable all public access block settings'
            });
        }

        if (analysis.policy.allowsPublicAccess) {
            analysis.findings.push({
                severity: 'critical',
                category: 'policy',
                title: 'S3 Bucket Policy Allows Public Access',
                description: 'Bucket policy allows public read/write access',
                remediation: 'Remove public access permissions from bucket policy'
            });
        }

        if (!analysis.logging.enabled) {
            analysis.findings.push({
                severity: 'medium',
                category: 'logging',
                title: 'S3 Bucket Logging Not Enabled',
                description: 'Bucket access logging is not enabled',
                remediation: 'Enable access logging for the bucket'
            });
        }

        return analysis;
    }

    /**
     * Enhanced EC2 Instance Analysis
     */
    analyzeEC2Instance(instance) {
        const analysis = {
            network: {
                publicIp: instance.PublicIpAddress,
                privateIp: instance.PrivateIpAddress,
                vpcId: instance.VpcId,
                subnetId: instance.SubnetId,
                hasPublicIp: !!instance.PublicIpAddress,
                inPublicSubnet: this.isInPublicSubnet(instance)
            },
            security: {
                securityGroups: instance.SecurityGroups || [],
                iamRole: instance.IamInstanceProfile?.Arn,
                hasIamRole: !!instance.IamInstanceProfile?.Arn,
                metadataOptions: instance.MetadataOptions || {},
                userData: instance.UserData
            },
            state: {
                state: instance.State?.Name,
                running: instance.State?.Name === 'running',
                stopped: instance.State?.Name === 'stopped',
                terminated: instance.State?.Name === 'terminated'
            },
            configuration: {
                instanceType: instance.InstanceType,
                platform: instance.Platform,
                architecture: instance.Architecture,
                rootDeviceType: instance.RootDeviceType,
                virtualizationType: instance.VirtualizationType
            },
            findings: []
        };

        // Generate findings
        if (analysis.network.hasPublicIp && analysis.state.running) {
            analysis.findings.push({
                severity: 'high',
                category: 'network',
                title: 'EC2 Instance Has Public IP',
                description: 'Instance has a public IP address and is running',
                remediation: 'Use private IP and route through NAT gateway if internet access needed'
            });
        }

        if (!analysis.security.hasIamRole) {
            analysis.findings.push({
                severity: 'medium',
                category: 'iam',
                title: 'EC2 Instance Without IAM Role',
                description: 'Instance does not have an IAM role attached',
                remediation: 'Attach an IAM role with minimal required permissions'
            });
        }

        if (analysis.security.metadataOptions?.HttpTokens === 'optional') {
            analysis.findings.push({
                severity: 'medium',
                category: 'metadata',
                title: 'EC2 Instance Metadata Not Protected',
                description: 'Instance metadata service does not require IMDSv2',
                remediation: 'Configure instance to require IMDSv2 tokens'
            });
        }

        return analysis;
    }

    /**
     * Enhanced IAM User Analysis
     */
    analyzeIAMUser(user) {
        const analysis = {
            access: {
                hasConsoleAccess: !!user.PasswordLastUsed,
                hasAccessKeys: (user.AccessKeys || []).length > 0,
                accessKeyCount: (user.AccessKeys || []).length,
                lastPasswordUse: user.PasswordLastUsed,
                lastAccessKeyUse: user.AccessKeyLastUsed
            },
            mfa: {
                enabled: (user.MFADevices || []).length > 0,
                deviceCount: (user.MFADevices || []).length,
                devices: user.MFADevices || []
            },
            permissions: {
                attachedPolicies: user.Policies?.filter(p => p.PolicyType === 'Managed') || [],
                inlinePolicies: user.Policies?.filter(p => p.PolicyType === 'Inline') || [],
                groups: user.Groups || [],
                hasElevatedPermissions: this.hasElevatedPermissions(user)
            },
            activity: {
                lastActivity: this.getLastActivity(user),
                isActive: this.isUserActive(user)
            },
            findings: []
        };

        // Generate findings
        if (!analysis.mfa.enabled && analysis.access.hasConsoleAccess) {
            analysis.findings.push({
                severity: 'high',
                category: 'mfa',
                title: 'IAM User Without MFA',
                description: 'User has console access but MFA is not enabled',
                remediation: 'Enable MFA for the user'
            });
        }

        if (analysis.permissions.hasElevatedPermissions) {
            analysis.findings.push({
                severity: 'critical',
                category: 'permissions',
                title: 'IAM User Has Elevated Permissions',
                description: 'User has permissions that could lead to privilege escalation',
                remediation: 'Review and reduce user permissions to minimum required'
            });
        }

        if (analysis.access.hasAccessKeys && !analysis.activity.isActive) {
            analysis.findings.push({
                severity: 'medium',
                category: 'access',
                title: 'Inactive IAM User With Access Keys',
                description: 'User has access keys but has not been active recently',
                remediation: 'Remove unused access keys or deactivate the user'
            });
        }

        return analysis;
    }

    /**
     * Enhanced IAM Role Analysis
     */
    analyzeIAMRole(role) {
        const analysis = {
            trust: {
                trustPolicy: role.AssumeRolePolicyDocument,
                trustedEntities: this.extractTrustedEntities(role.AssumeRolePolicyDocument),
                allowsCrossAccount: this.allowsCrossAccountAccess(role.AssumeRolePolicyDocument),
                allowsPublicAccess: this.allowsPublicAccess(role.AssumeRolePolicyDocument)
            },
            permissions: {
                attachedPolicies: role.Policies?.filter(p => p.PolicyType === 'Managed') || [],
                inlinePolicies: role.Policies?.filter(p => p.PolicyType === 'Inline') || [],
                hasElevatedPermissions: this.hasElevatedPermissions(role),
                permissionCount: this.countPermissions(role)
            },
            usage: {
                lastUsed: role.RoleLastUsed?.LastUsedDate,
                isUsed: !!role.RoleLastUsed?.LastUsedDate,
                daysSinceLastUse: this.getDaysSinceLastUse(role.RoleLastUsed?.LastUsedDate)
            },
            findings: []
        };

        // Generate findings
        if (analysis.trust.allowsPublicAccess) {
            analysis.findings.push({
                severity: 'critical',
                category: 'trust',
                title: 'IAM Role Allows Public Access',
                description: 'Role trust policy allows public access',
                remediation: 'Restrict trust policy to specific accounts or services'
            });
        }

        if (analysis.permissions.hasElevatedPermissions) {
            analysis.findings.push({
                severity: 'critical',
                category: 'permissions',
                title: 'IAM Role Has Elevated Permissions',
                description: 'Role has permissions that could lead to privilege escalation',
                remediation: 'Review and reduce role permissions to minimum required'
            });
        }

        if (!analysis.usage.isUsed && analysis.usage.daysSinceLastUse > 90) {
            analysis.findings.push({
                severity: 'medium',
                category: 'usage',
                title: 'Unused IAM Role',
                description: 'Role has not been used for more than 90 days',
                remediation: 'Consider removing the role if no longer needed'
            });
        }

        return analysis;
    }

    /**
     * Enhanced RDS Instance Analysis
     */
    analyzeRDSInstance(instance) {
        const analysis = {
            encryption: {
                storageEncrypted: instance.StorageEncrypted,
                encryptionType: instance.StorageEncrypted ? 'AES-256' : 'None',
                kmsKeyId: instance.KmsKeyId
            },
            network: {
                publiclyAccessible: instance.PubliclyAccessible,
                vpcId: instance.DBSubnetGroup?.VpcId,
                securityGroups: instance.VpcSecurityGroups || [],
                endpoint: instance.Endpoint
            },
            backup: {
                backupRetentionPeriod: instance.BackupRetentionPeriod,
                backupWindow: instance.PreferredBackupWindow,
                maintenanceWindow: instance.PreferredMaintenanceWindow,
                hasBackup: instance.BackupRetentionPeriod > 0
            },
            configuration: {
                engine: instance.Engine,
                engineVersion: instance.EngineVersion,
                instanceClass: instance.DBInstanceClass,
                multiAZ: instance.MultiAZ,
                deletionProtection: instance.DeletionProtection
            },
            findings: []
        };

        // Generate findings
        if (!analysis.encryption.storageEncrypted) {
            analysis.findings.push({
                severity: 'high',
                category: 'encryption',
                title: 'RDS Instance Not Encrypted',
                description: 'Database storage is not encrypted',
                remediation: 'Enable storage encryption for the RDS instance'
            });
        }

        if (analysis.network.publiclyAccessible) {
            analysis.findings.push({
                severity: 'critical',
                category: 'network',
                title: 'RDS Instance Publicly Accessible',
                description: 'Database is publicly accessible',
                remediation: 'Place database in private subnet and use VPN or bastion host'
            });
        }

        if (!analysis.backup.hasBackup) {
            analysis.findings.push({
                severity: 'medium',
                category: 'backup',
                title: 'RDS Instance Without Backup',
                description: 'Database has no backup retention configured',
                remediation: 'Configure backup retention period'
            });
        }

        if (!analysis.configuration.deletionProtection) {
            analysis.findings.push({
                severity: 'medium',
                category: 'protection',
                title: 'RDS Instance Without Deletion Protection',
                description: 'Database can be accidentally deleted',
                remediation: 'Enable deletion protection for the RDS instance'
            });
        }

        return analysis;
    }

    /**
     * Enhanced Azure VM Analysis
     */
    analyzeAzureVM(vm) {
        const analysis = {
            network: {
                publicIp: vm.publicIPAddress,
                privateIp: vm.privateIPAddress,
                hasPublicIp: !!vm.publicIPAddress,
                networkInterfaces: vm.networkProfile?.networkInterfaces || []
            },
            identity: {
                hasManagedIdentity: !!vm.identity?.type,
                identityType: vm.identity?.type || 'None',
                userAssignedIdentities: vm.identity?.userAssignedIdentities || []
            },
            security: {
                osDiskEncryption: vm.storageProfile?.osDisk?.encryptionSettings?.enabled || false,
                dataDiskEncryption: this.hasDataDiskEncryption(vm),
                securityProfile: vm.securityProfile || {}
            },
            configuration: {
                vmSize: vm.hardwareProfile?.vmSize,
                osType: vm.storageProfile?.osDisk?.osType,
                imageReference: vm.storageProfile?.imageReference
            },
            findings: []
        };

        // Generate findings
        if (analysis.network.hasPublicIp) {
            analysis.findings.push({
                severity: 'high',
                category: 'network',
                title: 'Azure VM Has Public IP',
                description: 'Virtual machine has a public IP address',
                remediation: 'Use private IP and route through load balancer if needed'
            });
        }

        if (!analysis.identity.hasManagedIdentity) {
            analysis.findings.push({
                severity: 'medium',
                category: 'identity',
                title: 'Azure VM Without Managed Identity',
                description: 'Virtual machine does not have managed identity',
                remediation: 'Enable system-assigned or user-assigned managed identity'
            });
        }

        if (!analysis.security.osDiskEncryption) {
            analysis.findings.push({
                severity: 'high',
                category: 'encryption',
                title: 'Azure VM OS Disk Not Encrypted',
                description: 'OS disk is not encrypted',
                remediation: 'Enable disk encryption for the virtual machine'
            });
        }

        return analysis;
    }

    /**
     * Enhanced Azure Storage Account Analysis
     */
    analyzeAzureStorageAccount(account) {
        const analysis = {
            access: {
                allowBlobPublicAccess: account.allowBlobPublicAccess,
                allowSharedKeyAccess: account.allowSharedKeyAccess,
                minimumTlsVersion: account.minimumTlsVersion
            },
            encryption: {
                encryptionServices: account.encryption?.services || {},
                keySource: account.encryption?.keySource || 'Microsoft.Storage'
            },
            network: {
                defaultAction: account.networkAcls?.defaultAction || 'Allow',
                ipRules: account.networkAcls?.ipRules || [],
                virtualNetworkRules: account.networkAcls?.virtualNetworkRules || []
            },
            findings: []
        };

        // Generate findings
        if (analysis.access.allowBlobPublicAccess) {
            analysis.findings.push({
                severity: 'critical',
                category: 'access',
                title: 'Azure Storage Account Allows Public Access',
                description: 'Storage account allows public blob access',
                remediation: 'Disable public blob access for the storage account'
            });
        }

        if (analysis.network.defaultAction === 'Allow') {
            analysis.findings.push({
                severity: 'high',
                category: 'network',
                title: 'Azure Storage Account Allows All Traffic',
                description: 'Storage account allows all network traffic',
                remediation: 'Configure network rules to restrict access'
            });
        }

        return analysis;
    }

    /**
     * Enhanced GCP Instance Analysis
     */
    analyzeGCPInstance(instance) {
        const analysis = {
            network: {
                networkInterfaces: instance.networkInterfaces || [],
                hasExternalIp: this.hasExternalIp(instance),
                serviceAccounts: instance.serviceAccounts || []
            },
            security: {
                shieldedInstanceConfig: instance.shieldedInstanceConfig || {},
                confidentialInstanceConfig: instance.confidentialInstanceConfig || {},
                hasShieldedInstance: instance.shieldedInstanceConfig?.enableSecureBoot || false
            },
            configuration: {
                machineType: instance.machineType,
                zone: instance.zone,
                status: instance.status
            },
            findings: []
        };

        // Generate findings
        if (analysis.network.hasExternalIp) {
            analysis.findings.push({
                severity: 'high',
                category: 'network',
                title: 'GCP Instance Has External IP',
                description: 'Compute instance has an external IP address',
                remediation: 'Use private IP and route through load balancer if needed'
            });
        }

        if (!analysis.security.hasShieldedInstance) {
            analysis.findings.push({
                severity: 'medium',
                category: 'security',
                title: 'GCP Instance Not Shielded',
                description: 'Compute instance is not using shielded instance features',
                remediation: 'Enable shielded instance features for enhanced security'
            });
        }

        return analysis;
    }

    /**
     * Enhanced GCP Bucket Analysis
     */
    analyzeGCPBucket(bucket) {
        const analysis = {
            access: {
                iamConfiguration: bucket.iamConfiguration || {},
                publicAccessPrevention: bucket.iamConfiguration?.publicAccessPrevention || 'Inherited',
                uniformBucketLevelAccess: bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled || false
            },
            encryption: {
                defaultKmsKeyName: bucket.encryption?.defaultKmsKeyName,
                hasCustomEncryption: !!bucket.encryption?.defaultKmsKeyName
            },
            lifecycle: {
                lifecycleRules: bucket.lifecycle?.rule || []
            },
            findings: []
        };

        // Generate findings
        if (analysis.access.publicAccessPrevention === 'Inherited') {
            analysis.findings.push({
                severity: 'high',
                category: 'access',
                title: 'GCP Bucket Public Access Not Blocked',
                description: 'Bucket inherits public access settings',
                remediation: 'Configure public access prevention for the bucket'
            });
        }

        if (!analysis.access.uniformBucketLevelAccess) {
            analysis.findings.push({
                severity: 'medium',
                category: 'access',
                title: 'GCP Bucket Without Uniform Access',
                description: 'Bucket does not use uniform bucket-level access',
                remediation: 'Enable uniform bucket-level access for better security'
            });
        }

        return analysis;
    }

    /**
     * Helper methods
     */
    isInPublicSubnet(instance) {
        // This would require subnet information to determine if in public subnet
        return false; // Placeholder
    }

    hasElevatedPermissions(resource) {
        const elevatedActions = [
            'iam:*',
            'iam:CreateAccessKey',
            'iam:CreateUser',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'sts:AssumeRole',
            'organizations:*'
        ];

        if (resource.Policies) {
            return resource.Policies.some(policy => {
                if (policy.PolicyDocument) {
                    try {
                        const doc = typeof policy.PolicyDocument === 'string' ? 
                            JSON.parse(policy.PolicyDocument) : policy.PolicyDocument;
                        return doc.Statement?.some(statement => 
                            elevatedActions.some(action => 
                                statement.Action === action || 
                                (Array.isArray(statement.Action) && statement.Action.includes(action))
                            )
                        );
                    } catch (e) {
                        return false;
                    }
                }
                return false;
            });
        }
        return false;
    }

    getLastActivity(user) {
        const passwordUse = user.PasswordLastUsed ? new Date(user.PasswordLastUsed) : null;
        const accessKeyUse = user.AccessKeyLastUsed ? new Date(user.AccessKeyLastUsed) : null;
        
        if (passwordUse && accessKeyUse) {
            return passwordUse > accessKeyUse ? passwordUse : accessKeyUse;
        }
        return passwordUse || accessKeyUse;
    }

    isUserActive(user) {
        const lastActivity = this.getLastActivity(user);
        if (!lastActivity) return false;
        
        const daysSinceActivity = (Date.now() - lastActivity.getTime()) / (1000 * 60 * 60 * 24);
        return daysSinceActivity <= 90;
    }

    extractTrustedEntities(trustPolicy) {
        if (!trustPolicy) return [];
        
        try {
            const policy = typeof trustPolicy === 'string' ? 
                JSON.parse(trustPolicy) : trustPolicy;
            return policy.Statement?.map(s => s.Principal) || [];
        } catch (e) {
            return [];
        }
    }

    allowsCrossAccountAccess(trustPolicy) {
        const entities = this.extractTrustedEntities(trustPolicy);
        return entities.some(entity => 
            entity.AWS && (entity.AWS.includes('*') || entity.AWS.length > 1)
        );
    }

    allowsPublicAccess(trustPolicy) {
        const entities = this.extractTrustedEntities(trustPolicy);
        return entities.some(entity => 
            entity.AWS === '*' || entity.Service === '*'
        );
    }

    countPermissions(resource) {
        let count = 0;
        if (resource.Policies) {
            resource.Policies.forEach(policy => {
                if (policy.PolicyDocument) {
                    try {
                        const doc = typeof policy.PolicyDocument === 'string' ? 
                            JSON.parse(policy.PolicyDocument) : policy.PolicyDocument;
                        count += doc.Statement?.length || 0;
                    } catch (e) {
                        // Ignore parsing errors
                    }
                }
            });
        }
        return count;
    }

    getDaysSinceLastUse(lastUsedDate) {
        if (!lastUsedDate) return Infinity;
        const lastUsed = new Date(lastUsedDate);
        return (Date.now() - lastUsed.getTime()) / (1000 * 60 * 60 * 24);
    }

    hasExternalIp(instance) {
        return instance.networkInterfaces?.some(nic => 
            nic.accessConfigs?.some(ac => ac.natIP)
        ) || false;
    }

    hasDataDiskEncryption(vm) {
        return vm.storageProfile?.dataDisks?.some(disk => 
            disk.encryptionSettings?.enabled
        ) || false;
    }

    /**
     * Calculate security score for a resource
     */
    calculateResourceSecurityScore(analysis) {
        let score = 100;
        
        analysis.findings.forEach(finding => {
            switch (finding.severity) {
                case 'critical':
                    score -= 25;
                    break;
                case 'high':
                    score -= 15;
                    break;
                case 'medium':
                    score -= 10;
                    break;
                case 'low':
                    score -= 5;
                    break;
            }
        });
        
        return Math.max(0, score);
    }

    /**
     * Determine risk level based on findings
     */
    determineRiskLevel(analysis) {
        const criticalFindings = analysis.findings.filter(f => f.severity === 'critical').length;
        const highFindings = analysis.findings.filter(f => f.severity === 'high').length;
        
        if (criticalFindings > 0) return 'critical';
        if (highFindings > 0) return 'high';
        if (analysis.findings.length > 0) return 'medium';
        return 'low';
    }

    /**
     * Calculate overall security posture
     */
    calculateSecurityPosture() {
        const resources = Object.values(this.analysisResults.resources);
        const totalResources = resources.length;
        
        if (totalResources === 0) {
            this.analysisResults.securityPosture = {
                overallScore: 100,
                riskDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
                averageScore: 100
            };
            return;
        }

        const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 };
        let totalScore = 0;

        resources.forEach(resource => {
            riskDistribution[resource.riskLevel]++;
            totalScore += resource.securityScore;
        });

        this.analysisResults.securityPosture = {
            overallScore: Math.round(totalScore / totalResources),
            riskDistribution,
            averageScore: Math.round(totalScore / totalResources)
        };
    }

    /**
     * Generate recommendations based on analysis
     */
    generateRecommendations() {
        const recommendations = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };

        Object.values(this.analysisResults.resources).forEach(resource => {
            resource.analysis.findings.forEach(finding => {
                if (recommendations[finding.severity]) {
                    recommendations[finding.severity].push({
                        resource: resource.name,
                        type: resource.type,
                        finding: finding
                    });
                }
            });
        });

        this.analysisResults.recommendations = recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = EnhancedAnalyzer;
} 