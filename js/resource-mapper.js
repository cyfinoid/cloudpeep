/**
 * PeekInTheCloud - Resource Cross-Referencing System
 * Maps relationships between resources across different cloud services
 * Inspired by ScoutSuite's resource mapping capabilities
 */

class ResourceMapper {
    constructor() {
        this.resourceMap = {};
        this.attackSurface = {};
        this.permissionPaths = {};
    }

    /**
     * Build comprehensive resource map from scan results
     */
    buildResourceMap(provider, scanResults) {
        console.log(`[ResourceMapper] Building resource map for ${provider}`);
        
        this.resourceMap = {
            provider: provider,
            resources: {},
            relationships: {},
            attackSurface: {},
            timestamp: new Date().toISOString()
        };

        switch (provider) {
            case 'aws':
                this.buildAWSResourceMap(scanResults);
                break;
            case 'azure':
                this.buildAzureResourceMap(scanResults);
                break;
            case 'gcp':
                this.buildGCPResourceMap(scanResults);
                break;
        }

        this.analyzeAttackSurface();
        this.analyzePermissionPaths();
        
        console.log(`[ResourceMapper] Resource map built with ${Object.keys(this.resourceMap.resources).length} resources`);
        return this.resourceMap;
    }

    /**
     * Build AWS resource map
     */
    buildAWSResourceMap(scanResults) {
        const resources = this.resourceMap.resources;
        const relationships = this.resourceMap.relationships;

        // Map IAM resources
        if (scanResults.iam) {
            // IAM Users
            if (scanResults.iam.users) {
                scanResults.iam.users.forEach(user => {
                    const resourceId = `iam-user-${user.UserName}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'IAM User',
                        name: user.UserName,
                        arn: user.Arn,
                        service: 'iam',
                        data: user,
                        permissions: this.extractIAMPermissions(user),
                        accessKeys: user.AccessKeys || [],
                        mfaDevices: user.MFADevices || [],
                        groups: user.Groups || [],
                        policies: user.Policies || []
                    };
                });
            }

            // IAM Roles
            if (scanResults.iam.roles) {
                scanResults.iam.roles.forEach(role => {
                    const resourceId = `iam-role-${role.RoleName}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'IAM Role',
                        name: role.RoleName,
                        arn: role.Arn,
                        service: 'iam',
                        data: role,
                        permissions: this.extractIAMPermissions(role),
                        policies: role.Policies || [],
                        trustPolicy: role.AssumeRolePolicyDocument
                    };
                });
            }

            // IAM Policies
            if (scanResults.iam.policies) {
                scanResults.iam.policies.forEach(policy => {
                    const resourceId = `iam-policy-${policy.PolicyName}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'IAM Policy',
                        name: policy.PolicyName,
                        arn: policy.Arn,
                        service: 'iam',
                        data: policy,
                        permissions: this.parsePolicyDocument(policy.PolicyDocument)
                    };
                });
            }
        }

        // Map EC2 resources
        if (scanResults.ec2) {
            // EC2 Instances
            if (scanResults.ec2.instances) {
                scanResults.ec2.instances.forEach(instance => {
                    const resourceId = `ec2-instance-${instance.InstanceId}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'EC2 Instance',
                        name: instance.InstanceId,
                        service: 'ec2',
                        data: instance,
                        publicIp: instance.PublicIpAddress,
                        privateIp: instance.PrivateIpAddress,
                        vpcId: instance.VpcId,
                        subnetId: instance.SubnetId,
                        securityGroups: instance.SecurityGroups || [],
                        iamRole: instance.IamInstanceProfile?.Arn,
                        state: instance.State?.Name
                    };
                });
            }

            // Security Groups
            if (scanResults.ec2.security_groups) {
                scanResults.ec2.security_groups.forEach(sg => {
                    const resourceId = `ec2-sg-${sg.GroupId}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'Security Group',
                        name: sg.GroupName,
                        service: 'ec2',
                        data: sg,
                        vpcId: sg.VpcId,
                        ingressRules: sg.IpPermissions || [],
                        egressRules: sg.IpPermissionsEgress || [],
                        attachedResources: []
                    };
                });
            }

            // VPCs
            if (scanResults.ec2.vpcs) {
                scanResults.ec2.vpcs.forEach(vpc => {
                    const resourceId = `ec2-vpc-${vpc.VpcId}`;
                    resources[resourceId] = {
                        id: resourceId,
                        type: 'VPC',
                        name: vpc.VpcId,
                        service: 'ec2',
                        data: vpc,
                        cidrBlock: vpc.CidrBlock,
                        subnets: [],
                        routeTables: [],
                        internetGateway: vpc.InternetGatewayId
                    };
                });
            }
        }

        // Map S3 resources
        if (scanResults.s3 && scanResults.s3.buckets) {
            scanResults.s3.buckets.forEach(bucket => {
                const resourceId = `s3-bucket-${bucket.Name}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'S3 Bucket',
                    name: bucket.Name,
                    service: 's3',
                    data: bucket,
                    region: bucket.Region,
                    publicAccess: bucket.PublicAccessBlockConfiguration,
                    encryption: bucket.ServerSideEncryptionConfiguration,
                    versioning: bucket.Versioning?.Status,
                    logging: bucket.Logging,
                    policy: bucket.Policy
                };
            });
        }

        // Map RDS resources
        if (scanResults.rds && scanResults.rds.instances) {
            scanResults.rds.instances.forEach(instance => {
                const resourceId = `rds-instance-${instance.DBInstanceIdentifier}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'RDS Instance',
                    name: instance.DBInstanceIdentifier,
                    service: 'rds',
                    data: instance,
                    engine: instance.Engine,
                    publiclyAccessible: instance.PubliclyAccessible,
                    vpcId: instance.DBSubnetGroup?.VpcId,
                    securityGroups: instance.VpcSecurityGroups || [],
                    encryption: instance.StorageEncrypted
                };
            });
        }

        // Build relationships
        this.buildAWSRelationships(resources, relationships);
    }

    /**
     * Build Azure resource map
     */
    buildAzureResourceMap(scanResults) {
        const resources = this.resourceMap.resources;
        const relationships = this.resourceMap.relationships;

        // Map Virtual Machines
        if (scanResults.compute && scanResults.compute.virtual_machines) {
            scanResults.compute.virtual_machines.forEach(vm => {
                const resourceId = `vm-${vm.id}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'Virtual Machine',
                    name: vm.name,
                    service: 'compute',
                    data: vm,
                    publicIp: vm.publicIPAddress,
                    privateIp: vm.privateIPAddress,
                    vnetId: vm.networkProfile?.networkInterfaces?.[0]?.id,
                    resourceGroup: vm.resourceGroup,
                    identity: vm.identity
                };
            });
        }

        // Map Storage Accounts
        if (scanResults.storage && scanResults.storage.storage_accounts) {
            scanResults.storage.storage_accounts.forEach(account => {
                const resourceId = `storage-${account.id}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'Storage Account',
                    name: account.name,
                    service: 'storage',
                    data: account,
                    resourceGroup: account.resourceGroup,
                    allowBlobPublicAccess: account.allowBlobPublicAccess,
                    encryption: account.encryption
                };
            });
        }

        // Build relationships
        this.buildAzureRelationships(resources, relationships);
    }

    /**
     * Build GCP resource map
     */
    buildGCPResourceMap(scanResults) {
        const resources = this.resourceMap.resources;
        const relationships = this.resourceMap.relationships;

        // Map Compute Instances
        if (scanResults.compute && scanResults.compute.instances) {
            scanResults.compute.instances.forEach(instance => {
                const resourceId = `gcp-instance-${instance.id}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'Compute Instance',
                    name: instance.name,
                    service: 'compute',
                    data: instance,
                    networkInterfaces: instance.networkInterfaces || [],
                    serviceAccounts: instance.serviceAccounts || [],
                    zone: instance.zone
                };
            });
        }

        // Map Cloud Storage Buckets
        if (scanResults.storage && scanResults.storage.buckets) {
            scanResults.storage.buckets.forEach(bucket => {
                const resourceId = `gcp-bucket-${bucket.id}`;
                resources[resourceId] = {
                    id: resourceId,
                    type: 'Cloud Storage Bucket',
                    name: bucket.name,
                    service: 'storage',
                    data: bucket,
                    iamPolicy: bucket.iamConfiguration,
                    publicAccess: bucket.iamConfiguration?.publicAccessPrevention
                };
            });
        }

        // Build relationships
        this.buildGCPRelationships(resources, relationships);
    }

    /**
     * Build AWS relationships
     */
    buildAWSRelationships(resources, relationships) {
        // Map IAM roles to EC2 instances
        Object.values(resources).forEach(resource => {
            if (resource.type === 'EC2 Instance' && resource.iamRole) {
                const roleResource = Object.values(resources).find(r => 
                    r.type === 'IAM Role' && r.arn === resource.iamRole
                );
                if (roleResource) {
                    this.addRelationship(relationships, resource.id, roleResource.id, 'uses-iam-role');
                }
            }
        });

        // Map security groups to resources
        Object.values(resources).forEach(resource => {
            if (resource.type === 'EC2 Instance' && resource.securityGroups) {
                resource.securityGroups.forEach(sg => {
                    const sgResource = Object.values(resources).find(r => 
                        r.type === 'Security Group' && r.data.GroupId === sg.GroupId
                    );
                    if (sgResource) {
                        this.addRelationship(relationships, resource.id, sgResource.id, 'uses-security-group');
                        sgResource.attachedResources.push(resource.id);
                    }
                });
            }
        });

        // Map VPCs to subnets and instances
        Object.values(resources).forEach(resource => {
            if (resource.type === 'EC2 Instance' && resource.vpcId) {
                const vpcResource = Object.values(resources).find(r => 
                    r.type === 'VPC' && r.name === resource.vpcId
                );
                if (vpcResource) {
                    this.addRelationship(relationships, resource.id, vpcResource.id, 'in-vpc');
                    vpcResource.subnets.push(resource.subnetId);
                }
            }
        });
    }

    /**
     * Build Azure relationships
     */
    buildAzureRelationships(resources, relationships) {
        // Map VMs to Virtual Networks
        Object.values(resources).forEach(resource => {
            if (resource.type === 'Virtual Machine' && resource.vnetId) {
                // Find VNet resource (would need to be added to scan results)
                const vnetResource = Object.values(resources).find(r => 
                    r.type === 'Virtual Network' && r.id === resource.vnetId
                );
                if (vnetResource) {
                    this.addRelationship(relationships, resource.id, vnetResource.id, 'in-vnet');
                }
            }
        });
    }

    /**
     * Build GCP relationships
     */
    buildGCPRelationships(resources, relationships) {
        // Map instances to service accounts
        Object.values(resources).forEach(resource => {
            if (resource.type === 'Compute Instance' && resource.serviceAccounts) {
                resource.serviceAccounts.forEach(sa => {
                    const saResource = Object.values(resources).find(r => 
                        r.type === 'Service Account' && r.data.email === sa.email
                    );
                    if (saResource) {
                        this.addRelationship(relationships, resource.id, saResource.id, 'uses-service-account');
                    }
                });
            }
        });
    }

    /**
     * Add relationship between resources
     */
    addRelationship(relationships, sourceId, targetId, relationshipType) {
        if (!relationships[sourceId]) {
            relationships[sourceId] = [];
        }
        relationships[sourceId].push({
            target: targetId,
            type: relationshipType
        });
    }

    /**
     * Extract IAM permissions from user/role
     */
    extractIAMPermissions(iamResource) {
        const permissions = {
            attachedPolicies: [],
            inlinePolicies: [],
            groups: [],
            permissions: []
        };

        if (iamResource.Policies) {
            iamResource.Policies.forEach(policy => {
                if (policy.PolicyType === 'Inline') {
                    permissions.inlinePolicies.push(policy);
                } else {
                    permissions.attachedPolicies.push(policy);
                }
            });
        }

        if (iamResource.Groups) {
            permissions.groups = iamResource.Groups;
        }

        return permissions;
    }

    /**
     * Parse IAM policy document
     */
    parsePolicyDocument(policyDocument) {
        if (!policyDocument) return [];

        const permissions = [];
        try {
            const policy = typeof policyDocument === 'string' ? 
                JSON.parse(policyDocument) : policyDocument;

            if (policy.Statement) {
                policy.Statement.forEach(statement => {
                    if (statement.Action) {
                        const actions = Array.isArray(statement.Action) ? 
                            statement.Action : [statement.Action];
                        actions.forEach(action => {
                            permissions.push({
                                action: action,
                                effect: statement.Effect || 'Allow',
                                resource: statement.Resource || '*',
                                condition: statement.Condition
                            });
                        });
                    }
                });
            }
        } catch (error) {
            console.warn('Error parsing policy document:', error);
        }

        return permissions;
    }

    /**
     * Analyze attack surface
     */
    analyzeAttackSurface() {
        const attackSurface = {
            publicResources: [],
            exposedServices: [],
            overPrivilegedResources: [],
            networkPaths: []
        };

        Object.values(this.resourceMap.resources).forEach(resource => {
            // Identify publicly accessible resources
            if (this.isPubliclyAccessible(resource)) {
                attackSurface.publicResources.push({
                    resourceId: resource.id,
                    type: resource.type,
                    name: resource.name,
                    exposure: this.getExposureLevel(resource)
                });
            }

            // Identify over-privileged resources
            if (this.isOverPrivileged(resource)) {
                attackSurface.overPrivilegedResources.push({
                    resourceId: resource.id,
                    type: resource.type,
                    name: resource.name,
                    permissions: resource.permissions
                });
            }
        });

        this.resourceMap.attackSurface = attackSurface;
    }

    /**
     * Check if resource is publicly accessible
     */
    isPubliclyAccessible(resource) {
        switch (resource.type) {
            case 'EC2 Instance':
                return resource.publicIp && resource.state === 'running';
            case 'S3 Bucket':
                return resource.data.PublicAccessBlockConfiguration?.BlockPublicAcls === false ||
                       resource.policy?.includes('"Principal": "*"');
            case 'RDS Instance':
                return resource.data.PubliclyAccessible === true;
            case 'Virtual Machine':
                return resource.publicIp !== undefined;
            case 'Cloud Storage Bucket':
                return resource.publicAccess === 'Inherited' || 
                       resource.iamPolicy?.publicAccessPrevention === 'Inherited';
            default:
                return false;
        }
    }

    /**
     * Get exposure level for resource
     */
    getExposureLevel(resource) {
        if (resource.type === 'S3 Bucket' && resource.policy?.includes('"Principal": "*"')) {
            return 'CRITICAL';
        }
        if (resource.publicIp) {
            return 'HIGH';
        }
        return 'MEDIUM';
    }

    /**
     * Check if resource is over-privileged
     */
    isOverPrivileged(resource) {
        if (resource.permissions) {
            const permissions = resource.permissions.permissions || [];
            return permissions.some(p => 
                p.action === '*' || 
                p.action.includes('*') ||
                p.resource === '*'
            );
        }
        return false;
    }

    /**
     * Analyze permission escalation paths
     */
    analyzePermissionPaths() {
        const permissionPaths = {
            escalationPaths: [],
            privilegeChains: [],
            crossServiceAccess: []
        };

        // Find potential privilege escalation paths
        Object.values(this.resourceMap.resources).forEach(resource => {
            if (resource.type === 'IAM Role' || resource.type === 'IAM User') {
                const escalationPath = this.findEscalationPath(resource);
                if (escalationPath.length > 0) {
                    permissionPaths.escalationPaths.push({
                        source: resource.id,
                        path: escalationPath,
                        severity: this.calculateEscalationSeverity(escalationPath)
                    });
                }
            }
        });

        this.resourceMap.permissionPaths = permissionPaths;
    }

    /**
     * Find privilege escalation path for resource
     */
    findEscalationPath(resource) {
        const path = [];
        const visited = new Set();

        const traverse = (currentResource, depth = 0) => {
            if (depth > 5 || visited.has(currentResource.id)) return;
            visited.add(currentResource.id);

            if (this.hasElevatedPermissions(currentResource)) {
                path.push({
                    resource: currentResource.id,
                    permissions: this.getElevatedPermissions(currentResource)
                });
                return;
            }

            // Follow relationships to find escalation paths
            const relationships = this.resourceMap.relationships[currentResource.id] || [];
            relationships.forEach(rel => {
                const targetResource = this.resourceMap.resources[rel.target];
                if (targetResource) {
                    traverse(targetResource, depth + 1);
                }
            });
        };

        traverse(resource);
        return path;
    }

    /**
     * Check if resource has elevated permissions
     */
    hasElevatedPermissions(resource) {
        if (!resource.permissions) return false;

        const elevatedActions = [
            'iam:*',
            'iam:CreateAccessKey',
            'iam:CreateUser',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'sts:AssumeRole',
            'organizations:*'
        ];

        const permissions = resource.permissions.permissions || [];
        return permissions.some(p => 
            elevatedActions.some(action => 
                p.action === action || p.action.includes(action)
            )
        );
    }

    /**
     * Get elevated permissions for resource
     */
    getElevatedPermissions(resource) {
        if (!resource.permissions) return [];

        const elevatedActions = [
            'iam:*',
            'iam:CreateAccessKey',
            'iam:CreateUser',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'sts:AssumeRole',
            'organizations:*'
        ];

        const permissions = resource.permissions.permissions || [];
        return permissions.filter(p => 
            elevatedActions.some(action => 
                p.action === action || p.action.includes(action)
            )
        );
    }

    /**
     * Calculate escalation severity
     */
    calculateEscalationSeverity(path) {
        if (path.length === 0) return 'LOW';
        
        const hasCriticalPermissions = path.some(step => 
            step.permissions.some(p => 
                p.action === 'iam:*' || p.action === 'organizations:*'
            )
        );

        if (hasCriticalPermissions) return 'CRITICAL';
        if (path.length > 3) return 'HIGH';
        return 'MEDIUM';
    }

    /**
     * Generate resource map report
     */
    generateResourceMapReport() {
        return {
            summary: {
                totalResources: Object.keys(this.resourceMap.resources).length,
                resourceTypes: this.getResourceTypeCounts(),
                relationships: Object.keys(this.resourceMap.relationships).length,
                publicResources: this.resourceMap.attackSurface.publicResources.length,
                overPrivilegedResources: this.resourceMap.attackSurface.overPrivilegedResources.length,
                escalationPaths: this.resourceMap.permissionPaths.escalationPaths.length
            },
            attackSurface: this.resourceMap.attackSurface,
            permissionPaths: this.resourceMap.permissionPaths,
            resources: this.resourceMap.resources,
            relationships: this.resourceMap.relationships
        };
    }

    /**
     * Get resource type counts
     */
    getResourceTypeCounts() {
        const counts = {};
        Object.values(this.resourceMap.resources).forEach(resource => {
            counts[resource.type] = (counts[resource.type] || 0) + 1;
        });
        return counts;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ResourceMapper;
} 