/**
 * Threat Detector - Identifies potential attack vectors and security threats
 * Analyzes cloud infrastructure for security vulnerabilities and attack paths
 */

class ThreatDetector {
    constructor() {
        this.threatPatterns = {
            publicExposure: {
                severity: 'critical',
                description: 'Resources exposed to public internet',
                indicators: ['publicIpAddress', 'publiclyAccessible', 'publicAccessBlock']
            },
            privilegeEscalation: {
                severity: 'critical',
                description: 'Potential privilege escalation paths',
                indicators: ['overlyPermissivePolicy', 'rootAccess', 'adminPrivileges']
            },
            dataExfiltration: {
                severity: 'high',
                description: 'Risk of data exfiltration',
                indicators: ['unencryptedData', 'publicBucket', 'weakAccessControls']
            },
            lateralMovement: {
                severity: 'high',
                description: 'Potential for lateral movement',
                indicators: ['openSecurityGroups', 'defaultVpc', 'weakNetworkControls']
            },
            persistence: {
                severity: 'medium',
                description: 'Potential persistence mechanisms',
                indicators: ['unusedAccessKeys', 'defaultCredentials', 'backdoorAccounts']
            }
        };
    }

    /**
     * Assess threats in cloud infrastructure
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Object} Threat assessment results
     */
    assessThreats(scanResults, provider) {
        console.log('🛡️ Starting threat assessment...');
        
        const assessment = {
            criticalThreats: 0,
            highThreats: 0,
            mediumThreats: 0,
            lowThreats: 0,
            attackVectors: [],
            threatPaths: [],
            recommendations: []
        };

        // Analyze attack surface
        assessment.attackVectors = this.analyzeAttackSurface(scanResults, provider);
        
        // Identify threat paths
        assessment.threatPaths = this.identifyThreatPaths(scanResults, provider);
        
        // Count threats by severity
        const allThreats = [...assessment.attackVectors, ...assessment.threatPaths];
        allThreats.forEach(threat => {
            switch (threat.severity) {
                case 'critical':
                    assessment.criticalThreats++;
                    break;
                case 'high':
                    assessment.highThreats++;
                    break;
                case 'medium':
                    assessment.mediumThreats++;
                    break;
                case 'low':
                    assessment.lowThreats++;
                    break;
            }
        });

        // Generate threat-based recommendations
        assessment.recommendations = this.generateThreatRecommendations(assessment);
        
        console.log(`🛡️ Threat assessment complete. Found ${assessment.criticalThreats} critical, ${assessment.highThreats} high threats`);
        
        return assessment;
    }

    /**
     * Analyze attack surface for vulnerabilities
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Array} Attack vectors
     */
    analyzeAttackSurface(scanResults, provider) {
        const attackVectors = [];
        
        // Public-facing resources
        const publicResources = this.identifyPublicResources(scanResults);
        if (publicResources.length > 0) {
            attackVectors.push({
                type: 'public_exposure',
                severity: 'critical',
                count: publicResources.length,
                resources: publicResources,
                description: `${publicResources.length} resources exposed to public internet`,
                risk: 'High risk of direct attack from internet'
            });
        }

        // Unencrypted data
        const unencryptedData = this.identifyUnencryptedData(scanResults);
        if (unencryptedData.length > 0) {
            attackVectors.push({
                type: 'unencrypted_data',
                severity: 'high',
                count: unencryptedData.length,
                resources: unencryptedData,
                description: `${unencryptedData.length} resources with unencrypted data`,
                risk: 'Data at rest is vulnerable to theft'
            });
        }

        // Weak access controls
        const weakAccessControls = this.identifyWeakAccessControls(scanResults);
        if (weakAccessControls.length > 0) {
            attackVectors.push({
                type: 'weak_access_controls',
                severity: 'high',
                count: weakAccessControls.length,
                resources: weakAccessControls,
                description: `${weakAccessControls.length} resources with weak access controls`,
                risk: 'Unauthorized access possible'
            });
        }

        // Missing monitoring
        const missingMonitoring = this.identifyMissingMonitoring(scanResults);
        if (missingMonitoring.length > 0) {
            attackVectors.push({
                type: 'missing_monitoring',
                severity: 'medium',
                count: missingMonitoring.length,
                resources: missingMonitoring,
                description: `${missingMonitoring.length} resources without proper monitoring`,
                risk: 'Attacks may go undetected'
            });
        }

        return attackVectors;
    }

    /**
     * Identify public-facing resources
     * @param {Object} scanResults - Scan results
     * @returns {Array} Public resources
     */
    identifyPublicResources(scanResults) {
        const publicResources = [];
        
        // EC2 instances with public IPs
        if (scanResults.ec2 && scanResults.ec2.instances) {
            scanResults.ec2.instances.forEach(instance => {
                if (instance.publicIpAddress) {
                    publicResources.push({
                        type: 'ec2_instance',
                        id: instance.instanceId,
                        publicIp: instance.publicIpAddress,
                        description: `EC2 instance ${instance.instanceId} has public IP`
                    });
                }
            });
        }

        // RDS instances with public access
        if (scanResults.rds && scanResults.rds.instances) {
            scanResults.rds.instances.forEach(instance => {
                if (instance.publiclyAccessible) {
                    publicResources.push({
                        type: 'rds_instance',
                        id: instance.dbInstanceIdentifier,
                        description: `RDS instance ${instance.dbInstanceIdentifier} is publicly accessible`
                    });
                }
            });
        }

        // S3 buckets with public access
        if (scanResults.s3 && scanResults.s3.buckets) {
            scanResults.s3.buckets.forEach(bucket => {
                if (bucket.publicAccessBlock) {
                    const block = bucket.publicAccessBlock;
                    if (!block.blockPublicAcls || !block.blockPublicPolicy || 
                        !block.ignorePublicAcls || !block.restrictPublicBuckets) {
                        publicResources.push({
                            type: 's3_bucket',
                            id: bucket.name,
                            description: `S3 bucket ${bucket.name} has public access enabled`
                        });
                    }
                }
            });
        }

        return publicResources;
    }

    /**
     * Identify unencrypted data
     * @param {Object} scanResults - Scan results
     * @returns {Array} Unencrypted resources
     */
    identifyUnencryptedData(scanResults) {
        const unencryptedResources = [];
        
        // Unencrypted EBS volumes
        if (scanResults.ec2 && scanResults.ec2.instances) {
            scanResults.ec2.instances.forEach(instance => {
                if (instance.blockDeviceMappings) {
                    instance.blockDeviceMappings.forEach(device => {
                        if (device.ebs && !device.ebs.encrypted) {
                            unencryptedResources.push({
                                type: 'ebs_volume',
                                id: device.ebs.volumeId,
                                description: `EBS volume ${device.ebs.volumeId} is not encrypted`
                            });
                        }
                    });
                }
            });
        }

        // Unencrypted RDS instances
        if (scanResults.rds && scanResults.rds.instances) {
            scanResults.rds.instances.forEach(instance => {
                if (!instance.storageEncrypted) {
                    unencryptedResources.push({
                        type: 'rds_instance',
                        id: instance.dbInstanceIdentifier,
                        description: `RDS instance ${instance.dbInstanceIdentifier} is not encrypted`
                    });
                }
            });
        }

        // Unencrypted S3 buckets
        if (scanResults.s3 && scanResults.s3.buckets) {
            scanResults.s3.buckets.forEach(bucket => {
                if (!bucket.encryption) {
                    unencryptedResources.push({
                        type: 's3_bucket',
                        id: bucket.name,
                        description: `S3 bucket ${bucket.name} is not encrypted`
                    });
                }
            });
        }

        return unencryptedResources;
    }

    /**
     * Identify weak access controls
     * @param {Object} scanResults - Scan results
     * @returns {Array} Resources with weak access controls
     */
    identifyWeakAccessControls(scanResults) {
        const weakAccessControls = [];
        
        // Overly permissive IAM policies
        if (scanResults.iam && scanResults.iam.policies) {
            scanResults.iam.policies.forEach(policy => {
                if (this.isOverlyPermissive(policy)) {
                    weakAccessControls.push({
                        type: 'iam_policy',
                        id: policy.policyName,
                        description: `IAM policy ${policy.policyName} is overly permissive`
                    });
                }
            });
        }

        // Open security groups
        if (scanResults.ec2 && scanResults.ec2.securityGroups) {
            scanResults.ec2.securityGroups.forEach(sg => {
                if (sg.ipPermissions) {
                    const openRules = sg.ipPermissions.filter(rule => 
                        rule.ipRanges && rule.ipRanges.some(range => range.cidrIp === '0.0.0.0/0')
                    );
                    if (openRules.length > 0) {
                        weakAccessControls.push({
                            type: 'security_group',
                            id: sg.groupId,
                            description: `Security group ${sg.groupName} has overly permissive rules`
                        });
                    }
                }
            });
        }

        // Root account usage
        if (scanResults.iam && scanResults.iam.users) {
            const rootUser = scanResults.iam.users.find(user => user.userName === 'root');
            if (rootUser) {
                weakAccessControls.push({
                    type: 'root_account',
                    id: rootUser.arn,
                    description: 'Root account is being used'
                });
            }
        }

        return weakAccessControls;
    }

    /**
     * Identify missing monitoring
     * @param {Object} scanResults - Scan results
     * @returns {Array} Resources without monitoring
     */
    identifyMissingMonitoring(scanResults) {
        const missingMonitoring = [];
        
        // Missing CloudTrail
        if (!scanResults.cloudtrail || !scanResults.cloudtrail.trails || scanResults.cloudtrail.trails.length === 0) {
            missingMonitoring.push({
                type: 'cloudtrail',
                description: 'No CloudTrail trails configured'
            });
        }

        // Missing VPC flow logs
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            scanResults.vpc.vpcs.forEach(vpc => {
                if (!vpc.flowLogs || vpc.flowLogs.length === 0) {
                    missingMonitoring.push({
                        type: 'vpc_flow_logs',
                        id: vpc.vpcId,
                        description: `VPC ${vpc.vpcId} has no flow logs enabled`
                    });
                }
            });
        }

        // Missing CloudWatch logs
        if (!scanResults.cloudwatch || !scanResults.cloudwatch.logGroups || scanResults.cloudwatch.logGroups.length === 0) {
            missingMonitoring.push({
                type: 'cloudwatch_logs',
                description: 'No CloudWatch log groups configured'
            });
        }

        return missingMonitoring;
    }

    /**
     * Check if IAM policy is overly permissive
     * @param {Object} policy - IAM policy
     * @returns {boolean} True if overly permissive
     */
    isOverlyPermissive(policy) {
        const wildcardPatterns = ['*', 'arn:aws:*:*:*:*'];
        
        if (policy.document) {
            const statements = policy.document.Statement || [];
            return statements.some(statement => {
                const actions = statement.Action || [];
                const resources = statement.Resource || [];
                
                return actions.some(action => 
                    wildcardPatterns.includes(action) || action.includes('*')
                ) || resources.some(resource => 
                    wildcardPatterns.includes(resource) || resource.includes('*')
                );
            });
        }
        
        return false;
    }

    /**
     * Identify potential threat paths
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Array} Threat paths
     */
    identifyThreatPaths(scanResults, provider) {
        const threatPaths = [];
        
        // Privilege escalation paths
        const escalationPaths = this.findPrivilegeEscalationPaths(scanResults);
        threatPaths.push(...escalationPaths);
        
        // Data exfiltration paths
        const exfiltrationPaths = this.findDataExfiltrationPaths(scanResults);
        threatPaths.push(...exfiltrationPaths);
        
        // Lateral movement paths
        const lateralPaths = this.findLateralMovementPaths(scanResults);
        threatPaths.push(...lateralPaths);
        
        return threatPaths;
    }

    /**
     * Find privilege escalation paths
     * @param {Object} scanResults - Scan results
     * @returns {Array} Privilege escalation paths
     */
    findPrivilegeEscalationPaths(scanResults) {
        const escalationPaths = [];
        
        // Check for overly permissive IAM policies
        if (scanResults.iam && scanResults.iam.policies) {
            scanResults.iam.policies.forEach(policy => {
                if (this.isOverlyPermissive(policy)) {
                    escalationPaths.push({
                        type: 'privilege_escalation',
                        severity: 'critical',
                        path: `Overly permissive policy ${policy.policyName}`,
                        description: 'Policy allows excessive permissions',
                        risk: 'Potential for privilege escalation'
                    });
                }
            });
        }

        // Check for root account usage
        if (scanResults.iam && scanResults.iam.users) {
            const rootUser = scanResults.iam.users.find(user => user.userName === 'root');
            if (rootUser) {
                escalationPaths.push({
                    type: 'privilege_escalation',
                    severity: 'critical',
                    path: 'Root account usage',
                    description: 'Root account provides unlimited access',
                    risk: 'Highest privilege level available'
                });
            }
        }

        return escalationPaths;
    }

    /**
     * Find data exfiltration paths
     * @param {Object} scanResults - Scan results
     * @returns {Array} Data exfiltration paths
     */
    findDataExfiltrationPaths(scanResults) {
        const exfiltrationPaths = [];
        
        // Public S3 buckets
        if (scanResults.s3 && scanResults.s3.buckets) {
            scanResults.s3.buckets.forEach(bucket => {
                if (bucket.publicAccessBlock) {
                    const block = bucket.publicAccessBlock;
                    if (!block.blockPublicAcls || !block.blockPublicPolicy || 
                        !block.ignorePublicAcls || !block.restrictPublicBuckets) {
                        exfiltrationPaths.push({
                            type: 'data_exfiltration',
                            severity: 'critical',
                            path: `Public S3 bucket ${bucket.name}`,
                            description: 'S3 bucket is publicly accessible',
                            risk: 'Data can be accessed from internet'
                        });
                    }
                }
            });
        }

        // Unencrypted data
        const unencryptedData = this.identifyUnencryptedData(scanResults);
        if (unencryptedData.length > 0) {
            exfiltrationPaths.push({
                type: 'data_exfiltration',
                severity: 'high',
                path: 'Unencrypted data at rest',
                description: `${unencryptedData.length} resources with unencrypted data`,
                risk: 'Data vulnerable to theft if accessed'
            });
        }

        return exfiltrationPaths;
    }

    /**
     * Find lateral movement paths
     * @param {Object} scanResults - Scan results
     * @returns {Array} Lateral movement paths
     */
    findLateralMovementPaths(scanResults) {
        const lateralPaths = [];
        
        // Open security groups
        if (scanResults.ec2 && scanResults.ec2.securityGroups) {
            const openSGs = scanResults.ec2.securityGroups.filter(sg => {
                if (sg.ipPermissions) {
                    return sg.ipPermissions.some(rule => 
                        rule.ipRanges && rule.ipRanges.some(range => range.cidrIp === '0.0.0.0/0')
                    );
                }
                return false;
            });
            
            if (openSGs.length > 0) {
                lateralPaths.push({
                    type: 'lateral_movement',
                    severity: 'high',
                    path: 'Open security groups',
                    description: `${openSGs.length} security groups with overly permissive rules`,
                    risk: 'Potential for lateral movement within VPC'
                });
            }
        }

        // Default VPC usage
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            const defaultVpcs = scanResults.vpc.vpcs.filter(vpc => vpc.isDefault);
            if (defaultVpcs.length > 0) {
                lateralPaths.push({
                    type: 'lateral_movement',
                    severity: 'medium',
                    path: 'Default VPC usage',
                    description: `${defaultVpcs.length} default VPCs in use`,
                    risk: 'Default VPCs may have overly permissive configurations'
                });
            }
        }

        return lateralPaths;
    }

    /**
     * Generate threat-based recommendations
     * @param {Object} assessment - Threat assessment
     * @returns {Array} Recommendations
     */
    generateThreatRecommendations(assessment) {
        const recommendations = [];
        
        // Critical threat recommendations
        if (assessment.criticalThreats > 0) {
            recommendations.push({
                priority: 'critical',
                title: 'Address Critical Threats Immediately',
                description: `${assessment.criticalThreats} critical threats detected`,
                actions: [
                    'Remove public access from all resources',
                    'Encrypt all data at rest',
                    'Review and restrict IAM permissions',
                    'Enable comprehensive logging'
                ]
            });
        }

        // High threat recommendations
        if (assessment.highThreats > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Address High-Risk Threats',
                description: `${assessment.highThreats} high-risk threats detected`,
                actions: [
                    'Implement least privilege access',
                    'Enable VPC flow logs',
                    'Configure CloudTrail logging',
                    'Review security group rules'
                ]
            });
        }

        // Attack vector recommendations
        if (assessment.attackVectors.length > 0) {
            recommendations.push({
                priority: 'high',
                title: 'Reduce Attack Surface',
                description: `${assessment.attackVectors.length} attack vectors identified`,
                actions: [
                    'Remove unnecessary public exposure',
                    'Implement network segmentation',
                    'Enable security monitoring',
                    'Regular security assessments'
                ]
            });
        }

        return recommendations;
    }
}

// Make class globally available
window.ThreatDetector = ThreatDetector; 