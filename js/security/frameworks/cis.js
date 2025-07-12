/**
 * CIS Compliance Framework Analyzer
 * Checks for CIS (Center for Internet Security) benchmark compliance
 */

class CISComplianceAnalyzer {
    constructor() {
        this.cisRequirements = {
            // Identity and Access Management
            iamBaseline: {
                title: 'IAM Baseline',
                description: 'Ensure IAM policies follow CIS benchmarks',
                checks: ['root_account', 'mfa_enforcement', 'password_policy', 'access_key_rotation']
            },
            iamUsers: {
                title: 'IAM Users',
                description: 'Ensure proper IAM user management',
                checks: ['user_management', 'group_management', 'policy_attachment']
            },
            iamPolicies: {
                title: 'IAM Policies',
                description: 'Ensure IAM policies follow least privilege',
                checks: ['policy_review', 'wildcard_usage', 'resource_permissions']
            },

            // Storage
            s3Baseline: {
                title: 'S3 Baseline',
                description: 'Ensure S3 buckets follow CIS benchmarks',
                checks: ['bucket_encryption', 'bucket_versioning', 'bucket_logging', 'public_access']
            },
            storageEncryption: {
                title: 'Storage Encryption',
                description: 'Ensure all storage is encrypted',
                checks: ['ebs_encryption', 'rds_encryption', 's3_encryption']
            },

            // Monitoring and Logging
            cloudTrail: {
                title: 'CloudTrail',
                description: 'Ensure comprehensive CloudTrail logging',
                checks: ['trail_enabled', 'multi_region', 'log_validation', 'log_retention']
            },
            cloudWatch: {
                title: 'CloudWatch',
                description: 'Ensure proper CloudWatch monitoring',
                checks: ['log_groups', 'metrics', 'alarms', 'dashboard']
            },
            vpcFlowLogs: {
                title: 'VPC Flow Logs',
                description: 'Ensure VPC flow logs are enabled',
                checks: ['flow_logs_enabled', 'log_destination', 'log_retention']
            },

            // Networking
            vpcBaseline: {
                title: 'VPC Baseline',
                description: 'Ensure VPC follows CIS benchmarks',
                checks: ['default_vpc', 'subnet_configuration', 'route_tables', 'nacls']
            },
            securityGroups: {
                title: 'Security Groups',
                description: 'Ensure security groups are properly configured',
                checks: ['restrictive_rules', 'specific_ports', 'source_ranges']
            },

            // Compute
            ec2Baseline: {
                title: 'EC2 Baseline',
                description: 'Ensure EC2 instances follow CIS benchmarks',
                checks: ['instance_encryption', 'security_groups', 'iam_roles', 'public_ips']
            },
            rdsBaseline: {
                title: 'RDS Baseline',
                description: 'Ensure RDS instances follow CIS benchmarks',
                checks: ['encryption_enabled', 'backup_retention', 'deletion_protection', 'public_access']
            }
        };
    }

    /**
     * Analyze CIS compliance
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Object} CIS compliance results
     */
    async analyze(scanResults, provider) {
        console.log('🛡️ Analyzing CIS compliance...');
        
        const complianceResults = {
            compliant: true,
            score: 0,
            findings: [],
            recommendations: [],
            requirements: {}
        };

        // Analyze each CIS requirement
        Object.entries(this.cisRequirements).forEach(([requirement, config]) => {
            const result = this.analyzeRequirement(scanResults, requirement, config, provider);
            complianceResults.requirements[requirement] = result;
            
            if (!result.compliant) {
                complianceResults.compliant = false;
                complianceResults.findings.push(...result.findings);
            }
        });

        // Calculate overall compliance score
        complianceResults.score = this.calculateComplianceScore(complianceResults.requirements);
        
        // Generate CIS-specific recommendations
        complianceResults.recommendations = this.generateCISRecommendations(complianceResults);
        
        console.log(`🛡️ CIS compliance analysis complete. Score: ${complianceResults.score}/100`);
        
        return complianceResults;
    }

    /**
     * Analyze specific CIS requirement
     * @param {Object} scanResults - Scan results
     * @param {string} requirement - Requirement key
     * @param {Object} config - Requirement configuration
     * @param {string} provider - Cloud provider
     * @returns {Object} Requirement analysis results
     */
    analyzeRequirement(scanResults, requirement, config, provider) {
        const result = {
            compliant: true,
            findings: [],
            score: 0,
            checks: []
        };

        // Perform checks based on requirement type
        switch (requirement) {
            case 'iamBaseline':
                result.checks = this.checkIAMBaseline(scanResults);
                break;
            case 'iamUsers':
                result.checks = this.checkIAMUsers(scanResults);
                break;
            case 'iamPolicies':
                result.checks = this.checkIAMPolicies(scanResults);
                break;
            case 's3Baseline':
                result.checks = this.checkS3Baseline(scanResults);
                break;
            case 'storageEncryption':
                result.checks = this.checkStorageEncryption(scanResults);
                break;
            case 'cloudTrail':
                result.checks = this.checkCloudTrail(scanResults);
                break;
            case 'cloudWatch':
                result.checks = this.checkCloudWatch(scanResults);
                break;
            case 'vpcFlowLogs':
                result.checks = this.checkVPCFlowLogs(scanResults);
                break;
            case 'vpcBaseline':
                result.checks = this.checkVPCBaseline(scanResults);
                break;
            case 'securityGroups':
                result.checks = this.checkSecurityGroups(scanResults);
                break;
            case 'ec2Baseline':
                result.checks = this.checkEC2Baseline(scanResults);
                break;
            case 'rdsBaseline':
                result.checks = this.checkRDSBaseline(scanResults);
                break;
        }

        // Determine compliance based on checks
        const failedChecks = result.checks.filter(check => !check.passed);
        if (failedChecks.length > 0) {
            result.compliant = false;
            result.findings = failedChecks.map(check => ({
                type: check.type,
                severity: check.severity,
                description: check.description,
                recommendation: check.recommendation
            }));
        }

        // Calculate requirement score
        const totalChecks = result.checks.length;
        const passedChecks = result.checks.filter(check => check.passed).length;
        result.score = totalChecks > 0 ? Math.round((passedChecks / totalChecks) * 100) : 100;

        return result;
    }

    /**
     * Check IAM baseline requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} IAM baseline checks
     */
    checkIAMBaseline(scanResults) {
        const checks = [];

        // Check for root account usage
        if (scanResults.iam && scanResults.iam.users) {
            const rootUser = scanResults.iam.users.find(user => user.userName === 'root');
            checks.push({
                type: 'root_account',
                passed: !rootUser,
                severity: rootUser ? 'critical' : 'info',
                description: rootUser ? 'Root account is being used' : 'Root account not in use',
                recommendation: rootUser ? 'Avoid using root account for daily operations' : null
            });
        }

        // Check for MFA (simplified)
        checks.push({
            type: 'mfa_enforcement',
            passed: false, // Placeholder - would need actual MFA data
            severity: 'critical',
            description: 'Multi-factor authentication status unknown',
            recommendation: 'Enable MFA for all IAM users'
        });

        // Check for password policy (simplified)
        checks.push({
            type: 'password_policy',
            passed: false, // Placeholder - would need actual password policy data
            severity: 'high',
            description: 'Password policy status unknown',
            recommendation: 'Implement strong password policy'
        });

        // Check for access key rotation
        if (scanResults.iam && scanResults.iam.accessKeys) {
            const oldKeys = scanResults.iam.accessKeys.filter(key => {
                const keyAge = Date.now() - new Date(key.createDate).getTime();
                return keyAge > (90 * 24 * 60 * 60 * 1000); // 90 days
            });
            
            checks.push({
                type: 'access_key_rotation',
                passed: oldKeys.length === 0,
                severity: oldKeys.length === 0 ? 'info' : 'medium',
                description: oldKeys.length === 0 ? 'Access keys are rotated regularly' : `${oldKeys.length} access keys older than 90 days`,
                recommendation: oldKeys.length === 0 ? null : 'Rotate access keys every 90 days'
            });
        }

        return checks;
    }

    /**
     * Check IAM users requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} IAM users checks
     */
    checkIAMUsers(scanResults) {
        const checks = [];

        // Check for user management
        if (scanResults.iam && scanResults.iam.users) {
            const hasUsers = scanResults.iam.users.length > 0;
            checks.push({
                type: 'user_management',
                passed: hasUsers,
                severity: hasUsers ? 'info' : 'medium',
                description: hasUsers ? 'IAM users are configured' : 'No IAM users found',
                recommendation: hasUsers ? null : 'Create IAM users for access management'
            });
        }

        // Check for group management
        if (scanResults.iam && scanResults.iam.groups) {
            const hasGroups = scanResults.iam.groups.length > 0;
            checks.push({
                type: 'group_management',
                passed: hasGroups,
                severity: hasGroups ? 'info' : 'medium',
                description: hasGroups ? 'IAM groups are configured' : 'No IAM groups found',
                recommendation: hasGroups ? null : 'Use IAM groups for permission management'
            });
        }

        return checks;
    }

    /**
     * Check IAM policies requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} IAM policies checks
     */
    checkIAMPolicies(scanResults) {
        const checks = [];

        // Check for overly permissive policies
        if (scanResults.iam && scanResults.iam.policies) {
            const overlyPermissive = scanResults.iam.policies.filter(policy => this.isOverlyPermissive(policy));
            checks.push({
                type: 'policy_review',
                passed: overlyPermissive.length === 0,
                severity: overlyPermissive.length === 0 ? 'info' : 'critical',
                description: overlyPermissive.length === 0 ? 'IAM policies follow least privilege' : `${overlyPermissive.length} overly permissive IAM policies`,
                recommendation: overlyPermissive.length === 0 ? null : 'Apply principle of least privilege to IAM policies'
            });

            // Check for wildcard usage
            const wildcardPolicies = scanResults.iam.policies.filter(policy => this.hasWildcards(policy));
            checks.push({
                type: 'wildcard_usage',
                passed: wildcardPolicies.length === 0,
                severity: wildcardPolicies.length === 0 ? 'info' : 'high',
                description: wildcardPolicies.length === 0 ? 'No wildcard policies found' : `${wildcardPolicies.length} policies with wildcard permissions`,
                recommendation: wildcardPolicies.length === 0 ? null : 'Avoid wildcard permissions in IAM policies'
            });
        }

        return checks;
    }

    /**
     * Check S3 baseline requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} S3 baseline checks
     */
    checkS3Baseline(scanResults) {
        const checks = [];

        // Check for bucket encryption
        if (scanResults.s3 && scanResults.s3.buckets) {
            const unencryptedBuckets = scanResults.s3.buckets.filter(bucket => !bucket.encryption);
            checks.push({
                type: 'bucket_encryption',
                passed: unencryptedBuckets.length === 0,
                severity: unencryptedBuckets.length === 0 ? 'info' : 'critical',
                description: unencryptedBuckets.length === 0 ? 'All S3 buckets encrypted' : `${unencryptedBuckets.length} unencrypted S3 buckets`,
                recommendation: unencryptedBuckets.length === 0 ? null : 'Enable encryption for all S3 buckets'
            });

            // Check for bucket versioning
            const bucketsWithoutVersioning = scanResults.s3.buckets.filter(bucket => !bucket.versioning);
            checks.push({
                type: 'bucket_versioning',
                passed: bucketsWithoutVersioning.length === 0,
                severity: bucketsWithoutVersioning.length === 0 ? 'info' : 'medium',
                description: bucketsWithoutVersioning.length === 0 ? 'All S3 buckets have versioning' : `${bucketsWithoutVersioning.length} S3 buckets without versioning`,
                recommendation: bucketsWithoutVersioning.length === 0 ? null : 'Enable versioning for S3 buckets'
            });

            // Check for public access
            const publicBuckets = scanResults.s3.buckets.filter(bucket => {
                if (bucket.publicAccessBlock) {
                    const block = bucket.publicAccessBlock;
                    return !block.blockPublicAcls || !block.blockPublicPolicy || 
                           !block.ignorePublicAcls || !block.restrictPublicBuckets;
                }
                return false;
            });
            
            checks.push({
                type: 'public_access',
                passed: publicBuckets.length === 0,
                severity: publicBuckets.length === 0 ? 'info' : 'critical',
                description: publicBuckets.length === 0 ? 'No public S3 buckets' : `${publicBuckets.length} S3 buckets with public access`,
                recommendation: publicBuckets.length === 0 ? null : 'Block public access for all S3 buckets'
            });
        }

        return checks;
    }

    /**
     * Check storage encryption requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Storage encryption checks
     */
    checkStorageEncryption(scanResults) {
        const checks = [];

        // Check for EBS encryption
        if (scanResults.ec2 && scanResults.ec2.instances) {
            let unencryptedVolumes = 0;
            let totalVolumes = 0;
            
            scanResults.ec2.instances.forEach(instance => {
                if (instance.blockDeviceMappings) {
                    instance.blockDeviceMappings.forEach(device => {
                        totalVolumes++;
                        if (device.ebs && !device.ebs.encrypted) {
                            unencryptedVolumes++;
                        }
                    });
                }
            });
            
            checks.push({
                type: 'ebs_encryption',
                passed: unencryptedVolumes === 0,
                severity: unencryptedVolumes === 0 ? 'info' : 'high',
                description: unencryptedVolumes === 0 ? 'All EBS volumes encrypted' : `${unencryptedVolumes}/${totalVolumes} EBS volumes not encrypted`,
                recommendation: unencryptedVolumes === 0 ? null : 'Enable encryption for all EBS volumes'
            });
        }

        // Check for RDS encryption
        if (scanResults.rds && scanResults.rds.instances) {
            const unencryptedRDS = scanResults.rds.instances.filter(instance => !instance.storageEncrypted);
            checks.push({
                type: 'rds_encryption',
                passed: unencryptedRDS.length === 0,
                severity: unencryptedRDS.length === 0 ? 'info' : 'high',
                description: unencryptedRDS.length === 0 ? 'All RDS instances encrypted' : `${unencryptedRDS.length} unencrypted RDS instances`,
                recommendation: unencryptedRDS.length === 0 ? null : 'Enable encryption for all RDS instances'
            });
        }

        // Check for S3 encryption
        if (scanResults.s3 && scanResults.s3.buckets) {
            const unencryptedS3 = scanResults.s3.buckets.filter(bucket => !bucket.encryption);
            checks.push({
                type: 's3_encryption',
                passed: unencryptedS3.length === 0,
                severity: unencryptedS3.length === 0 ? 'info' : 'high',
                description: unencryptedS3.length === 0 ? 'All S3 buckets encrypted' : `${unencryptedS3.length} unencrypted S3 buckets`,
                recommendation: unencryptedS3.length === 0 ? null : 'Enable encryption for all S3 buckets'
            });
        }

        return checks;
    }

    /**
     * Check CloudTrail requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} CloudTrail checks
     */
    checkCloudTrail(scanResults) {
        const checks = [];

        // Check for CloudTrail enabled
        if (scanResults.cloudtrail && scanResults.cloudtrail.trails) {
            const hasTrails = scanResults.cloudtrail.trails.length > 0;
            checks.push({
                type: 'trail_enabled',
                passed: hasTrails,
                severity: hasTrails ? 'info' : 'critical',
                description: hasTrails ? 'CloudTrail logging enabled' : 'No CloudTrail trails configured',
                recommendation: hasTrails ? null : 'Enable CloudTrail for API activity logging'
            });

            // Check for multi-region trails
            if (hasTrails) {
                const multiRegionTrails = scanResults.cloudtrail.trails.filter(trail => trail.isMultiRegionTrail);
                checks.push({
                    type: 'multi_region',
                    passed: multiRegionTrails.length > 0,
                    severity: multiRegionTrails.length > 0 ? 'info' : 'medium',
                    description: multiRegionTrails.length > 0 ? 'Multi-region CloudTrail configured' : 'No multi-region CloudTrail found',
                    recommendation: multiRegionTrails.length > 0 ? null : 'Use multi-region CloudTrail for comprehensive logging'
                });
            }
        }

        return checks;
    }

    /**
     * Check CloudWatch requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} CloudWatch checks
     */
    checkCloudWatch(scanResults) {
        const checks = [];

        // Check for log groups
        if (scanResults.cloudwatch && scanResults.cloudwatch.logGroups) {
            const hasLogGroups = scanResults.cloudwatch.logGroups.length > 0;
            checks.push({
                type: 'log_groups',
                passed: hasLogGroups,
                severity: hasLogGroups ? 'info' : 'medium',
                description: hasLogGroups ? 'CloudWatch log groups configured' : 'No CloudWatch log groups found',
                recommendation: hasLogGroups ? null : 'Configure CloudWatch log groups for application logging'
            });
        }

        return checks;
    }

    /**
     * Check VPC flow logs requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} VPC flow logs checks
     */
    checkVPCFlowLogs(scanResults) {
        const checks = [];

        // Check for VPC flow logs
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            const vpcsWithFlowLogs = scanResults.vpc.vpcs.filter(vpc => vpc.flowLogs && vpc.flowLogs.length > 0);
            checks.push({
                type: 'flow_logs_enabled',
                passed: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length,
                severity: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? 'info' : 'medium',
                description: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? 'All VPCs have flow logs' : `${scanResults.vpc.vpcs.length - vpcsWithFlowLogs.length} VPCs without flow logs`,
                recommendation: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? null : 'Enable VPC flow logs for network activity monitoring'
            });
        }

        return checks;
    }

    /**
     * Check VPC baseline requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} VPC baseline checks
     */
    checkVPCBaseline(scanResults) {
        const checks = [];

        // Check for default VPC usage
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            const defaultVpcs = scanResults.vpc.vpcs.filter(vpc => vpc.isDefault);
            checks.push({
                type: 'default_vpc',
                passed: defaultVpcs.length === 0,
                severity: defaultVpcs.length === 0 ? 'info' : 'medium',
                description: defaultVpcs.length === 0 ? 'No default VPCs in use' : `${defaultVpcs.length} default VPCs in use`,
                recommendation: defaultVpcs.length === 0 ? null : 'Use custom VPCs instead of default VPCs'
            });
        }

        return checks;
    }

    /**
     * Check security groups requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Security groups checks
     */
    checkSecurityGroups(scanResults) {
        const checks = [];

        // Check for overly permissive security groups
        if (scanResults.ec2 && scanResults.ec2.securityGroups) {
            const openSGs = scanResults.ec2.securityGroups.filter(sg => {
                if (sg.ipPermissions) {
                    return sg.ipPermissions.some(rule => 
                        rule.ipRanges && rule.ipRanges.some(range => range.cidrIp === '0.0.0.0/0')
                    );
                }
                return false;
            });
            
            checks.push({
                type: 'restrictive_rules',
                passed: openSGs.length === 0,
                severity: openSGs.length === 0 ? 'info' : 'high',
                description: openSGs.length === 0 ? 'Security groups are restrictive' : `${openSGs.length} security groups with open access`,
                recommendation: openSGs.length === 0 ? null : 'Restrict security group rules to specific IP ranges'
            });
        }

        return checks;
    }

    /**
     * Check EC2 baseline requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} EC2 baseline checks
     */
    checkEC2Baseline(scanResults) {
        const checks = [];

        // Check for public EC2 instances
        if (scanResults.ec2 && scanResults.ec2.instances) {
            const publicInstances = scanResults.ec2.instances.filter(instance => instance.publicIpAddress);
            checks.push({
                type: 'public_ips',
                passed: publicInstances.length === 0,
                severity: publicInstances.length === 0 ? 'info' : 'high',
                description: publicInstances.length === 0 ? 'No public EC2 instances' : `${publicInstances.length} EC2 instances with public IPs`,
                recommendation: publicInstances.length === 0 ? null : 'Use private subnets for EC2 instances'
            });
        }

        return checks;
    }

    /**
     * Check RDS baseline requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} RDS baseline checks
     */
    checkRDSBaseline(scanResults) {
        const checks = [];

        // Check for RDS encryption
        if (scanResults.rds && scanResults.rds.instances) {
            const unencryptedRDS = scanResults.rds.instances.filter(instance => !instance.storageEncrypted);
            checks.push({
                type: 'encryption_enabled',
                passed: unencryptedRDS.length === 0,
                severity: unencryptedRDS.length === 0 ? 'info' : 'high',
                description: unencryptedRDS.length === 0 ? 'All RDS instances encrypted' : `${unencryptedRDS.length} unencrypted RDS instances`,
                recommendation: unencryptedRDS.length === 0 ? null : 'Enable encryption for all RDS instances'
            });

            // Check for public RDS instances
            const publicRDS = scanResults.rds.instances.filter(instance => instance.publiclyAccessible);
            checks.push({
                type: 'public_access',
                passed: publicRDS.length === 0,
                severity: publicRDS.length === 0 ? 'info' : 'critical',
                description: publicRDS.length === 0 ? 'No public RDS instances' : `${publicRDS.length} publicly accessible RDS instances`,
                recommendation: publicRDS.length === 0 ? null : 'Place RDS instances in private subnets'
            });
        }

        return checks;
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
     * Check if policy has wildcards
     * @param {Object} policy - IAM policy
     * @returns {boolean} True if has wildcards
     */
    hasWildcards(policy) {
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
     * Calculate compliance score
     * @param {Object} requirements - Requirements analysis results
     * @returns {number} Compliance score (0-100)
     */
    calculateComplianceScore(requirements) {
        let totalScore = 0;
        let totalRequirements = 0;

        Object.values(requirements).forEach(requirement => {
            totalScore += requirement.score;
            totalRequirements++;
        });

        return totalRequirements > 0 ? Math.round(totalScore / totalRequirements) : 0;
    }

    /**
     * Generate CIS-specific recommendations
     * @param {Object} complianceResults - Compliance analysis results
     * @returns {Array} CIS recommendations
     */
    generateCISRecommendations(complianceResults) {
        const recommendations = [];

        if (!complianceResults.compliant) {
            recommendations.push({
                priority: 'high',
                title: 'CIS Benchmark Compliance Required',
                description: 'Address CIS benchmark compliance gaps',
                actions: [
                    'Implement CIS benchmark controls',
                    'Enable comprehensive logging and monitoring',
                    'Apply least privilege access controls',
                    'Enable encryption for all data',
                    'Regular security assessments'
                ]
            });
        }

        // Specific recommendations based on findings
        complianceResults.findings.forEach(finding => {
            if (finding.severity === 'critical') {
                recommendations.push({
                    priority: 'critical',
                    title: `Address ${finding.type} Issue`,
                    description: finding.description,
                    actions: [finding.recommendation]
                });
            }
        });

        return recommendations;
    }
}

// Make class globally available
window.CISChecker = CISComplianceAnalyzer; 