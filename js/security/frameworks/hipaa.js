/**
 * HIPAA Compliance Framework Analyzer
 * Checks for HIPAA (Health Insurance Portability and Accountability Act) compliance
 */

class HIPAAComplianceAnalyzer {
    constructor() {
        this.hipaaRequirements = {
            // Administrative Safeguards
            accessManagement: {
                title: 'Access Management',
                description: 'Implement policies and procedures for granting access to ePHI',
                checks: ['iam_users', 'iam_roles', 'access_keys']
            },
            workforceTraining: {
                title: 'Workforce Training',
                description: 'Implement security awareness and training program',
                checks: ['user_management', 'access_reviews']
            },
            incidentResponse: {
                title: 'Incident Response',
                description: 'Implement policies and procedures to address security incidents',
                checks: ['cloudtrail', 'cloudwatch', 'monitoring']
            },

            // Physical Safeguards
            facilityAccess: {
                title: 'Facility Access Controls',
                description: 'Implement physical safeguards for data centers',
                checks: ['vpc_security', 'network_isolation']
            },
            workstationSecurity: {
                title: 'Workstation Security',
                description: 'Implement physical safeguards for workstations',
                checks: ['ec2_security', 'instance_management']
            },

            // Technical Safeguards
            accessControl: {
                title: 'Access Control',
                description: 'Implement technical policies and procedures for electronic information systems',
                checks: ['iam_policies', 'security_groups', 'network_acls']
            },
            auditControls: {
                title: 'Audit Controls',
                description: 'Implement hardware, software, and/or procedural mechanisms to record and examine activity',
                checks: ['cloudtrail', 'cloudwatch_logs', 'vpc_flow_logs']
            },
            integrity: {
                title: 'Integrity',
                description: 'Implement policies and procedures to protect ePHI from improper alteration or destruction',
                checks: ['data_encryption', 'backup_encryption', 'versioning']
            },
            transmissionSecurity: {
                title: 'Transmission Security',
                description: 'Implement technical security measures to guard against unauthorized access to ePHI',
                checks: ['ssl_tls', 'vpn', 'private_subnets']
            }
        };
    }

    /**
     * Analyze HIPAA compliance
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Object} HIPAA compliance results
     */
    async analyze(scanResults, provider) {
        console.log('🏥 Analyzing HIPAA compliance...');
        
        const complianceResults = {
            compliant: true,
            score: 0,
            findings: [],
            recommendations: [],
            requirements: {}
        };

        // Analyze each HIPAA requirement
        Object.entries(this.hipaaRequirements).forEach(([requirement, config]) => {
            const result = this.analyzeRequirement(scanResults, requirement, config, provider);
            complianceResults.requirements[requirement] = result;
            
            if (!result.compliant) {
                complianceResults.compliant = false;
                complianceResults.findings.push(...result.findings);
            }
        });

        // Calculate overall compliance score
        complianceResults.score = this.calculateComplianceScore(complianceResults.requirements);
        
        // Generate HIPAA-specific recommendations
        complianceResults.recommendations = this.generateHIPAARecommendations(complianceResults);
        
        console.log(`🏥 HIPAA compliance analysis complete. Score: ${complianceResults.score}/100`);
        
        return complianceResults;
    }

    /**
     * Analyze specific HIPAA requirement
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
            case 'accessManagement':
                result.checks = this.checkAccessManagement(scanResults);
                break;
            case 'workforceTraining':
                result.checks = this.checkWorkforceTraining(scanResults);
                break;
            case 'incidentResponse':
                result.checks = this.checkIncidentResponse(scanResults);
                break;
            case 'facilityAccess':
                result.checks = this.checkFacilityAccess(scanResults);
                break;
            case 'workstationSecurity':
                result.checks = this.checkWorkstationSecurity(scanResults);
                break;
            case 'accessControl':
                result.checks = this.checkAccessControl(scanResults);
                break;
            case 'auditControls':
                result.checks = this.checkAuditControls(scanResults);
                break;
            case 'integrity':
                result.checks = this.checkIntegrity(scanResults);
                break;
            case 'transmissionSecurity':
                result.checks = this.checkTransmissionSecurity(scanResults);
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
     * Check access management requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Access management checks
     */
    checkAccessManagement(scanResults) {
        const checks = [];

        // Check for IAM users
        if (scanResults.iam && scanResults.iam.users) {
            const hasUsers = scanResults.iam.users.length > 0;
            checks.push({
                type: 'iam_users',
                passed: hasUsers,
                severity: hasUsers ? 'info' : 'high',
                description: hasUsers ? 'IAM users are configured' : 'No IAM users found',
                recommendation: hasUsers ? null : 'Create IAM users for workforce access'
            });
        }

        // Check for IAM roles
        if (scanResults.iam && scanResults.iam.roles) {
            const hasRoles = scanResults.iam.roles.length > 0;
            checks.push({
                type: 'iam_roles',
                passed: hasRoles,
                severity: hasRoles ? 'info' : 'medium',
                description: hasRoles ? 'IAM roles are configured' : 'No IAM roles found',
                recommendation: hasRoles ? null : 'Create IAM roles for service access'
            });
        }

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
     * Check workforce training requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Workforce training checks
     */
    checkWorkforceTraining(scanResults) {
        const checks = [];

        // Check for user management
        if (scanResults.iam && scanResults.iam.users) {
            const hasMultipleUsers = scanResults.iam.users.length > 1;
            checks.push({
                type: 'user_management',
                passed: hasMultipleUsers,
                severity: hasMultipleUsers ? 'info' : 'medium',
                description: hasMultipleUsers ? 'Multiple users configured' : 'Single user configuration detected',
                recommendation: hasMultipleUsers ? null : 'Create individual user accounts for workforce members'
            });
        }

        // Check for MFA (simplified - would need actual MFA data)
        checks.push({
            type: 'mfa_enforcement',
            passed: false, // Placeholder - would need actual MFA data
            severity: 'high',
            description: 'Multi-factor authentication status unknown',
            recommendation: 'Enable MFA for all IAM users'
        });

        return checks;
    }

    /**
     * Check incident response requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Incident response checks
     */
    checkIncidentResponse(scanResults) {
        const checks = [];

        // Check for CloudTrail logging
        if (scanResults.cloudtrail && scanResults.cloudtrail.trails) {
            const hasTrails = scanResults.cloudtrail.trails.length > 0;
            checks.push({
                type: 'cloudtrail_logging',
                passed: hasTrails,
                severity: hasTrails ? 'info' : 'critical',
                description: hasTrails ? 'CloudTrail logging enabled' : 'No CloudTrail trails configured',
                recommendation: hasTrails ? null : 'Enable CloudTrail for API activity logging'
            });
        }

        // Check for CloudWatch monitoring
        if (scanResults.cloudwatch && scanResults.cloudwatch.logGroups) {
            const hasLogGroups = scanResults.cloudwatch.logGroups.length > 0;
            checks.push({
                type: 'cloudwatch_monitoring',
                passed: hasLogGroups,
                severity: hasLogGroups ? 'info' : 'medium',
                description: hasLogGroups ? 'CloudWatch logging enabled' : 'No CloudWatch log groups configured',
                recommendation: hasLogGroups ? null : 'Configure CloudWatch logs for service monitoring'
            });
        }

        return checks;
    }

    /**
     * Check facility access controls
     * @param {Object} scanResults - Scan results
     * @returns {Array} Facility access checks
     */
    checkFacilityAccess(scanResults) {
        const checks = [];

        // Check for VPC security
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            const hasCustomVpcs = scanResults.vpc.vpcs.some(vpc => !vpc.isDefault);
            checks.push({
                type: 'vpc_security',
                passed: hasCustomVpcs,
                severity: hasCustomVpcs ? 'info' : 'medium',
                description: hasCustomVpcs ? 'Custom VPCs configured' : 'Using default VPCs',
                recommendation: hasCustomVpcs ? null : 'Use custom VPCs for better network isolation'
            });
        }

        // Check for network isolation
        if (scanResults.vpc && scanResults.vpc.subnets) {
            const hasPrivateSubnets = scanResults.vpc.subnets.some(subnet => !subnet.mapPublicIpOnLaunch);
            checks.push({
                type: 'network_isolation',
                passed: hasPrivateSubnets,
                severity: hasPrivateSubnets ? 'info' : 'medium',
                description: hasPrivateSubnets ? 'Private subnets configured' : 'No private subnets found',
                recommendation: hasPrivateSubnets ? null : 'Use private subnets for sensitive data'
            });
        }

        return checks;
    }

    /**
     * Check workstation security
     * @param {Object} scanResults - Scan results
     * @returns {Array} Workstation security checks
     */
    checkWorkstationSecurity(scanResults) {
        const checks = [];

        // Check for EC2 security
        if (scanResults.ec2 && scanResults.ec2.instances) {
            const publicInstances = scanResults.ec2.instances.filter(instance => instance.publicIpAddress);
            checks.push({
                type: 'ec2_security',
                passed: publicInstances.length === 0,
                severity: publicInstances.length === 0 ? 'info' : 'high',
                description: publicInstances.length === 0 ? 'No public EC2 instances' : `${publicInstances.length} public EC2 instances`,
                recommendation: publicInstances.length === 0 ? null : 'Use private subnets for EC2 instances'
            });
        }

        return checks;
    }

    /**
     * Check access control requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Access control checks
     */
    checkAccessControl(scanResults) {
        const checks = [];

        // Check for overly permissive IAM policies
        if (scanResults.iam && scanResults.iam.policies) {
            const overlyPermissive = scanResults.iam.policies.filter(policy => this.isOverlyPermissive(policy));
            checks.push({
                type: 'iam_policies',
                passed: overlyPermissive.length === 0,
                severity: overlyPermissive.length === 0 ? 'info' : 'high',
                description: overlyPermissive.length === 0 ? 'IAM policies follow least privilege' : `${overlyPermissive.length} overly permissive IAM policies`,
                recommendation: overlyPermissive.length === 0 ? null : 'Apply principle of least privilege to IAM policies'
            });
        }

        // Check for security group restrictions
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
                type: 'security_groups',
                passed: openSGs.length === 0,
                severity: openSGs.length === 0 ? 'info' : 'high',
                description: openSGs.length === 0 ? 'Security groups are restrictive' : `${openSGs.length} security groups with open access`,
                recommendation: openSGs.length === 0 ? null : 'Restrict security group rules to specific IP ranges'
            });
        }

        return checks;
    }

    /**
     * Check audit controls
     * @param {Object} scanResults - Scan results
     * @returns {Array} Audit control checks
     */
    checkAuditControls(scanResults) {
        const checks = [];

        // Check for CloudTrail
        if (scanResults.cloudtrail && scanResults.cloudtrail.trails) {
            const hasTrails = scanResults.cloudtrail.trails.length > 0;
            checks.push({
                type: 'cloudtrail_audit',
                passed: hasTrails,
                severity: hasTrails ? 'info' : 'critical',
                description: hasTrails ? 'CloudTrail audit logging enabled' : 'No CloudTrail trails configured',
                recommendation: hasTrails ? null : 'Enable CloudTrail for comprehensive audit logging'
            });
        }

        // Check for VPC flow logs
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            const vpcsWithFlowLogs = scanResults.vpc.vpcs.filter(vpc => vpc.flowLogs && vpc.flowLogs.length > 0);
            checks.push({
                type: 'vpc_flow_logs',
                passed: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length,
                severity: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? 'info' : 'medium',
                description: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? 'All VPCs have flow logs' : `${scanResults.vpc.vpcs.length - vpcsWithFlowLogs.length} VPCs without flow logs`,
                recommendation: vpcsWithFlowLogs.length === scanResults.vpc.vpcs.length ? null : 'Enable VPC flow logs for network activity monitoring'
            });
        }

        return checks;
    }

    /**
     * Check data integrity requirements
     * @param {Object} scanResults - Scan results
     * @returns {Array} Integrity checks
     */
    checkIntegrity(scanResults) {
        const checks = [];

        // Check for data encryption
        if (scanResults.s3 && scanResults.s3.buckets) {
            const unencryptedBuckets = scanResults.s3.buckets.filter(bucket => !bucket.encryption);
            checks.push({
                type: 'data_encryption',
                passed: unencryptedBuckets.length === 0,
                severity: unencryptedBuckets.length === 0 ? 'info' : 'high',
                description: unencryptedBuckets.length === 0 ? 'All S3 buckets encrypted' : `${unencryptedBuckets.length} unencrypted S3 buckets`,
                recommendation: unencryptedBuckets.length === 0 ? null : 'Enable encryption for all S3 buckets'
            });
        }

        // Check for backup encryption
        if (scanResults.rds && scanResults.rds.instances) {
            const unencryptedRDS = scanResults.rds.instances.filter(instance => !instance.storageEncrypted);
            checks.push({
                type: 'backup_encryption',
                passed: unencryptedRDS.length === 0,
                severity: unencryptedRDS.length === 0 ? 'info' : 'high',
                description: unencryptedRDS.length === 0 ? 'All RDS instances encrypted' : `${unencryptedRDS.length} unencrypted RDS instances`,
                recommendation: unencryptedRDS.length === 0 ? null : 'Enable encryption for all RDS instances'
            });
        }

        // Check for versioning
        if (scanResults.s3 && scanResults.s3.buckets) {
            const bucketsWithoutVersioning = scanResults.s3.buckets.filter(bucket => !bucket.versioning);
            checks.push({
                type: 'versioning',
                passed: bucketsWithoutVersioning.length === 0,
                severity: bucketsWithoutVersioning.length === 0 ? 'info' : 'medium',
                description: bucketsWithoutVersioning.length === 0 ? 'All S3 buckets have versioning' : `${bucketsWithoutVersioning.length} S3 buckets without versioning`,
                recommendation: bucketsWithoutVersioning.length === 0 ? null : 'Enable versioning for S3 buckets'
            });
        }

        return checks;
    }

    /**
     * Check transmission security
     * @param {Object} scanResults - Scan results
     * @returns {Array} Transmission security checks
     */
    checkTransmissionSecurity(scanResults) {
        const checks = [];

        // Check for SSL/TLS (simplified)
        checks.push({
            type: 'ssl_tls',
            passed: false, // Placeholder - would need actual SSL/TLS data
            severity: 'high',
            description: 'SSL/TLS configuration status unknown',
            recommendation: 'Use HTTPS for all data transmission'
        });

        // Check for VPN (simplified)
        checks.push({
            type: 'vpn',
            passed: false, // Placeholder - would need actual VPN data
            severity: 'medium',
            description: 'VPN configuration status unknown',
            recommendation: 'Use VPN for secure remote access'
        });

        // Check for private subnets
        if (scanResults.vpc && scanResults.vpc.subnets) {
            const hasPrivateSubnets = scanResults.vpc.subnets.some(subnet => !subnet.mapPublicIpOnLaunch);
            checks.push({
                type: 'private_subnets',
                passed: hasPrivateSubnets,
                severity: hasPrivateSubnets ? 'info' : 'medium',
                description: hasPrivateSubnets ? 'Private subnets configured' : 'No private subnets found',
                recommendation: hasPrivateSubnets ? null : 'Use private subnets for secure data transmission'
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
     * Generate HIPAA-specific recommendations
     * @param {Object} complianceResults - Compliance analysis results
     * @returns {Array} HIPAA recommendations
     */
    generateHIPAARecommendations(complianceResults) {
        const recommendations = [];

        if (!complianceResults.compliant) {
            recommendations.push({
                priority: 'critical',
                title: 'HIPAA Compliance Required',
                description: 'Address HIPAA compliance gaps to protect ePHI',
                actions: [
                    'Implement comprehensive access controls',
                    'Enable encryption for all data at rest and in transit',
                    'Configure comprehensive audit logging',
                    'Establish incident response procedures',
                    'Conduct regular security assessments'
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

module.exports = HIPAAComplianceAnalyzer; 