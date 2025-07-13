/**
 * PeekInTheCloud - Security Rules Engine
 * Comprehensive security assessment system inspired by ScoutSuite
 * All processing happens client-side for privacy
 */

class SecurityRuleEngine {
    constructor() {
        this.rules = this.loadSecurityRules();
        this.findings = [];
        this.securityScore = 100;
    }

    /**
     * Load security rules for all cloud providers
     */
    loadSecurityRules() {
        return {
            aws: this.loadAWSSecurityRules(),
            azure: this.loadAzureSecurityRules(),
            gcp: this.loadGCPSecurityRules()
        };
    }

    /**
     * Load AWS security rules
     */
    loadAWSSecurityRules() {
        return {
            // IAM Security Rules
            'iam-user-without-mfa': {
                id: 'iam-user-without-mfa',
                title: 'IAM User Without MFA',
                description: 'IAM users should have Multi-Factor Authentication enabled',
                rationale: 'MFA adds an extra layer of protection on top of username and password',
                remediation: 'Enable MFA for all IAM users in the AWS account',
                severity: 'high',
                category: 'IAM',
                compliance: ['CIS-AWS-1.2'],
                conditions: [
                    { field: 'LoginProfile', operator: 'exists' },
                    { field: 'MFADevices', operator: 'empty' }
                ],
                path: 'iam.users.id'
            },

            'iam-root-account-used': {
                id: 'iam-root-account-used',
                title: 'Root Account Recently Used',
                description: 'The root account should not be used for day-to-day operations',
                rationale: 'Using the root account for daily operations violates the principle of least privilege',
                remediation: 'Use IAM users with appropriate permissions instead of the root account',
                severity: 'critical',
                category: 'IAM',
                compliance: ['CIS-AWS-1.1'],
                conditions: [
                    { field: 'PasswordLastUsed', operator: 'notEmpty' },
                    { field: 'AccessKeyLastUsed', operator: 'notEmpty' }
                ],
                path: 'iam.root'
            },

            'iam-password-policy-weak': {
                id: 'iam-password-policy-weak',
                title: 'Weak Password Policy',
                description: 'IAM password policy does not meet security requirements',
                rationale: 'Weak password policies increase the risk of unauthorized access',
                remediation: 'Configure a strong password policy with minimum length, complexity, and rotation',
                severity: 'medium',
                category: 'IAM',
                compliance: ['CIS-AWS-1.3'],
                conditions: [
                    { field: 'MinimumPasswordLength', operator: 'lessThan', value: 14 },
                    { field: 'RequireUppercaseCharacters', operator: 'equals', value: false },
                    { field: 'RequireLowercaseCharacters', operator: 'equals', value: false },
                    { field: 'RequireNumbers', operator: 'equals', value: false },
                    { field: 'RequireSymbols', operator: 'equals', value: false }
                ],
                path: 'iam.password_policy'
            },

            // S3 Security Rules
            's3-bucket-public-access': {
                id: 's3-bucket-public-access',
                title: 'S3 Bucket Publicly Accessible',
                description: 'S3 bucket allows public access',
                rationale: 'Public access to S3 buckets can lead to data exposure',
                remediation: 'Configure bucket policies to deny public access and enable block public access settings',
                severity: 'high',
                category: 'Storage',
                compliance: ['CIS-AWS-2.3'],
                conditions: [
                    { field: 'grantees', operator: 'contains', value: 'AllUsers' },
                    { field: 'policy.Statement', operator: 'contains', value: '"Principal": "*"' }
                ],
                path: 's3.buckets.id'
            },

            's3-bucket-no-encryption': {
                id: 's3-bucket-no-encryption',
                title: 'S3 Bucket Without Default Encryption',
                description: 'S3 bucket does not have default encryption enabled',
                rationale: 'Data at rest should be encrypted to protect sensitive information',
                remediation: 'Enable default encryption for the S3 bucket',
                severity: 'medium',
                category: 'Storage',
                compliance: ['CIS-AWS-2.4'],
                conditions: [
                    { field: 'default_encryption_enabled', operator: 'equals', value: false }
                ],
                path: 's3.buckets.id'
            },

            's3-bucket-no-logging': {
                id: 's3-bucket-no-logging',
                title: 'S3 Bucket Without Access Logging',
                description: 'S3 bucket does not have access logging enabled',
                rationale: 'Access logging helps monitor and audit bucket access',
                remediation: 'Enable access logging for the S3 bucket',
                severity: 'medium',
                category: 'Storage',
                compliance: ['CIS-AWS-2.5'],
                conditions: [
                    { field: 'logging', operator: 'equals', value: 'Disabled' }
                ],
                path: 's3.buckets.id'
            },

            // EC2 Security Rules
            'ec2-instance-public-ip': {
                id: 'ec2-instance-public-ip',
                title: 'EC2 Instance with Public IP',
                description: 'EC2 instance has a public IP address',
                rationale: 'Public IP addresses increase the attack surface',
                remediation: 'Use private IP addresses and route through NAT gateway if internet access is needed',
                severity: 'medium',
                category: 'Compute',
                compliance: ['CIS-AWS-4.1'],
                conditions: [
                    { field: 'public_ip_address', operator: 'notEmpty' },
                    { field: 'state', operator: 'equals', value: 'running' }
                ],
                path: 'ec2.instances.id'
            },

            'ec2-security-group-overly-permissive': {
                id: 'ec2-security-group-overly-permissive',
                title: 'Overly Permissive Security Group',
                description: 'Security group allows overly permissive access',
                rationale: 'Overly permissive security groups increase the risk of unauthorized access',
                remediation: 'Restrict security group rules to specific IP ranges and ports',
                severity: 'high',
                category: 'Networking',
                compliance: ['CIS-AWS-4.2'],
                conditions: [
                    { field: 'rules.ingress', operator: 'contains', value: '0.0.0.0/0' },
                    { field: 'rules.ingress', operator: 'contains', value: '0.0.0.0/0:0-65535' }
                ],
                path: 'ec2.security_groups.id'
            },

            // RDS Security Rules
            'rds-instance-publicly-accessible': {
                id: 'rds-instance-publicly-accessible',
                title: 'RDS Instance Publicly Accessible',
                description: 'RDS instance is publicly accessible',
                rationale: 'Publicly accessible databases are at risk of unauthorized access',
                remediation: 'Configure RDS instance to be in a private subnet',
                severity: 'high',
                category: 'Database',
                compliance: ['CIS-AWS-6.1'],
                conditions: [
                    { field: 'publicly_accessible', operator: 'equals', value: true }
                ],
                path: 'rds.instances.id'
            },

            'rds-instance-no-encryption': {
                id: 'rds-instance-no-encryption',
                title: 'RDS Instance Without Encryption',
                description: 'RDS instance does not have encryption enabled',
                rationale: 'Database encryption protects sensitive data at rest',
                remediation: 'Enable encryption for the RDS instance',
                severity: 'medium',
                category: 'Database',
                compliance: ['CIS-AWS-6.2'],
                conditions: [
                    { field: 'storage_encrypted', operator: 'equals', value: false }
                ],
                path: 'rds.instances.id'
            },

            // CloudTrail Security Rules
            'cloudtrail-not-enabled': {
                id: 'cloudtrail-not-enabled',
                title: 'CloudTrail Not Enabled',
                description: 'CloudTrail is not enabled for the AWS account',
                rationale: 'CloudTrail provides visibility into API calls and helps with compliance',
                remediation: 'Enable CloudTrail for the AWS account',
                severity: 'medium',
                category: 'Monitoring',
                compliance: ['CIS-AWS-2.1'],
                conditions: [
                    { field: 'trails', operator: 'empty' }
                ],
                path: 'cloudtrail'
            },

            'cloudtrail-not-multi-region': {
                id: 'cloudtrail-not-multi-region',
                title: 'CloudTrail Not Multi-Region',
                description: 'CloudTrail is not configured for multi-region',
                rationale: 'Multi-region CloudTrail ensures comprehensive logging across all regions',
                remediation: 'Configure CloudTrail for multi-region logging',
                severity: 'medium',
                category: 'Monitoring',
                compliance: ['CIS-AWS-2.2'],
                conditions: [
                    { field: 'is_multi_region_trail', operator: 'equals', value: false }
                ],
                path: 'cloudtrail.trails.id'
            }
        };
    }

    /**
     * Load Azure security rules
     */
    loadAzureSecurityRules() {
        return {
            // Azure AD Security Rules
            'azure-ad-mfa-not-enabled': {
                id: 'azure-ad-mfa-not-enabled',
                title: 'Azure AD MFA Not Enabled',
                description: 'Multi-Factor Authentication is not enabled for users',
                rationale: 'MFA provides additional security for user accounts',
                remediation: 'Enable MFA for all users in Azure AD',
                severity: 'high',
                category: 'Identity',
                compliance: ['CIS-Azure-1.1'],
                conditions: [
                    { field: 'mfa_enabled', operator: 'equals', value: false }
                ],
                path: 'azuread.users.id'
            },

            // Virtual Machine Security Rules
            'vm-public-ip': {
                id: 'vm-public-ip',
                title: 'Virtual Machine with Public IP',
                description: 'Virtual machine has a public IP address',
                rationale: 'Public IP addresses increase the attack surface',
                remediation: 'Use private IP addresses and route through load balancer if needed',
                severity: 'medium',
                category: 'Compute',
                compliance: ['CIS-Azure-6.1'],
                conditions: [
                    { field: 'public_ip_address', operator: 'notEmpty' },
                    { field: 'power_state', operator: 'equals', value: 'running' }
                ],
                path: 'compute.virtual_machines.id'
            },

            // Storage Account Security Rules
            'storage-account-public-access': {
                id: 'storage-account-public-access',
                title: 'Storage Account Publicly Accessible',
                description: 'Storage account allows public access',
                rationale: 'Public access to storage accounts can lead to data exposure',
                remediation: 'Configure storage account to deny public access',
                severity: 'high',
                category: 'Storage',
                compliance: ['CIS-Azure-3.1'],
                conditions: [
                    { field: 'allow_blob_public_access', operator: 'equals', value: true }
                ],
                path: 'storage.storage_accounts.id'
            }
        };
    }

    /**
     * Load GCP security rules
     */
    loadGCPSecurityRules() {
        return {
            // IAM Security Rules
            'gcp-service-account-with-user-managed-keys': {
                id: 'gcp-service-account-with-user-managed-keys',
                title: 'Service Account with User-Managed Keys',
                description: 'Service account has user-managed keys',
                rationale: 'User-managed keys are less secure than Google-managed keys',
                remediation: 'Use Google-managed keys instead of user-managed keys',
                severity: 'medium',
                category: 'IAM',
                compliance: ['CIS-GCP-1.1'],
                conditions: [
                    { field: 'keys', operator: 'notEmpty' },
                    { field: 'key_type', operator: 'equals', value: 'USER_MANAGED' }
                ],
                path: 'iam.service_accounts.id'
            },

            // Compute Engine Security Rules
            'gcp-instance-public-ip': {
                id: 'gcp-instance-public-ip',
                title: 'Compute Instance with Public IP',
                description: 'Compute instance has a public IP address',
                rationale: 'Public IP addresses increase the attack surface',
                remediation: 'Use private IP addresses and route through load balancer if needed',
                severity: 'medium',
                category: 'Compute',
                compliance: ['CIS-GCP-4.1'],
                conditions: [
                    { field: 'access_configs', operator: 'notEmpty' },
                    { field: 'status', operator: 'equals', value: 'RUNNING' }
                ],
                path: 'compute.instances.id'
            },

            // Cloud Storage Security Rules
            'gcp-bucket-public-access': {
                id: 'gcp-bucket-public-access',
                title: 'Cloud Storage Bucket Publicly Accessible',
                description: 'Cloud Storage bucket allows public access',
                rationale: 'Public access to storage buckets can lead to data exposure',
                remediation: 'Configure bucket IAM to deny public access',
                severity: 'high',
                category: 'Storage',
                compliance: ['CIS-GCP-3.1'],
                conditions: [
                    { field: 'iam_policy', operator: 'contains', value: 'allUsers' },
                    { field: 'iam_policy', operator: 'contains', value: 'allAuthenticatedUsers' }
                ],
                path: 'storage.buckets.id'
            }
        };
    }

    /**
     * Evaluate security rules against scan results
     */
    evaluateRules(provider, scanResults) {
        this.findings = [];
        this.securityScore = 100;

        const rules = this.rules[provider];
        if (!rules) {
            console.warn(`No security rules found for provider: ${provider}`);
            return { findings: [], securityScore: 100 };
        }

        console.log(`Evaluating ${Object.keys(rules).length} security rules for ${provider}`);

        // Evaluate each rule
        Object.values(rules).forEach(rule => {
            const ruleFindings = this.evaluateRule(rule, scanResults);
            this.findings.push(...ruleFindings);
        });

        // Calculate security score
        this.calculateSecurityScore();

        return {
            findings: this.findings,
            securityScore: this.securityScore,
            totalRules: Object.keys(rules).length,
            findingsBySeverity: this.groupFindingsBySeverity()
        };
    }

    /**
     * Evaluate a single security rule
     */
    evaluateRule(rule, scanResults) {
        const findings = [];
        
        try {
            // Find resources that match the rule path
            const resources = this.findResourcesByPath(rule.path, scanResults);
            
            resources.forEach(resource => {
                if (this.matchesRuleConditions(rule.conditions, resource)) {
                    findings.push({
                        ruleId: rule.id,
                        title: rule.title,
                        description: rule.description,
                        rationale: rule.rationale,
                        remediation: rule.remediation,
                        severity: rule.severity,
                        category: rule.category,
                        compliance: rule.compliance,
                        resourceId: resource.id || resource.name,
                        resourceType: this.getResourceTypeFromPath(rule.path),
                        timestamp: new Date().toISOString()
                    });
                }
            });
        } catch (error) {
            console.error(`Error evaluating rule ${rule.id}:`, error);
        }

        return findings;
    }

    /**
     * Check if a resource matches rule conditions
     */
    matchesRuleConditions(conditions, resource) {
        if (!conditions || conditions.length === 0) {
            return false;
        }

        // Handle complex conditions with logical operators
        if (Array.isArray(conditions) && conditions.length > 0) {
            const operator = conditions[0];
            
            if (operator === 'and') {
                return conditions.slice(1).every(condition => 
                    this.evaluateCondition(condition, resource)
                );
            } else if (operator === 'or') {
                return conditions.slice(1).some(condition => 
                    this.evaluateCondition(condition, resource)
                );
            } else {
                // Single condition
                return this.evaluateCondition(conditions, resource);
            }
        }

        return false;
    }

    /**
     * Evaluate a single condition
     */
    evaluateCondition(condition, resource) {
        if (!Array.isArray(condition) || condition.length < 2) {
            return false;
        }

        const [field, operator, value] = condition;
        const fieldValue = this.getFieldValue(resource, field);

        switch (operator) {
            case 'equals':
                return fieldValue === value;
            case 'notEquals':
                return fieldValue !== value;
            case 'empty':
                return !fieldValue || (Array.isArray(fieldValue) && fieldValue.length === 0);
            case 'notEmpty':
                return fieldValue && (Array.isArray(fieldValue) ? fieldValue.length > 0 : true);
            case 'exists':
                return fieldValue !== undefined && fieldValue !== null;
            case 'notExists':
                return fieldValue === undefined || fieldValue === null;
            case 'contains':
                if (Array.isArray(fieldValue)) {
                    return fieldValue.includes(value);
                } else if (typeof fieldValue === 'string') {
                    return fieldValue.includes(value);
                } else if (typeof fieldValue === 'object') {
                    return JSON.stringify(fieldValue).includes(value);
                }
                return false;
            case 'lessThan':
                return typeof fieldValue === 'number' && fieldValue < value;
            case 'greaterThan':
                return typeof fieldValue === 'number' && fieldValue > value;
            default:
                console.warn(`Unknown condition operator: ${operator}`);
                return false;
        }
    }

    /**
     * Get field value from resource using dot notation
     */
    getFieldValue(resource, fieldPath) {
        if (!fieldPath) return undefined;
        
        const fields = fieldPath.split('.');
        let value = resource;
        
        for (const field of fields) {
            if (value && typeof value === 'object' && field in value) {
                value = value[field];
            } else {
                return undefined;
            }
        }
        
        return value;
    }

    /**
     * Find resources by path pattern
     */
    findResourcesByPath(path, scanResults) {
        const resources = [];
        
        // Parse path like 's3.buckets.id' or 'iam.users.id'
        const pathParts = path.split('.');
        
        if (pathParts.length < 2) {
            return resources;
        }

        const service = pathParts[0];
        const resourceType = pathParts[1];
        
        if (scanResults[service] && scanResults[service][resourceType]) {
            const resourceData = scanResults[service][resourceType];
            
            if (Array.isArray(resourceData)) {
                resources.push(...resourceData);
            } else if (typeof resourceData === 'object') {
                Object.values(resourceData).forEach(resource => {
                    if (typeof resource === 'object') {
                        resources.push(resource);
                    }
                });
            }
        }

        return resources;
    }

    /**
     * Get resource type from path
     */
    getResourceTypeFromPath(path) {
        const pathParts = path.split('.');
        return pathParts.length >= 2 ? pathParts[1] : 'unknown';
    }

    /**
     * Calculate security score based on findings
     */
    calculateSecurityScore() {
        let score = 100;
        
        this.findings.forEach(finding => {
            switch (finding.severity) {
                case 'critical':
                    score -= 20;
                    break;
                case 'high':
                    score -= 10;
                    break;
                case 'medium':
                    score -= 5;
                    break;
                case 'low':
                    score -= 2;
                    break;
            }
        });
        
        this.securityScore = Math.max(0, score);
    }

    /**
     * Group findings by severity
     */
    groupFindingsBySeverity() {
        const grouped = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };

        this.findings.forEach(finding => {
            if (grouped[finding.severity]) {
                grouped[finding.severity].push(finding);
            }
        });

        return grouped;
    }

    /**
     * Get compliance status
     */
    getComplianceStatus() {
        const compliance = {};
        
        this.findings.forEach(finding => {
            if (finding.compliance) {
                finding.compliance.forEach(standard => {
                    if (!compliance[standard]) {
                        compliance[standard] = {
                            total: 0,
                            failed: 0,
                            passed: 0
                        };
                    }
                    compliance[standard].total++;
                    compliance[standard].failed++;
                });
            }
        });

        return compliance;
    }

    /**
     * Generate security report
     */
    generateSecurityReport(provider, scanResults) {
        const evaluation = this.evaluateRules(provider, scanResults);
        
        return {
            provider: provider,
            timestamp: new Date().toISOString(),
            securityScore: evaluation.securityScore,
            totalFindings: evaluation.findings.length,
            findingsBySeverity: evaluation.findingsBySeverity,
            complianceStatus: this.getComplianceStatus(),
            findings: evaluation.findings,
            recommendations: this.generateRecommendations(evaluation.findings)
        };
    }

    /**
     * Generate security recommendations
     */
    generateRecommendations(findings) {
        const recommendations = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };

        findings.forEach(finding => {
            if (recommendations[finding.severity]) {
                recommendations[finding.severity].push({
                    title: finding.title,
                    description: finding.description,
                    remediation: finding.remediation,
                    affectedResources: finding.resourceId
                });
            }
        });

        return recommendations;
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityRuleEngine;
} 