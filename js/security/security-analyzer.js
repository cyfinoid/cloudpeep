/**
 * Security Analyzer - Comprehensive cloud security analysis engine
 * Handles security scoring, compliance checks, and threat detection
 */

class SecurityAnalyzer {
    constructor() {
        this.complianceFrameworks = {
            hipaa: window.HIPAAChecker ? new window.HIPAAChecker() : null,
            pci: window.PCIChecker ? new window.PCIChecker() : null,
            cis: window.CISChecker ? new window.CISChecker() : null
        };
        
        this.threatDetector = window.ThreatDetector ? new window.ThreatDetector() : null;
        this.riskAssessor = window.RiskAssessor ? new window.RiskAssessor() : null;
    }

    /**
     * Analyze security posture of cloud resources
     * @param {Object} scanResults - Results from cloud scanners
     * @param {string} provider - Cloud provider (aws, azure, gcp)
     * @returns {Object} Comprehensive security analysis
     */
    async analyzeSecurity(scanResults, provider) {
        console.log('🔒 Starting comprehensive security analysis...');
        
        const analysis = {
            timestamp: new Date(),
            provider: provider,
            overallScore: 0,
            securityFindings: [],
            threatAssessment: {},
            recommendations: [],
            riskScore: 0
        };

        // 1. Security Scoring
        analysis.overallScore = this.calculateSecurityScore(scanResults);
        
        // 2. Security Findings Analysis
        analysis.securityFindings = this.analyzeSecurityFindings(scanResults, provider);
        
        // 3. Threat Assessment (removed compliance analysis)
        if (this.threatDetector && typeof this.threatDetector.assessThreats === 'function') {
            analysis.threatAssessment = this.threatDetector.assessThreats(scanResults, provider);
        } else {
            analysis.threatAssessment = {
                criticalThreats: 0,
                highThreats: 0,
                mediumThreats: 0,
                attackVectors: [],
                threatPaths: [],
                recommendations: []
            };
        }
        
        // 4. Risk Assessment
        if (this.riskAssessor && typeof this.riskAssessor.calculateRiskScore === 'function') {
            analysis.riskScore = this.riskAssessor.calculateRiskScore(scanResults, analysis);
        } else {
            analysis.riskScore = 0;
        }
        
        // 5. Generate Recommendations
        analysis.recommendations = this.generateRecommendations(analysis);
        
        console.log(`🔒 Security analysis complete. Overall score: ${analysis.overallScore}/100`);
        
        return analysis;
    }

    /**
     * Calculate overall security score (0-100)
     * @param {Object} scanResults - Scan results
     * @returns {number} Security score
     */
    calculateSecurityScore(scanResults) {
        let score = 100;
        const weights = {
            'critical': 20,
            'high': 15,
            'medium': 10,
            'low': 5,
            'info': 2
        };

        // Analyze each service for security issues
        Object.entries(scanResults).forEach(([service, data]) => {
            if (service === 'unimplemented_services' || service === 'cors_limited_services') return;
            
            const findings = this.analyzeServiceSecurity(data, service);
            findings.forEach(finding => {
                score -= weights[finding.severity] || 0;
            });
        });

        return Math.max(0, Math.round(score));
    }

    /**
     * Analyze security findings across all services
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Array} Security findings
     */
    analyzeSecurityFindings(scanResults, provider) {
        const findings = [];
        
        // Analyze each service for security issues
        Object.entries(scanResults).forEach(([service, data]) => {
            if (service === 'unimplemented_services' || service === 'cors_limited_services') return;
            
            const serviceFindings = this.analyzeServiceSecurity(data, service);
            findings.push(...serviceFindings);
        });
        
        return findings;
    }

    /**
     * Analyze security findings for a specific service
     * @param {Object} data - Service data
     * @param {string} service - Service name
     * @returns {Array} Security findings
     */
    analyzeServiceSecurity(data, service) {
        const findings = [];
        
        if (!data || data.error) {
            findings.push({
                type: 'service_error',
                severity: 'medium',
                service: service,
                description: `Unable to scan ${service}: ${data?.error || 'Unknown error'}`
            });
            return findings;
        }

        // Service-specific security checks
        switch (service) {
            case 'ec2':
                findings.push(...this.analyzeEC2Security(data));
                break;
            case 's3':
                findings.push(...this.analyzeS3Security(data));
                break;
            case 'iam':
                findings.push(...this.analyzeIAMSecurity(data));
                break;
            case 'rds':
                findings.push(...this.analyzeRDSSecurity(data));
                break;
            case 'vpc':
                findings.push(...this.analyzeVPCSecurity(data));
                break;
            case 'cloudtrail':
                findings.push(...this.analyzeCloudTrailSecurity(data));
                break;
            case 'cloudwatch':
                findings.push(...this.analyzeCloudWatchSecurity(data));
                break;
            case 'lambda':
                findings.push(...this.analyzeLambdaSecurity(data));
                break;
            default:
                // Generic security checks for other services
                findings.push(...this.analyzeGenericSecurity(data, service));
        }

        return findings;
    }

    /**
     * Analyze EC2 security
     * @param {Object} data - EC2 data
     * @returns {Array} Security findings
     */
    analyzeEC2Security(data) {
        const findings = [];
        
        if (!data.instances) return findings;

        data.instances.forEach(instance => {
            // Skip if instance is missing basic info
            if (!instance || !instance.instanceId) {
                console.warn('[SECURITY] EC2 instance missing instanceId:', instance);
                return;
            }

            const instanceId = instance.instanceId;
            
            // Check for public IP addresses
            if (instance.publicIpAddress) {
                findings.push({
                    type: 'public_instance',
                    severity: 'high',
                    resource: instanceId,
                    description: `EC2 instance ${instanceId} has public IP ${instance.publicIpAddress}`,
                    recommendation: 'Consider using private subnets and NAT gateways for internet access'
                });
            }

            // Check for unencrypted volumes - handle both string and array formats
            if (instance.blockDeviceMappings) {
                let blockDevices = [];
                
                // Handle different formats
                if (typeof instance.blockDeviceMappings === 'string') {
                    // If it's a formatted string, we can't easily check encryption
                    console.warn(`[SECURITY] Block device mappings for ${instanceId} is a string, cannot check encryption`);
                } else if (Array.isArray(instance.blockDeviceMappings)) {
                    blockDevices = instance.blockDeviceMappings;
                } else {
                    console.warn(`[SECURITY] Unknown block device mappings format for ${instanceId}:`, typeof instance.blockDeviceMappings);
                }
                
                // Check encryption for array format
                blockDevices.forEach(device => {
                    if (device && device.ebs && !device.ebs.encrypted) {
                        const volumeId = device.ebs.volumeId || 'unknown';
                        findings.push({
                            type: 'unencrypted_volume',
                            severity: 'high',
                            resource: volumeId,
                            description: `EBS volume ${volumeId} is not encrypted`,
                            recommendation: 'Enable encryption for all EBS volumes'
                        });
                    }
                });
            }

            // Check for missing IAM roles
            if (!instance.iamInstanceProfile) {
                findings.push({
                    type: 'missing_iam_role',
                    severity: 'medium',
                    resource: instanceId,
                    description: `EC2 instance ${instanceId} has no IAM role attached`,
                    recommendation: 'Attach appropriate IAM role with least privilege permissions'
                });
            }

            // Check for stopped instances (potential security risk)
            if (instance.state && instance.state.toLowerCase() === 'stopped') {
                findings.push({
                    type: 'stopped_instance',
                    severity: 'low',
                    resource: instanceId,
                    description: `EC2 instance ${instanceId} is stopped`,
                    recommendation: 'Review stopped instances and terminate if not needed'
                });
            }
        });

        return findings;
    }

    /**
     * Analyze S3 security
     * @param {Object} data - S3 data
     * @returns {Array} Security findings
     */
    analyzeS3Security(data) {
        const findings = [];
        
        if (!data.buckets) return findings;

        data.buckets.forEach(bucket => {
            // Skip if bucket is missing basic info
            if (!bucket || !bucket.name) {
                console.warn('[SECURITY] S3 bucket missing name:', bucket);
                return;
            }

            const bucketName = bucket.name;
            
            // Check for public access
            if (bucket.publicAccessBlock) {
                const block = bucket.publicAccessBlock;
                if (!block.blockPublicAcls || !block.blockPublicPolicy || 
                    !block.ignorePublicAcls || !block.restrictPublicBuckets) {
                    findings.push({
                        type: 'public_bucket_access',
                        severity: 'critical',
                        resource: bucketName,
                        description: `S3 bucket ${bucketName} has public access enabled`,
                        recommendation: 'Enable all public access block settings'
                    });
                }
            }

            // Check for encryption
            if (!bucket.encryption) {
                findings.push({
                    type: 'unencrypted_bucket',
                    severity: 'high',
                    resource: bucketName,
                    description: `S3 bucket ${bucketName} is not encrypted`,
                    recommendation: 'Enable default encryption for S3 buckets'
                });
            }

            // Check for versioning
            if (!bucket.versioning) {
                findings.push({
                    type: 'no_versioning',
                    severity: 'medium',
                    resource: bucketName,
                    description: `S3 bucket ${bucketName} has versioning disabled`,
                    recommendation: 'Enable versioning for data protection'
                });
            }
        });

        return findings;
    }

    /**
     * Analyze IAM security
     * @param {Object} data - IAM data
     * @returns {Array} Security findings
     */
    analyzeIAMSecurity(data) {
        const findings = [];
        
        // Check for root account usage
        if (data.users && Array.isArray(data.users)) {
            data.users.forEach(user => {
                if (user && user.userName === 'root') {
                    const arn = user.arn || 'root';
                    findings.push({
                        type: 'root_account_usage',
                        severity: 'critical',
                        resource: arn,
                        description: 'Root account is being used',
                        recommendation: 'Use IAM users instead of root account'
                    });
                }
            });
        }

        // Check for unused access keys
        if (data.accessKeys && Array.isArray(data.accessKeys)) {
            data.accessKeys.forEach(key => {
                if (key && key.status === 'Inactive') {
                    const keyId = key.accessKeyId || 'unknown';
                    findings.push({
                        type: 'unused_access_key',
                        severity: 'medium',
                        resource: keyId,
                        description: `Unused access key ${keyId}`,
                        recommendation: 'Remove unused access keys'
                    });
                }
            });
        }

        // Check for overly permissive policies
        if (data.policies && Array.isArray(data.policies)) {
            data.policies.forEach(policy => {
                if (policy && this.isOverlyPermissive(policy)) {
                    const policyName = policy.policyName || 'unknown';
                    const arn = policy.arn || 'unknown';
                    findings.push({
                        type: 'overly_permissive_policy',
                        severity: 'high',
                        resource: arn,
                        description: `Policy ${policyName} is overly permissive`,
                        recommendation: 'Apply principle of least privilege'
                    });
                }
            });
        }

        return findings;
    }

    /**
     * Check if IAM policy is overly permissive
     * @param {Object} policy - IAM policy
     * @returns {boolean} True if overly permissive
     */
    isOverlyPermissive(policy) {
        // Check for wildcard permissions
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
     * Analyze RDS security
     * @param {Object} data - RDS data
     * @returns {Array} Security findings
     */
    analyzeRDSSecurity(data) {
        const findings = [];
        
        if (!data.instances) return findings;

        data.instances.forEach(instance => {
            // Skip if instance is missing basic info
            if (!instance || !instance.dbInstanceIdentifier) {
                console.warn('[SECURITY] RDS instance missing dbInstanceIdentifier:', instance);
                return;
            }

            const instanceId = instance.dbInstanceIdentifier;
            
            // Check for public accessibility
            if (instance.publiclyAccessible) {
                findings.push({
                    type: 'public_rds_instance',
                    severity: 'critical',
                    resource: instanceId,
                    description: `RDS instance ${instanceId} is publicly accessible`,
                    recommendation: 'Place RDS instances in private subnets'
                });
            }

            // Check for encryption
            if (!instance.storageEncrypted) {
                findings.push({
                    type: 'unencrypted_rds',
                    severity: 'high',
                    resource: instanceId,
                    description: `RDS instance ${instanceId} is not encrypted`,
                    recommendation: 'Enable encryption for RDS instances'
                });
            }

            // Check for automated backups
            if (!instance.backupRetentionPeriod || instance.backupRetentionPeriod === 0) {
                findings.push({
                    type: 'no_automated_backups',
                    severity: 'medium',
                    resource: instanceId,
                    description: `RDS instance ${instanceId} has no automated backups`,
                    recommendation: 'Enable automated backups with appropriate retention'
                });
            }
        });

        return findings;
    }

    /**
     * Analyze VPC security
     * @param {Object} data - VPC data
     * @returns {Array} Security findings
     */
    analyzeVPCSecurity(data) {
        const findings = [];
        
        if (!data.vpcs) return findings;

        data.vpcs.forEach(vpc => {
            // Skip if VPC is missing basic info
            if (!vpc || !vpc.vpcId) {
                console.warn('[SECURITY] VPC missing vpcId:', vpc);
                return;
            }

            const vpcId = vpc.vpcId;
            
            // Check for default VPC usage
            if (vpc.isDefault) {
                findings.push({
                    type: 'default_vpc_usage',
                    severity: 'medium',
                    resource: vpcId,
                    description: `Default VPC ${vpcId} is being used`,
                    recommendation: 'Use custom VPCs instead of default VPC'
                });
            }

            // Check for flow logs
            if (!vpc.flowLogs || vpc.flowLogs.length === 0) {
                findings.push({
                    type: 'no_flow_logs',
                    severity: 'medium',
                    resource: vpcId,
                    description: `VPC ${vpcId} has no flow logs enabled`,
                    recommendation: 'Enable VPC flow logs for network monitoring'
                });
            }
        });

        return findings;
    }

    /**
     * Analyze CloudTrail security
     * @param {Object} data - CloudTrail data
     * @returns {Array} Security findings
     */
    analyzeCloudTrailSecurity(data) {
        const findings = [];
        
        if (!data.trails || data.trails.length === 0) {
            findings.push({
                type: 'no_cloudtrail',
                severity: 'critical',
                resource: 'account',
                description: 'No CloudTrail trails configured',
                recommendation: 'Enable CloudTrail for API activity logging'
            });
            return findings;
        }

        data.trails.forEach(trail => {
            // Check for global trails
            if (!trail.isMultiRegionTrail) {
                findings.push({
                    type: 'regional_cloudtrail',
                    severity: 'medium',
                    resource: trail.name,
                    description: `CloudTrail ${trail.name} is not multi-region`,
                    recommendation: 'Use multi-region CloudTrail for comprehensive logging'
                });
            }

            // Check for log file validation
            if (!trail.logFileValidationEnabled) {
                findings.push({
                    type: 'no_log_validation',
                    severity: 'medium',
                    resource: trail.name,
                    description: `CloudTrail ${trail.name} has log file validation disabled`,
                    recommendation: 'Enable log file validation for integrity'
                });
            }
        });

        return findings;
    }

    /**
     * Analyze CloudWatch security
     * @param {Object} data - CloudWatch data
     * @returns {Array} Security findings
     */
    analyzeCloudWatchSecurity(data) {
        const findings = [];
        
        // Check for missing log groups
        if (!data.logGroups || data.logGroups.length === 0) {
            findings.push({
                type: 'no_cloudwatch_logs',
                severity: 'medium',
                resource: 'account',
                description: 'No CloudWatch log groups configured',
                recommendation: 'Configure CloudWatch logs for service monitoring'
            });
        }

        return findings;
    }

    /**
     * Analyze Lambda security
     * @param {Object} data - Lambda data
     * @returns {Array} Security findings
     */
    analyzeLambdaSecurity(data) {
        const findings = [];
        
        if (!data.functions || !Array.isArray(data.functions)) {
            return findings;
        }

        data.functions.forEach(func => {
            if (!func) {
                return;
            }

            const functionName = func.functionName;
            
            // Check for exposed environment variables
            if (func.hasEnvironmentVariables && func.environmentVariables) {
                const envVarCount = Object.keys(func.environmentVariables).length;
                findings.push({
                    type: 'exposed_environment_variables',
                    severity: 'high',
                    resource: functionName,
                    description: `Lambda function ${functionName} has ${envVarCount} environment variables exposed`,
                    recommendation: 'Review environment variables for sensitive data and consider using AWS Secrets Manager'
                });
            }

            // Check for sensitive environment variables
            if (func.sensitiveEnvironmentVariables && func.sensitiveEnvironmentVariables !== 'None') {
                findings.push({
                    type: 'sensitive_environment_variables',
                    severity: 'critical',
                    resource: functionName,
                    description: `Lambda function ${functionName} has sensitive environment variables: ${func.sensitiveEnvironmentVariables}`,
                    recommendation: 'Move sensitive data to AWS Secrets Manager or Parameter Store'
                });
            }

            // Check for excessive timeout
            if (func.timeout && func.timeout > 900) { // 15 minutes
                findings.push({
                    type: 'excessive_timeout',
                    severity: 'medium',
                    resource: functionName,
                    description: `Lambda function ${functionName} has timeout of ${func.timeout} seconds (exceeds 15 minutes)`,
                    recommendation: 'Consider reducing timeout to improve security and cost efficiency'
                });
            }

            // Check for excessive memory allocation
            if (func.memorySize && func.memorySize > 3008) { // 3GB
                findings.push({
                    type: 'excessive_memory',
                    severity: 'low',
                    resource: functionName,
                    description: `Lambda function ${functionName} has ${func.memorySize}MB memory allocation`,
                    recommendation: 'Review memory allocation for cost optimization'
                });
            }

            // Check for missing IAM role
            if (!func.role) {
                findings.push({
                    type: 'missing_iam_role',
                    severity: 'high',
                    resource: functionName,
                    description: `Lambda function ${functionName} has no IAM role attached`,
                    recommendation: 'Attach appropriate IAM role with least privilege permissions'
                });
            }
        });

        return findings;
    }

    /**
     * Generic security analysis for other services
     * @param {Object} data - Service data
     * @param {string} service - Service name
     * @returns {Array} Security findings
     */
    analyzeGenericSecurity(data, service) {
        const findings = [];
        
        // Check for error states
        if (data.error) {
            findings.push({
                type: 'service_error',
                severity: 'medium',
                service: service,
                description: `Error scanning ${service}: ${data.error}`,
                recommendation: 'Check service permissions and configuration'
            });
        }

        // Check for empty results (might indicate permission issues)
        if (data && typeof data === 'object' && Object.keys(data).length === 0) {
            findings.push({
                type: 'no_data_returned',
                severity: 'low',
                service: service,
                description: `No data returned for ${service}`,
                recommendation: 'Verify service permissions and resource existence'
            });
        }

        return findings;
    }

    /**
     * Analyze compliance with various frameworks
     * @param {Object} scanResults - Scan results
     * @param {string} provider - Cloud provider
     * @returns {Object} Compliance results
     */
    async analyzeCompliance(scanResults, provider) {
        const complianceResults = {};
        
        // Analyze each compliance framework
        for (const [framework, analyzer] of Object.entries(this.complianceFrameworks)) {
            try {
                if (analyzer && typeof analyzer.analyze === 'function') {
                    complianceResults[framework] = await analyzer.analyze(scanResults, provider);
                } else {
                    console.warn(`${framework} compliance analyzer not available`);
                    complianceResults[framework] = {
                        compliant: false,
                        score: 0,
                        findings: [],
                        error: 'Compliance analyzer not available'
                    };
                }
            } catch (error) {
                console.error(`Error analyzing ${framework} compliance:`, error);
                complianceResults[framework] = {
                    compliant: false,
                    score: 0,
                    findings: [],
                    error: error.message
                };
            }
        }
        
        return complianceResults;
    }

    /**
     * Generate security recommendations
     * @param {Object} analysis - Security analysis results
     * @returns {Array} Recommendations
     */
    generateRecommendations(analysis) {
        const recommendations = [];
        
        // High priority recommendations
        if (analysis.overallScore < 50) {
            recommendations.push({
                priority: 'critical',
                category: 'overall',
                title: 'Immediate Security Improvements Required',
                description: 'Your security score is below 50. Implement critical security controls immediately.',
                actions: [
                    'Enable CloudTrail logging',
                    'Encrypt all data at rest',
                    'Review and restrict IAM permissions',
                    'Enable VPC flow logs'
                ]
            });
        }

        // Threat-based recommendations (removed compliance recommendations)
        if (analysis.threatAssessment.criticalThreats > 0) {
            recommendations.push({
                priority: 'critical',
                category: 'threats',
                title: 'Critical Threats Detected',
                description: `${analysis.threatAssessment.criticalThreats} critical threats identified`,
                actions: analysis.threatAssessment.recommendations || []
            });
        }

        return recommendations;
    }
}

// Make class globally available
window.SecurityAnalyzer = SecurityAnalyzer; 