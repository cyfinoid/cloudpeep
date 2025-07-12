/**
 * Risk Assessor - Calculates risk scores and business impact
 * Evaluates security risks based on findings and business context
 */

class RiskAssessor {
    constructor() {
        this.riskFactors = {
            // Technical risk factors
            publicExposure: { weight: 0.25, critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
            dataSensitivity: { weight: 0.20, critical: 0.9, high: 0.7, medium: 0.5, low: 0.3 },
            accessControl: { weight: 0.20, critical: 0.8, high: 0.6, medium: 0.4, low: 0.2 },
            monitoring: { weight: 0.15, critical: 0.6, high: 0.4, medium: 0.2, low: 0.1 },
            compliance: { weight: 0.20, critical: 0.8, high: 0.6, medium: 0.4, low: 0.2 }
        };
        
        this.businessImpact = {
            financial: { weight: 0.30, high: 0.9, medium: 0.6, low: 0.3 },
            operational: { weight: 0.25, high: 0.8, medium: 0.5, low: 0.2 },
            reputational: { weight: 0.25, high: 0.8, medium: 0.5, low: 0.2 },
            regulatory: { weight: 0.20, high: 0.9, medium: 0.6, low: 0.3 }
        };
    }

    /**
     * Calculate overall risk score
     * @param {Object} scanResults - Scan results
     * @param {Object} analysis - Security analysis
     * @returns {number} Risk score (0-100)
     */
    calculateRiskScore(scanResults, analysis) {
        console.log('📊 Calculating risk score...');
        
        const riskAssessment = {
            technicalRisk: this.calculateTechnicalRisk(scanResults, analysis),
            businessImpact: this.calculateBusinessImpact(scanResults, analysis),
            overallRisk: 0,
            riskFactors: {},
            recommendations: []
        };

        // Calculate overall risk score
        riskAssessment.overallRisk = this.combineRiskFactors(riskAssessment.technicalRisk, riskAssessment.businessImpact);
        
        // Generate risk-based recommendations
        riskAssessment.recommendations = this.generateRiskRecommendations(riskAssessment);
        
        console.log(`📊 Risk assessment complete. Overall risk score: ${riskAssessment.overallRisk}/100`);
        
        return riskAssessment.overallRisk;
    }

    /**
     * Calculate technical risk score
     * @param {Object} scanResults - Scan results
     * @param {Object} analysis - Security analysis
     * @returns {number} Technical risk score
     */
    calculateTechnicalRisk(scanResults, analysis) {
        let technicalRisk = 0;
        const riskFactors = {};

        // Public exposure risk
        const publicExposureRisk = this.calculatePublicExposureRisk(scanResults);
        riskFactors.publicExposure = publicExposureRisk;
        technicalRisk += publicExposureRisk * this.riskFactors.publicExposure.weight;

        // Data sensitivity risk
        const dataSensitivityRisk = this.calculateDataSensitivityRisk(scanResults);
        riskFactors.dataSensitivity = dataSensitivityRisk;
        technicalRisk += dataSensitivityRisk * this.riskFactors.dataSensitivity.weight;

        // Access control risk
        const accessControlRisk = this.calculateAccessControlRisk(scanResults);
        riskFactors.accessControl = accessControlRisk;
        technicalRisk += accessControlRisk * this.riskFactors.accessControl.weight;

        // Monitoring risk
        const monitoringRisk = this.calculateMonitoringRisk(scanResults);
        riskFactors.monitoring = monitoringRisk;
        technicalRisk += monitoringRisk * this.riskFactors.monitoring.weight;

        // Compliance risk
        const complianceRisk = this.calculateComplianceRisk(analysis);
        riskFactors.compliance = complianceRisk;
        technicalRisk += complianceRisk * this.riskFactors.compliance.weight;

        return {
            score: Math.round(technicalRisk * 100),
            factors: riskFactors
        };
    }

    /**
     * Calculate public exposure risk
     * @param {Object} scanResults - Scan results
     * @returns {number} Public exposure risk score
     */
    calculatePublicExposureRisk(scanResults) {
        let riskScore = 0;
        let totalResources = 0;
        let exposedResources = 0;

        // Count public EC2 instances
        if (scanResults.ec2 && scanResults.ec2.instances) {
            totalResources += scanResults.ec2.instances.length;
            exposedResources += scanResults.ec2.instances.filter(instance => instance.publicIpAddress).length;
        }

        // Count public RDS instances
        if (scanResults.rds && scanResults.rds.instances) {
            totalResources += scanResults.rds.instances.length;
            exposedResources += scanResults.rds.instances.filter(instance => instance.publiclyAccessible).length;
        }

        // Count public S3 buckets
        if (scanResults.s3 && scanResults.s3.buckets) {
            totalResources += scanResults.s3.buckets.length;
            const publicBuckets = scanResults.s3.buckets.filter(bucket => {
                if (bucket.publicAccessBlock) {
                    const block = bucket.publicAccessBlock;
                    return !block.blockPublicAcls || !block.blockPublicPolicy || 
                           !block.ignorePublicAcls || !block.restrictPublicBuckets;
                }
                return false;
            });
            exposedResources += publicBuckets.length;
        }

        if (totalResources > 0) {
            const exposureRatio = exposedResources / totalResources;
            if (exposureRatio > 0.5) {
                riskScore = this.riskFactors.publicExposure.critical;
            } else if (exposureRatio > 0.2) {
                riskScore = this.riskFactors.publicExposure.high;
            } else if (exposureRatio > 0.05) {
                riskScore = this.riskFactors.publicExposure.medium;
            } else {
                riskScore = this.riskFactors.publicExposure.low;
            }
        }

        return riskScore;
    }

    /**
     * Calculate data sensitivity risk
     * @param {Object} scanResults - Scan results
     * @returns {number} Data sensitivity risk score
     */
    calculateDataSensitivityRisk(scanResults) {
        let riskScore = 0;
        let unencryptedResources = 0;
        let totalDataResources = 0;

        // Count unencrypted EBS volumes
        if (scanResults.ec2 && scanResults.ec2.instances) {
            scanResults.ec2.instances.forEach(instance => {
                if (instance.blockDeviceMappings) {
                    instance.blockDeviceMappings.forEach(device => {
                        totalDataResources++;
                        if (device.ebs && !device.ebs.encrypted) {
                            unencryptedResources++;
                        }
                    });
                }
            });
        }

        // Count unencrypted RDS instances
        if (scanResults.rds && scanResults.rds.instances) {
            totalDataResources += scanResults.rds.instances.length;
            unencryptedResources += scanResults.rds.instances.filter(instance => !instance.storageEncrypted).length;
        }

        // Count unencrypted S3 buckets
        if (scanResults.s3 && scanResults.s3.buckets) {
            totalDataResources += scanResults.s3.buckets.length;
            unencryptedResources += scanResults.s3.buckets.filter(bucket => !bucket.encryption).length;
        }

        if (totalDataResources > 0) {
            const unencryptedRatio = unencryptedResources / totalDataResources;
            if (unencryptedRatio > 0.5) {
                riskScore = this.riskFactors.dataSensitivity.critical;
            } else if (unencryptedRatio > 0.2) {
                riskScore = this.riskFactors.dataSensitivity.high;
            } else if (unencryptedRatio > 0.05) {
                riskScore = this.riskFactors.dataSensitivity.medium;
            } else {
                riskScore = this.riskFactors.dataSensitivity.low;
            }
        }

        return riskScore;
    }

    /**
     * Calculate access control risk
     * @param {Object} scanResults - Scan results
     * @returns {number} Access control risk score
     */
    calculateAccessControlRisk(scanResults) {
        let riskScore = 0;
        let weakAccessControls = 0;
        let totalAccessControls = 0;

        // Count overly permissive IAM policies
        if (scanResults.iam && scanResults.iam.policies) {
            totalAccessControls += scanResults.iam.policies.length;
            weakAccessControls += scanResults.iam.policies.filter(policy => this.isOverlyPermissive(policy)).length;
        }

        // Count open security groups
        if (scanResults.ec2 && scanResults.ec2.securityGroups) {
            totalAccessControls += scanResults.ec2.securityGroups.length;
            weakAccessControls += scanResults.ec2.securityGroups.filter(sg => {
                if (sg.ipPermissions) {
                    return sg.ipPermissions.some(rule => 
                        rule.ipRanges && rule.ipRanges.some(range => range.cidrIp === '0.0.0.0/0')
                    );
                }
                return false;
            }).length;
        }

        // Check for root account usage
        if (scanResults.iam && scanResults.iam.users) {
            const rootUser = scanResults.iam.users.find(user => user.userName === 'root');
            if (rootUser) {
                weakAccessControls++;
            }
            totalAccessControls++;
        }

        if (totalAccessControls > 0) {
            const weakRatio = weakAccessControls / totalAccessControls;
            if (weakRatio > 0.3) {
                riskScore = this.riskFactors.accessControl.critical;
            } else if (weakRatio > 0.1) {
                riskScore = this.riskFactors.accessControl.high;
            } else if (weakRatio > 0.05) {
                riskScore = this.riskFactors.accessControl.medium;
            } else {
                riskScore = this.riskFactors.accessControl.low;
            }
        }

        return riskScore;
    }

    /**
     * Calculate monitoring risk
     * @param {Object} scanResults - Scan results
     * @returns {number} Monitoring risk score
     */
    calculateMonitoringRisk(scanResults) {
        let riskScore = 0;
        let missingMonitoring = 0;
        let totalMonitoringPoints = 0;

        // Check for CloudTrail
        totalMonitoringPoints++;
        if (!scanResults.cloudtrail || !scanResults.cloudtrail.trails || scanResults.cloudtrail.trails.length === 0) {
            missingMonitoring++;
        }

        // Check for VPC flow logs
        if (scanResults.vpc && scanResults.vpc.vpcs) {
            totalMonitoringPoints += scanResults.vpc.vpcs.length;
            missingMonitoring += scanResults.vpc.vpcs.filter(vpc => !vpc.flowLogs || vpc.flowLogs.length === 0).length;
        }

        // Check for CloudWatch logs
        totalMonitoringPoints++;
        if (!scanResults.cloudwatch || !scanResults.cloudwatch.logGroups || scanResults.cloudwatch.logGroups.length === 0) {
            missingMonitoring++;
        }

        if (totalMonitoringPoints > 0) {
            const missingRatio = missingMonitoring / totalMonitoringPoints;
            if (missingRatio > 0.5) {
                riskScore = this.riskFactors.monitoring.critical;
            } else if (missingRatio > 0.3) {
                riskScore = this.riskFactors.monitoring.high;
            } else if (missingRatio > 0.1) {
                riskScore = this.riskFactors.monitoring.medium;
            } else {
                riskScore = this.riskFactors.monitoring.low;
            }
        }

        return riskScore;
    }

    /**
     * Calculate compliance risk
     * @param {Object} analysis - Security analysis
     * @returns {number} Compliance risk score
     */
    calculateComplianceRisk(analysis) {
        let riskScore = 0;
        let nonCompliantFrameworks = 0;
        let totalFrameworks = 0;

        if (analysis.complianceResults) {
            Object.entries(analysis.complianceResults).forEach(([framework, result]) => {
                totalFrameworks++;
                if (!result.compliant) {
                    nonCompliantFrameworks++;
                }
            });
        }

        if (totalFrameworks > 0) {
            const nonCompliantRatio = nonCompliantFrameworks / totalFrameworks;
            if (nonCompliantRatio > 0.5) {
                riskScore = this.riskFactors.compliance.critical;
            } else if (nonCompliantRatio > 0.2) {
                riskScore = this.riskFactors.compliance.high;
            } else if (nonCompliantRatio > 0.05) {
                riskScore = this.riskFactors.compliance.medium;
            } else {
                riskScore = this.riskFactors.compliance.low;
            }
        }

        return riskScore;
    }

    /**
     * Calculate business impact
     * @param {Object} scanResults - Scan results
     * @param {Object} analysis - Security analysis
     * @returns {Object} Business impact assessment
     */
    calculateBusinessImpact(scanResults, analysis) {
        const businessImpact = {
            financial: this.calculateFinancialImpact(scanResults),
            operational: this.calculateOperationalImpact(scanResults),
            reputational: this.calculateReputationalImpact(scanResults),
            regulatory: this.calculateRegulatoryImpact(analysis),
            overall: 0
        };

        // Calculate overall business impact
        businessImpact.overall = 
            businessImpact.financial * this.businessImpact.financial.weight +
            businessImpact.operational * this.businessImpact.operational.weight +
            businessImpact.reputational * this.businessImpact.reputational.weight +
            businessImpact.regulatory * this.businessImpact.regulatory.weight;

        return businessImpact;
    }

    /**
     * Calculate financial impact
     * @param {Object} scanResults - Scan results
     * @returns {number} Financial impact score
     */
    calculateFinancialImpact(scanResults) {
        let impactScore = 0;
        let criticalFindings = 0;
        let totalResources = 0;

        // Count critical security findings
        Object.entries(scanResults).forEach(([service, data]) => {
            if (service === 'unimplemented_services') return;
            
            if (data && typeof data === 'object') {
                // Count resources
                if (data.instances) totalResources += data.instances.length;
                if (data.buckets) totalResources += data.buckets.length;
                if (data.users) totalResources += data.users.length;
                
                // Count critical findings (simplified)
                if (data.error) criticalFindings++;
            }
        });

        if (totalResources > 0) {
            const criticalRatio = criticalFindings / totalResources;
            if (criticalRatio > 0.1) {
                impactScore = this.businessImpact.financial.high;
            } else if (criticalRatio > 0.05) {
                impactScore = this.businessImpact.financial.medium;
            } else {
                impactScore = this.businessImpact.financial.low;
            }
        }

        return impactScore;
    }

    /**
     * Calculate operational impact
     * @param {Object} scanResults - Scan results
     * @returns {number} Operational impact score
     */
    calculateOperationalImpact(scanResults) {
        let impactScore = 0;
        let operationalIssues = 0;

        // Check for missing monitoring (operational visibility)
        if (!scanResults.cloudtrail || !scanResults.cloudtrail.trails || scanResults.cloudtrail.trails.length === 0) {
            operationalIssues++;
        }

        if (!scanResults.cloudwatch || !scanResults.cloudwatch.logGroups || scanResults.cloudwatch.logGroups.length === 0) {
            operationalIssues++;
        }

        // Check for security group issues (network operations)
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
                operationalIssues++;
            }
        }

        if (operationalIssues > 2) {
            impactScore = this.businessImpact.operational.high;
        } else if (operationalIssues > 1) {
            impactScore = this.businessImpact.operational.medium;
        } else {
            impactScore = this.businessImpact.operational.low;
        }

        return impactScore;
    }

    /**
     * Calculate reputational impact
     * @param {Object} scanResults - Scan results
     * @returns {number} Reputational impact score
     */
    calculateReputationalImpact(scanResults) {
        let impactScore = 0;
        let publicExposure = 0;

        // Count publicly exposed resources
        if (scanResults.ec2 && scanResults.ec2.instances) {
            publicExposure += scanResults.ec2.instances.filter(instance => instance.publicIpAddress).length;
        }

        if (scanResults.rds && scanResults.rds.instances) {
            publicExposure += scanResults.rds.instances.filter(instance => instance.publiclyAccessible).length;
        }

        if (scanResults.s3 && scanResults.s3.buckets) {
            const publicBuckets = scanResults.s3.buckets.filter(bucket => {
                if (bucket.publicAccessBlock) {
                    const block = bucket.publicAccessBlock;
                    return !block.blockPublicAcls || !block.blockPublicPolicy || 
                           !block.ignorePublicAcls || !block.restrictPublicBuckets;
                }
                return false;
            });
            publicExposure += publicBuckets.length;
        }

        if (publicExposure > 5) {
            impactScore = this.businessImpact.reputational.high;
        } else if (publicExposure > 2) {
            impactScore = this.businessImpact.reputational.medium;
        } else {
            impactScore = this.businessImpact.reputational.low;
        }

        return impactScore;
    }

    /**
     * Calculate regulatory impact
     * @param {Object} analysis - Security analysis
     * @returns {number} Regulatory impact score
     */
    calculateRegulatoryImpact(analysis) {
        let impactScore = 0;
        let nonCompliantFrameworks = 0;

        if (analysis.complianceResults) {
            Object.entries(analysis.complianceResults).forEach(([framework, result]) => {
                if (!result.compliant) {
                    nonCompliantFrameworks++;
                }
            });
        }

        if (nonCompliantFrameworks > 2) {
            impactScore = this.businessImpact.regulatory.high;
        } else if (nonCompliantFrameworks > 1) {
            impactScore = this.businessImpact.regulatory.medium;
        } else {
            impactScore = this.businessImpact.regulatory.low;
        }

        return impactScore;
    }

    /**
     * Combine technical risk and business impact
     * @param {Object} technicalRisk - Technical risk assessment
     * @param {Object} businessImpact - Business impact assessment
     * @returns {number} Combined risk score
     */
    combineRiskFactors(technicalRisk, businessImpact) {
        // Weight technical risk at 60% and business impact at 40%
        const technicalWeight = 0.6;
        const businessWeight = 0.4;

        const combinedRisk = 
            (technicalRisk.score / 100) * technicalWeight +
            (businessImpact.overall) * businessWeight;

        return Math.round(combinedRisk * 100);
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
     * Generate risk-based recommendations
     * @param {Object} riskAssessment - Risk assessment results
     * @returns {Array} Risk-based recommendations
     */
    generateRiskRecommendations(riskAssessment) {
        const recommendations = [];
        
        if (riskAssessment.overallRisk > 80) {
            recommendations.push({
                priority: 'critical',
                title: 'Immediate Risk Mitigation Required',
                description: 'High-risk environment requiring immediate attention',
                actions: [
                    'Conduct immediate security assessment',
                    'Implement emergency security controls',
                    'Review all public-facing resources',
                    'Enable comprehensive monitoring'
                ]
            });
        } else if (riskAssessment.overallRisk > 60) {
            recommendations.push({
                priority: 'high',
                title: 'Address High-Risk Issues',
                description: 'Significant risk factors identified',
                actions: [
                    'Prioritize security improvements',
                    'Reduce public exposure',
                    'Strengthen access controls',
                    'Implement monitoring solutions'
                ]
            });
        } else if (riskAssessment.overallRisk > 40) {
            recommendations.push({
                priority: 'medium',
                title: 'Moderate Risk Environment',
                description: 'Some risk factors present',
                actions: [
                    'Implement security best practices',
                    'Regular security assessments',
                    'Monitor for new vulnerabilities',
                    'Maintain security controls'
                ]
            });
        }

        return recommendations;
    }
}

// Make class globally available
window.RiskAssessor = RiskAssessor; 