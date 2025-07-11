/**
 * Service metadata for PeekInTheCloud
 * Contains information about cloud services, their icons, descriptions, and permissions
 */

const ServiceMetadata = {
    aws: {
        name: 'Amazon Web Services',
        services: {
            s3: {
                name: 'S3',
                fullName: 'Simple Storage Service',
                description: 'Object storage service for storing and retrieving data',
                icon: '📦',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListBuckets', 'ListObjects', 'GetObject', 'PutObject', 'DeleteObject'],
                category: 'Storage'
            },
            ec2: {
                name: 'EC2',
                fullName: 'Elastic Compute Cloud',
                description: 'Virtual servers in the cloud',
                icon: '🖥️',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['DescribeInstances', 'DescribeSecurityGroups', 'DescribeVolumes'],
                category: 'Compute'
            },
            iam: {
                name: 'IAM',
                fullName: 'Identity and Access Management',
                description: 'Manage users, groups, and permissions',
                icon: '👤',
                permissions: ['List', 'Read'],
                apiCalls: ['ListUsers', 'ListRoles', 'ListPolicies', 'GetUser'],
                category: 'Security'
            },
            sts: {
                name: 'STS',
                fullName: 'Security Token Service',
                description: 'Temporary security credentials',
                icon: '🔑',
                permissions: ['Read'],
                apiCalls: ['GetCallerIdentity'],
                category: 'Security'
            },
            lambda: {
                name: 'Lambda',
                fullName: 'Serverless Computing',
                description: 'Run code without provisioning servers',
                icon: '⚡',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListFunctions', 'GetFunction', 'InvokeFunction'],
                category: 'Compute'
            }
        }
    },
    azure: {
        name: 'Microsoft Azure',
        services: {
            resourceGroups: {
                name: 'Resource Groups',
                fullName: 'Resource Groups',
                description: 'Logical containers for Azure resources',
                icon: '📁',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListResourceGroups', 'GetResourceGroup'],
                category: 'Management'
            },
            vms: {
                name: 'Virtual Machines',
                fullName: 'Azure Virtual Machines',
                description: 'Scalable computing resources',
                icon: '🖥️',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListVirtualMachines', 'GetVirtualMachine'],
                category: 'Compute'
            },
            blobStorage: {
                name: 'Blob Storage',
                fullName: 'Azure Blob Storage',
                description: 'Object storage for unstructured data',
                icon: '📦',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListContainers', 'ListBlobs', 'GetBlob'],
                category: 'Storage'
            },
            appServices: {
                name: 'App Services',
                fullName: 'Azure App Service',
                description: 'Web apps, mobile backends, and RESTful APIs',
                icon: '🌐',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListWebApps', 'GetWebApp'],
                category: 'Web'
            }
        }
    },
    gcp: {
        name: 'Google Cloud Platform',
        services: {
            compute: {
                name: 'Compute Engine',
                fullName: 'Google Compute Engine',
                description: 'Virtual machines on Google infrastructure',
                icon: '🖥️',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListInstances', 'GetInstance'],
                category: 'Compute'
            },
            gcs: {
                name: 'Cloud Storage',
                fullName: 'Google Cloud Storage',
                description: 'Object storage with global edge locations',
                icon: '📦',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListBuckets', 'ListObjects', 'GetObject'],
                category: 'Storage'
            },
            iam: {
                name: 'IAM',
                fullName: 'Identity and Access Management',
                description: 'Manage access to Google Cloud resources',
                icon: '👤',
                permissions: ['List', 'Read'],
                apiCalls: ['ListServiceAccounts', 'ListRoles'],
                category: 'Security'
            },
            cloudFunctions: {
                name: 'Cloud Functions',
                fullName: 'Google Cloud Functions',
                description: 'Serverless functions that scale automatically',
                icon: '⚡',
                permissions: ['List', 'Read', 'Write', 'Delete'],
                apiCalls: ['ListFunctions', 'GetFunction'],
                category: 'Compute'
            }
        }
    }
};

/**
 * Permission levels for services
 */
const PermissionLevels = {
    NONE: 'none',
    LIST: 'list',
    READ: 'read',
    WRITE: 'write',
    DELETE: 'delete'
};

/**
 * Service status indicators
 */
const ServiceStatus = {
    UNKNOWN: 'unknown',
    ACCESSIBLE: 'accessible',
    INACCESSIBLE: 'inaccessible',
    ERROR: 'error'
};

/**
 * Get service metadata for a specific provider and service
 * @param {string} provider - Cloud provider (aws, azure, gcp)
 * @param {string} service - Service name
 * @returns {Object|null} - Service metadata or null if not found
 */
function getServiceMetadata(provider, service) {
    return ServiceMetadata[provider]?.services[service] || null;
}

/**
 * Get all services for a provider
 * @param {string} provider - Cloud provider
 * @returns {Object} - All services for the provider
 */
function getProviderServices(provider) {
    return ServiceMetadata[provider]?.services || {};
}

/**
 * Get all providers
 * @returns {Array} - Array of provider names
 */
function getProviders() {
    return Object.keys(ServiceMetadata);
}

/**
 * Get service categories for a provider
 * @param {string} provider - Cloud provider
 * @returns {Array} - Array of unique categories
 */
function getServiceCategories(provider) {
    const services = getProviderServices(provider);
    const categories = new Set();
    
    Object.values(services).forEach(service => {
        categories.add(service.category);
    });
    
    return Array.from(categories);
}

/**
 * Get services by category for a provider
 * @param {string} provider - Cloud provider
 * @param {string} category - Service category
 * @returns {Object} - Services in the specified category
 */
function getServicesByCategory(provider, category) {
    const services = getProviderServices(provider);
    const filtered = {};
    
    Object.entries(services).forEach(([key, service]) => {
        if (service.category === category) {
            filtered[key] = service;
        }
    });
    
    return filtered;
}

/**
 * Format permission level for display
 * @param {string} permission - Permission level
 * @returns {string} - Formatted permission string
 */
function formatPermission(permission) {
    switch (permission) {
        case PermissionLevels.NONE:
            return 'No Access';
        case PermissionLevels.LIST:
            return 'List Only';
        case PermissionLevels.READ:
            return 'Read Access';
        case PermissionLevels.WRITE:
            return 'Write Access';
        case PermissionLevels.DELETE:
            return 'Full Access';
        default:
            return 'Unknown';
    }
}

/**
 * Get permission color for UI
 * @param {string} permission - Permission level
 * @returns {string} - CSS color class
 */
function getPermissionColor(permission) {
    switch (permission) {
        case PermissionLevels.NONE:
            return 'text-red-500';
        case PermissionLevels.LIST:
            return 'text-yellow-500';
        case PermissionLevels.READ:
            return 'text-blue-500';
        case PermissionLevels.WRITE:
            return 'text-green-500';
        case PermissionLevels.DELETE:
            return 'text-purple-500';
        default:
            return 'text-gray-500';
    }
}

/**
 * Get service status color for UI
 * @param {string} status - Service status
 * @returns {string} - CSS color class
 */
function getStatusColor(status) {
    switch (status) {
        case ServiceStatus.ACCESSIBLE:
            return 'text-green-500';
        case ServiceStatus.INACCESSIBLE:
            return 'text-red-500';
        case ServiceStatus.ERROR:
            return 'text-orange-500';
        default:
            return 'text-gray-500';
    }
}

// Export for use in other modules
window.ServiceMetadata = {
    metadata: ServiceMetadata,
    PermissionLevels,
    ServiceStatus,
    getServiceMetadata,
    getProviderServices,
    getProviders,
    getServiceCategories,
    getServicesByCategory,
    formatPermission,
    getPermissionColor,
    getStatusColor
}; 