// services.js
// Broad service catalog for UI, service selection, and scanning coverage (PeekInTheCloud)
// This file is distinct from js/service-metadata.js, which contains detailed security/permission metadata.
// Use this file for listing, filtering, and categorizing cloud services in the UI.
// Cloud Service Metadata
const CLOUD_SERVICES = {
    aws: {
        name: 'Amazon Web Services',
        icon: '☁️',
        color: '#FF9900',
        services: {
            // Compute Services
            ec2: { name: 'EC2 Instances', category: 'Compute', description: 'Virtual servers' },
            lambda: { name: 'Lambda Functions', category: 'Compute', description: 'Serverless functions' },
            ecs: { name: 'ECS Clusters', category: 'Compute', description: 'Container orchestration' },
            eks: { name: 'EKS Clusters', category: 'Compute', description: 'Kubernetes service' },
            elasticbeanstalk: { name: 'Elastic Beanstalk', category: 'Compute', description: 'Platform as a service' },
            emr: { name: 'EMR Clusters', category: 'Compute', description: 'Big data processing' },
            
            // Storage Services
            s3: { name: 'S3 Buckets', category: 'Storage', description: 'Object storage' },
            efs: { name: 'EFS File Systems', category: 'Storage', description: 'File storage' },
            storagegateway: { name: 'Storage Gateway', category: 'Storage', description: 'Hybrid storage' },
            
            // Database Services
            rds: { name: 'RDS Instances', category: 'Database', description: 'Managed databases' },
            dynamodb: { name: 'DynamoDB Tables', category: 'Database', description: 'NoSQL database' },
            redshift: { name: 'Redshift Clusters', category: 'Database', description: 'Data warehouse' },
            elasticache: { name: 'ElastiCache Clusters', category: 'Database', description: 'In-memory caching' },
            athena: { name: 'Athena Workgroups', category: 'Database', description: 'Query service' },
            
            // Networking Services
            vpc: { name: 'VPCs', category: 'Networking', description: 'Virtual private clouds' },
            subnets: { name: 'Subnets', category: 'Networking', description: 'Network subnets' },
            securitygroups: { name: 'Security Groups', category: 'Networking', description: 'Firewall rules' },
            route53: { name: 'Route53 Zones', category: 'Networking', description: 'DNS service' },
            apigateway: { name: 'API Gateway', category: 'Networking', description: 'API management' },
            cloudfront: { name: 'CloudFront Distributions', category: 'Networking', description: 'CDN service' },
            
            // Security Services
            iam: { name: 'IAM Users/Roles', category: 'Security', description: 'Identity management' },
            cloudtrail: { name: 'CloudTrail Trails', category: 'Security', description: 'Audit logging' },
            secretsmanager: { name: 'Secrets Manager', category: 'Security', description: 'Secret management' },
            detective: { name: 'Detective Graphs', category: 'Security', description: 'Security analytics' },
            
            // Analytics Services
            kinesis: { name: 'Kinesis Streams', category: 'Analytics', description: 'Real-time streaming' },
            glue: { name: 'Glue Data Catalogs', category: 'Analytics', description: 'Data catalog' },
            stepfunctions: { name: 'Step Functions', category: 'Analytics', description: 'Workflow orchestration' },
            cloudwatch: { name: 'CloudWatch Alarms', category: 'Analytics', description: 'Monitoring' },
            
            // Media Services
            mediaconvert: { name: 'MediaConvert Jobs', category: 'Media', description: 'Video processing' },
            medialive: { name: 'MediaLive Channels', category: 'Media', description: 'Live streaming' },
            mediapackage: { name: 'MediaPackage Channels', category: 'Media', description: 'Video delivery' },
            elastictranscoder: { name: 'Elastic Transcoder', category: 'Media', description: 'Video transcoding' },
            
            // AI/ML Services
            sagemaker: { name: 'SageMaker Notebooks', category: 'AI/ML', description: 'Machine learning' },
            lex: { name: 'Lex Bots', category: 'AI/ML', description: 'Conversational AI' },
            iot: { name: 'IoT Things', category: 'AI/ML', description: 'Internet of Things' },
            
            // Development Services
            codepipeline: { name: 'CodePipeline', category: 'Development', description: 'CI/CD pipeline' },
            codecommit: { name: 'CodeCommit Repositories', category: 'Development', description: 'Git repositories' },
            cloud9: { name: 'Cloud9 Environments', category: 'Development', description: 'Cloud IDE' },
            ssm: { name: 'SSM Documents', category: 'Development', description: 'Systems Manager' },
            
            // Management Services
            cloudformation: { name: 'CloudFormation Stacks', category: 'Management', description: 'Infrastructure as code' },
            organizations: { name: 'Organizations', category: 'Management', description: 'Account management' },
            backup: { name: 'Backup Plans', category: 'Management', description: 'Backup service' },
            
            // Messaging Services
            sns: { name: 'SNS Topics', category: 'Messaging', description: 'Pub/sub messaging' },
            sqs: { name: 'SQS Queues', category: 'Messaging', description: 'Message queuing' },
            
            // Container Services
            ecr: { name: 'ECR Repositories', category: 'Containers', description: 'Container registry' },
            
            // Additional Services
            appsync: { name: 'AppSync APIs', category: 'Development', description: 'GraphQL service' },
            datapipeline: { name: 'Data Pipeline', category: 'Analytics', description: 'Data processing' },
            workspaces: { name: 'WorkSpaces', category: 'Compute', description: 'Virtual desktops' },
            datasync: { name: 'DataSync Tasks', category: 'Storage', description: 'Data transfer' },
            pinpoint: { name: 'Pinpoint Applications', category: 'Messaging', description: 'Mobile engagement' },
            mq: { name: 'MQ Brokers', category: 'Messaging', description: 'Message broker' },
            opsworks: { name: 'OpsWorks Stacks', category: 'Management', description: 'Configuration management' },
            appmesh: { name: 'App Mesh Meshes', category: 'Networking', description: 'Service mesh' },
            mediastore: { name: 'MediaStore Containers', category: 'Media', description: 'Media storage' },
            serverlessrepo: { name: 'Serverless Repo', category: 'Development', description: 'Application repository' }
        }
    },
    
    azure: {
        name: 'Microsoft Azure',
        icon: '☁️',
        color: '#0078D4',
        services: {
            // Compute Services
            virtualmachines: { name: 'Virtual Machines', category: 'Compute', description: 'Cloud virtual machines' },
            appservices: { name: 'App Services', category: 'Compute', description: 'Web applications' },
            containerinstances: { name: 'Container Instances', category: 'Compute', description: 'Serverless containers' },
            functions: { name: 'Functions', category: 'Compute', description: 'Serverless functions' },
            kubernetes: { name: 'AKS Clusters', category: 'Compute', description: 'Kubernetes service' },
            
            // Storage Services
            blobstorage: { name: 'Blob Storage', category: 'Storage', description: 'Object storage' },
            filestorage: { name: 'File Storage', category: 'Storage', description: 'File shares' },
            queuestorage: { name: 'Queue Storage', category: 'Storage', description: 'Message queuing' },
            tablestorage: { name: 'Table Storage', category: 'Storage', description: 'NoSQL storage' },
            disks: { name: 'Managed Disks', category: 'Storage', description: 'Block storage' },
            
            // Database Services
            sqldatabase: { name: 'SQL Database', category: 'Database', description: 'Managed SQL database' },
            cosmosdb: { name: 'Cosmos DB', category: 'Database', description: 'Multi-model database' },
            rediscache: { name: 'Redis Cache', category: 'Database', description: 'In-memory cache' },
            postgresql: { name: 'PostgreSQL', category: 'Database', description: 'Managed PostgreSQL' },
            mysql: { name: 'MySQL Database', category: 'Database', description: 'Managed MySQL' },
            
            // Networking Services
            virtualnetworks: { name: 'Virtual Networks', category: 'Networking', description: 'Network isolation' },
            loadbalancers: { name: 'Load Balancers', category: 'Networking', description: 'Traffic distribution' },
            applicationgateway: { name: 'Application Gateway', category: 'Networking', description: 'Web traffic manager' },
            expressroute: { name: 'ExpressRoute', category: 'Networking', description: 'Private connectivity' },
            dns: { name: 'DNS Zones', category: 'Networking', description: 'Domain name system' },
            cdn: { name: 'CDN Profiles', category: 'Networking', description: 'Content delivery network' },
            
            // Security Services
            keyvault: { name: 'Key Vault', category: 'Security', description: 'Secret management' },
            securitycenter: { name: 'Security Center', category: 'Security', description: 'Security monitoring' },
            activedirectory: { name: 'Active Directory', category: 'Security', description: 'Identity services' },
            sentinel: { name: 'Sentinel', category: 'Security', description: 'SIEM solution' },
            
            // AI/ML Services
            cognitiveservices: { name: 'Cognitive Services', category: 'AI/ML', description: 'AI APIs' },
            machinelearning: { name: 'Machine Learning', category: 'AI/ML', description: 'ML platform' },
            botframework: { name: 'Bot Framework', category: 'AI/ML', description: 'Chatbot platform' },
            
            // Development Services
            devops: { name: 'Azure DevOps', category: 'Development', description: 'DevOps platform' },
            logicapps: { name: 'Logic Apps', category: 'Development', description: 'Workflow automation' },
            apimanagement: { name: 'API Management', category: 'Development', description: 'API gateway' },
            
            // Analytics Services
            databricks: { name: 'Databricks', category: 'Analytics', description: 'Data analytics' },
            synapse: { name: 'Synapse Analytics', category: 'Analytics', description: 'Data warehouse' },
            streamanalytics: { name: 'Stream Analytics', category: 'Analytics', description: 'Real-time analytics' },
            
            // Media Services
            mediaservices: { name: 'Media Services', category: 'Media', description: 'Video processing' },
            
            // Management Services
            resourcegroups: { name: 'Resource Groups', category: 'Management', description: 'Resource organization' },
            subscriptions: { name: 'Subscriptions', category: 'Management', description: 'Billing units' },
            policy: { name: 'Policy Definitions', category: 'Management', description: 'Governance' },
            monitor: { name: 'Monitor', category: 'Management', description: 'Monitoring and diagnostics' }
        }
    },
    
    gcp: {
        name: 'Google Cloud Platform',
        icon: '☁️',
        color: '#4285F4',
        services: {
            // Compute Services
            computeengine: { name: 'Compute Engine', category: 'Compute', description: 'Virtual machines' },
            appengine: { name: 'App Engine', category: 'Compute', description: 'Platform as a service' },
            cloudrun: { name: 'Cloud Run', category: 'Compute', description: 'Serverless containers' },
            kubernetes: { name: 'GKE Clusters', category: 'Compute', description: 'Kubernetes service' },
            functions: { name: 'Cloud Functions', category: 'Compute', description: 'Serverless functions' },
            
            // Storage Services
            cloudstorage: { name: 'Cloud Storage', category: 'Storage', description: 'Object storage' },
            cloudfilestore: { name: 'Cloud Filestore', category: 'Storage', description: 'File storage' },
            persistentdisks: { name: 'Persistent Disks', category: 'Storage', description: 'Block storage' },
            
            // Database Services
            cloudsql: { name: 'Cloud SQL', category: 'Database', description: 'Managed databases' },
            firestore: { name: 'Firestore', category: 'Database', description: 'NoSQL database' },
            bigquery: { name: 'BigQuery', category: 'Database', description: 'Data warehouse' },
            spanner: { name: 'Cloud Spanner', category: 'Database', description: 'Global database' },
            datastore: { name: 'Datastore', category: 'Database', description: 'NoSQL database' },
            
            // Networking Services
            vpc: { name: 'VPC Networks', category: 'Networking', description: 'Virtual private clouds' },
            loadbalancing: { name: 'Load Balancing', category: 'Networking', description: 'Traffic distribution' },
            cloudarmor: { name: 'Cloud Armor', category: 'Networking', description: 'DDoS protection' },
            cloudcdn: { name: 'Cloud CDN', category: 'Networking', description: 'Content delivery' },
            clouddns: { name: 'Cloud DNS', category: 'Networking', description: 'DNS service' },
            
            // Security Services
            iam: { name: 'IAM', category: 'Security', description: 'Identity management' },
            securitycommandcenter: { name: 'Security Command Center', category: 'Security', description: 'Security monitoring' },
            binaryauthorization: { name: 'Binary Authorization', category: 'Security', description: 'Deployment security' },
            accesscontextmanager: { name: 'Access Context Manager', category: 'Security', description: 'Context-aware access' },
            
            // AI/ML Services
            aiplatform: { name: 'AI Platform', category: 'AI/ML', description: 'Machine learning' },
            visionapi: { name: 'Vision API', category: 'AI/ML', description: 'Image analysis' },
            speechapi: { name: 'Speech API', category: 'AI/ML', description: 'Speech recognition' },
            naturallanguage: { name: 'Natural Language API', category: 'AI/ML', description: 'Text analysis' },
            translation: { name: 'Translation API', category: 'AI/ML', description: 'Language translation' },
            
            // Development Services
            cloudbuild: { name: 'Cloud Build', category: 'Development', description: 'CI/CD platform' },
            sourcerepositories: { name: 'Source Repositories', category: 'Development', description: 'Git repositories' },
            clouddeploy: { name: 'Cloud Deploy', category: 'Development', description: 'Deployment automation' },
            artifactregistry: { name: 'Artifact Registry', category: 'Development', description: 'Container registry' },
            
            // Analytics Services
            dataproc: { name: 'Dataproc', category: 'Analytics', description: 'Hadoop/Spark clusters' },
            dataflow: { name: 'Dataflow', category: 'Analytics', description: 'Stream processing' },
            pubsub: { name: 'Pub/Sub', category: 'Analytics', description: 'Messaging service' },
            datacatalog: { name: 'Data Catalog', category: 'Analytics', description: 'Data discovery' },
            
            // Management Services
            resourcemanager: { name: 'Resource Manager', category: 'Management', description: 'Resource organization' },
            cloudmonitoring: { name: 'Cloud Monitoring', category: 'Management', description: 'Monitoring service' },
            cloudlogging: { name: 'Cloud Logging', category: 'Management', description: 'Log management' },
            cloudtrace: { name: 'Cloud Trace', category: 'Management', description: 'Distributed tracing' },
            
            // Additional Services
            cloudkms: { name: 'Cloud KMS', category: 'Security', description: 'Key management' },
            cloudtasks: { name: 'Cloud Tasks', category: 'Development', description: 'Task queuing' },
            cloudscheduler: { name: 'Cloud Scheduler', category: 'Development', description: 'Job scheduling' },
            cloudiot: { name: 'Cloud IoT', category: 'AI/ML', description: 'Internet of Things' }
        }
    }
};

// Service categories for filtering
const SERVICE_CATEGORIES = {
    'Compute': '🖥️',
    'Storage': '💾',
    'Database': '🗄️',
    'Networking': '🌐',
    'Security': '🔒',
    'AI/ML': '🤖',
    'Development': '🛠️',
    'Analytics': '📊',
    'Media': '🎬',
    'Management': '⚙️',
    'Messaging': '💬',
    'Containers': '📦'
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { CLOUD_SERVICES, SERVICE_CATEGORIES };
} 