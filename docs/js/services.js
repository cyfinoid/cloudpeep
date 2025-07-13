// services.js
// Broad service catalog for UI, service selection, and scanning coverage (PeekInTheCloud)
// This file is distinct from js/service-metadata.js, which contains detailed security/permission metadata.
// Use this file for listing, filtering, and categorizing cloud services in the UI.

// Service category icons
const SERVICE_CATEGORIES = {
    'Compute': '🖥️',
    'Storage': '💾',
    'Database': '🗄️',
    'Networking': '🌐',
    'Security': '🔒',
    'Analytics': '📊',
    'Media': '🎬',
    'AI/ML': '🤖',
    'Development': '🛠️',
    'Management': '⚙️',
    'Messaging': '💬',
    'Containers': '📦'
};

// Cloud Service Metadata
const CLOUD_SERVICES = {
    aws: {
        name: 'Amazon Web Services',
        icon: '☁️',
        color: '#FF9900',
        services: {
            // Compute Services
            ec2: { 
                name: 'EC2 Instances', 
                category: 'Compute', 
                description: 'Virtual servers',
                icon: 'icons/aws/ec2.svg'
            },
            lambda: { 
                name: 'Lambda Functions', 
                category: 'Compute', 
                description: 'Serverless functions',
                icon: 'icons/aws/lambda.svg'
            },
            ecs: { 
                name: 'ECS Clusters', 
                category: 'Compute', 
                description: 'Container orchestration',
                icon: 'icons/aws/ecs.svg'
            },
            eks: { 
                name: 'EKS Clusters', 
                category: 'Compute', 
                description: 'Kubernetes service',
                icon: 'icons/aws/eks.svg'
            },
            elasticbeanstalk: { 
                name: 'Elastic Beanstalk', 
                category: 'Compute', 
                description: 'Platform as a service',
                icon: 'icons/aws/elasticbeanstalk.svg'
            },
            emr: { 
                name: 'EMR Clusters', 
                category: 'Compute', 
                description: 'Big data processing',
                icon: 'icons/aws/emr.svg'
            },
            
            // Storage Services
            s3: { 
                name: 'S3 Buckets', 
                category: 'Storage', 
                description: 'Object storage',
                icon: 'icons/aws/s3.svg'
            },
            efs: { 
                name: 'EFS File Systems', 
                category: 'Storage', 
                description: 'File storage',
                icon: 'icons/aws/efs.svg'
            },
            storagegateway: { 
                name: 'Storage Gateway', 
                category: 'Storage', 
                description: 'Hybrid storage',
                icon: 'icons/aws/storagegateway.svg'
            },
            
            // Database Services
            rds: { 
                name: 'RDS Instances', 
                category: 'Database', 
                description: 'Managed databases',
                icon: 'icons/aws/rds.svg'
            },
            dynamodb: { 
                name: 'DynamoDB Tables', 
                category: 'Database', 
                description: 'NoSQL database',
                icon: 'icons/aws/dynamodb.svg'
            },
            redshift: { 
                name: 'Redshift Clusters', 
                category: 'Database', 
                description: 'Data warehouse',
                icon: 'icons/aws/redshift.svg'
            },
            elasticache: { 
                name: 'ElastiCache Clusters', 
                category: 'Database', 
                description: 'In-memory caching',
                icon: 'icons/aws/elasticache.svg'
            },
            athena: { 
                name: 'Athena Workgroups', 
                category: 'Database', 
                description: 'Query service',
                icon: 'icons/aws/athena.svg'
            },
            
            // Networking Services
            vpc: { 
                name: 'VPCs', 
                category: 'Networking', 
                description: 'Virtual private clouds',
                icon: 'icons/aws/vpc.svg'
            },
            subnets: { 
                name: 'Subnets', 
                category: 'Networking', 
                description: 'Network subnets',
                icon: 'icons/aws/subnets.svg'
            },
            securitygroups: { 
                name: 'Security Groups', 
                category: 'Networking', 
                description: 'Firewall rules',
                icon: 'icons/aws/securitygroups.svg'
            },
            route53: { 
                name: 'Route53 Zones', 
                category: 'Networking', 
                description: 'DNS service',
                icon: 'icons/aws/route53.svg'
            },
            apigateway: { 
                name: 'API Gateway', 
                category: 'Networking', 
                description: 'API management',
                icon: 'icons/aws/apigateway.svg'
            },
            cloudfront: { 
                name: 'CloudFront Distributions', 
                category: 'Networking', 
                description: 'CDN service',
                icon: 'icons/aws/cloudfront.svg'
            },
            
            // Security Services
            iam: { 
                name: 'IAM Users/Roles', 
                category: 'Security', 
                description: 'Identity management',
                icon: 'icons/aws/iam.svg'
            },
            cloudtrail: { 
                name: 'CloudTrail Trails', 
                category: 'Security', 
                description: 'Audit logging',
                icon: 'icons/aws/cloudtrail.svg'
            },
            secretsmanager: { 
                name: 'Secrets Manager', 
                category: 'Security', 
                description: 'Secret management',
                icon: 'icons/aws/secretsmanager.svg'
            },
            detective: { 
                name: 'Detective Graphs', 
                category: 'Security', 
                description: 'Security analytics',
                icon: 'icons/aws/detective.svg'
            },
            
            // Analytics Services
            kinesis: { 
                name: 'Kinesis Streams', 
                category: 'Analytics', 
                description: 'Real-time streaming',
                icon: 'icons/aws/kinesis.svg'
            },
            glue: { 
                name: 'Glue Data Catalogs', 
                category: 'Analytics', 
                description: 'Data catalog',
                icon: 'icons/aws/glue.svg'
            },
            stepfunctions: { 
                name: 'Step Functions', 
                category: 'Analytics', 
                description: 'Workflow orchestration',
                icon: 'icons/aws/stepfunctions.svg'
            },
            cloudwatch: { 
                name: 'CloudWatch Alarms', 
                category: 'Analytics', 
                description: 'Monitoring',
                icon: 'icons/aws/cloudwatch.svg'
            },
            
            // Media Services
            mediaconvert: { 
                name: 'MediaConvert Jobs', 
                category: 'Media', 
                description: 'Video processing',
                icon: 'icons/aws/mediaconvert.svg'
            },
            medialive: { 
                name: 'MediaLive Channels', 
                category: 'Media', 
                description: 'Live streaming',
                icon: 'icons/aws/medialive.svg'
            },
            mediapackage: { 
                name: 'MediaPackage Channels', 
                category: 'Media', 
                description: 'Video delivery',
                icon: 'icons/aws/mediapackage.svg'
            },
            elastictranscoder: { 
                name: 'Elastic Transcoder', 
                category: 'Media', 
                description: 'Video transcoding',
                icon: 'icons/aws/elastictranscoder.svg'
            },
            
            // AI/ML Services
            sagemaker: { 
                name: 'SageMaker Notebooks', 
                category: 'AI/ML', 
                description: 'Machine learning',
                icon: 'icons/aws/sagemaker.svg'
            },
            lex: { 
                name: 'Lex Bots', 
                category: 'AI/ML', 
                description: 'Conversational AI',
                icon: 'icons/aws/lex.svg'
            },
            iot: { 
                name: 'IoT Things', 
                category: 'AI/ML', 
                description: 'Internet of Things',
                icon: 'icons/aws/iot.svg'
            },
            
            // Development Services
            codepipeline: { 
                name: 'CodePipeline', 
                category: 'Development', 
                description: 'CI/CD pipeline',
                icon: 'icons/aws/codepipeline.svg'
            },
            codecommit: { 
                name: 'CodeCommit Repositories', 
                category: 'Development', 
                description: 'Git repositories',
                icon: 'icons/aws/codecommit.svg'
            },
            cloud9: { 
                name: 'Cloud9 Environments', 
                category: 'Development', 
                description: 'Cloud IDE',
                icon: 'icons/aws/cloud9.svg'
            },
            ssm: { 
                name: 'SSM Documents', 
                category: 'Development', 
                description: 'Systems Manager',
                icon: 'icons/aws/ssm.svg'
            },
            
            // Management Services
            cloudformation: { 
                name: 'CloudFormation Stacks', 
                category: 'Management', 
                description: 'Infrastructure as code',
                icon: 'icons/aws/cloudformation.svg'
            },
            organizations: { 
                name: 'Organizations', 
                category: 'Management', 
                description: 'Account management',
                icon: 'icons/aws/organizations.svg'
            },
            backup: { 
                name: 'Backup Plans', 
                category: 'Management', 
                description: 'Backup service',
                icon: 'icons/aws/backup.svg'
            },
            
            // Messaging Services
            sns: { 
                name: 'SNS Topics', 
                category: 'Messaging', 
                description: 'Pub/sub messaging',
                icon: 'icons/aws/sns.svg'
            },
            sqs: { 
                name: 'SQS Queues', 
                category: 'Messaging', 
                description: 'Message queuing',
                icon: 'icons/aws/sqs.svg'
            },
            
            // Container Services
            ecr: { 
                name: 'ECR Repositories', 
                category: 'Containers', 
                description: 'Container registry',
                icon: 'icons/aws/ecr.svg'
            },
            
            // Additional Services
            appsync: { 
                name: 'AppSync APIs', 
                category: 'Development', 
                description: 'GraphQL service',
                icon: 'icons/aws/appsync.svg'
            },
            datapipeline: { 
                name: 'Data Pipeline', 
                category: 'Analytics', 
                description: 'Data processing',
                icon: 'icons/aws/datapipeline.svg'
            },
            workspaces: { 
                name: 'WorkSpaces', 
                category: 'Compute', 
                description: 'Virtual desktops',
                icon: 'icons/aws/workspaces.svg'
            },
            datasync: { 
                name: 'DataSync Tasks', 
                category: 'Storage', 
                description: 'Data transfer',
                icon: 'icons/aws/datasync.svg'
            },
            pinpoint: { 
                name: 'Pinpoint Applications', 
                category: 'Messaging', 
                description: 'Mobile engagement',
                icon: 'icons/aws/pinpoint.svg'
            },
            mq: { 
                name: 'MQ Brokers', 
                category: 'Messaging', 
                description: 'Message broker',
                icon: 'icons/aws/mq.svg'
            },
            opsworks: { 
                name: 'OpsWorks Stacks', 
                category: 'Management', 
                description: 'Configuration management',
                icon: 'icons/aws/opsworks.svg'
            },
            appmesh: { 
                name: 'App Mesh Meshes', 
                category: 'Networking', 
                description: 'Service mesh',
                icon: 'icons/aws/appmesh.svg'
            },
            mediastore: { 
                name: 'MediaStore Containers', 
                category: 'Media', 
                description: 'Media storage',
                icon: 'icons/aws/mediastore.svg'
            },
            serverlessrepo: { 
                name: 'Serverless Repo', 
                category: 'Development', 
                description: 'Application repository',
                icon: 'icons/aws/serverlessrepo.svg'
            }
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

// Make constants globally available
window.CLOUD_SERVICES = CLOUD_SERVICES;
window.SERVICE_CATEGORIES = SERVICE_CATEGORIES; 