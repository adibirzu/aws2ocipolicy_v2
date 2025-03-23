from flask import Blueprint, render_template, request, jsonify
import sys, os
import logging
import json

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Import translator first
from translator import translate_simple_policy, translate_advanced_policy, SERVICE_MAPPINGS, OCI_RESOURCE_TYPES
# Import and initialize validators
import validators
validators.SERVICE_MAPPINGS = SERVICE_MAPPINGS
validators.OCI_RESOURCE_TYPES = OCI_RESOURCE_TYPES
from validators import validate_policy
from policy_parser import run_policy_parser
from aws_policy_utils import generate_policy_from_params, get_common_actions_for_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

policy_routes = Blueprint('policy_routes', __name__)

@policy_routes.route('/')
def home():
    return render_template('base.html')

@policy_routes.route('/simple-policy')
def simple_policy():
    return render_template('simple_policy.html')

@policy_routes.route('/advanced-policy/object-storage')
def object_storage_policy():
    return render_template('object_storage.html')

@policy_routes.route('/advanced-policy/compute')
def compute_policy():
    return render_template('compute.html')

@policy_routes.route('/advanced-policy/iam')
def iam_policy():
    return render_template('iam.html')

@policy_routes.route('/service-mappings')
def service_mappings():
    return render_template('service_mappings.html')

@policy_routes.route('/action-mappings')
def action_mappings():
    return render_template('action_mappings.html')

@policy_routes.route('/policy-differences')
def policy_differences():
    return render_template('policy_differences.html')

@policy_routes.route('/aws-policy-generator')
def aws_policy_generator():
    return render_template('aws_policy_generator.html')

@policy_routes.route('/database-api-operations')
def database_api_operations():
    return render_template('database_api_operations.html')

@policy_routes.route('/network-api-operations')
def network_api_operations():
    return render_template('network_api_operations.html')

@policy_routes.route('/security-api-operations')
def security_api_operations():
    return render_template('security_api_operations.html')

@policy_routes.route('/observability-api-operations')
def observability_api_operations():
    return render_template('observability_api_operations.html')

@policy_routes.route('/cloud-guard-oag-api-operations')
def cloud_guard_oag_api_operations():
    return render_template('cloud_guard_oag_api_operations.html')

@policy_routes.route('/devops-api-operations')
def devops_api_operations():
    return render_template('devops_api_operations.html')

@policy_routes.route('/oci-conditions')
def oci_conditions():
    return render_template('oci_conditions.html')

@policy_routes.route('/api/generate-aws-policy', methods=['POST'])
def generate_aws_policy():
    """
    Generates an AWS IAM policy based on the provided parameters
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        effect = data.get("effect", "Allow")
        service = data.get("service", "")
        actions = data.get("actions", [])
        resources = data.get("resources", ["*"])
        conditions = data.get("conditions", [])
        
        # Generate the AWS policy
        aws_policy = generate_policy_from_params(effect, service, actions, resources, conditions)
        logger.info(f"Generated AWS policy for service: {service}")
        
        return jsonify({"policy": aws_policy})
    
    except Exception as e:
        logger.exception(f"Error generating AWS policy: {str(e)}")
        return jsonify({"error": f"Error generating policy: {str(e)}"}), 500

@policy_routes.route('/api/list-service-actions', methods=['GET'])
def list_service_actions():
    """
    Returns a list of common actions for a specified AWS service
    """
    try:
        service = request.args.get('service', '')
        if not service:
            return jsonify({"error": "Service parameter is required"}), 400
            
        actions = get_common_actions_for_service(service)
        return jsonify({"actions": actions})
    
    except Exception as e:
        logger.exception(f"Error retrieving actions for service {service}: {str(e)}")
        return jsonify({"error": f"Error retrieving actions: {str(e)}"}), 500

@policy_routes.route('/oci-reference-policies')
def oci_reference_policies():
    # Try to load policy reference data if it exists
    policy_reference_data = {}
    data_file_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "static", "data", "oci_policy_reference.json"
    )
    
    if os.path.exists(data_file_path):
        try:
            with open(data_file_path, 'r') as f:
                policy_reference_data = json.load(f)
            logger.info(f"Loaded policy reference data from {data_file_path}")
        except Exception as e:
            logger.error(f"Error loading policy reference data: {str(e)}")
    
    return render_template('oci_reference_policies.html', policy_reference_data=policy_reference_data)

@policy_routes.route('/api/generate-simple-policy', methods=['POST'])
def generate_simple_policy():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        aws_policy = data.get("aws_policy", "")
        oci_group = data.get("oci_group", "")
        use_identity_domains = data.get("use_identity_domains", False)
        
        if not aws_policy or not oci_group:
            return jsonify({"error": "Missing required fields: aws_policy and oci_group"}), 400
        
        logger.info(f"Generating simple policy for group: {oci_group}, use_identity_domains: {use_identity_domains}")
        oci_policy = translate_simple_policy(aws_policy, oci_group, use_identity_domains)
        errors = validate_policy(oci_policy)
        
        return jsonify({"policy": oci_policy, "errors": errors})
    
    except Exception as e:
        logger.exception(f"Error generating simple policy: {str(e)}")
        return jsonify({"error": f"Error generating policy: {str(e)}"}), 500

@policy_routes.route('/api/generate-advanced-policy', methods=['POST'])
def generate_advanced_policy():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        aws_policy = data.get("aws_policy", "")
        oci_group = data.get("oci_group", "")
        resource_type = data.get("resource_type", "")
        resource_ocid = data.get("resource_ocid", "")
        
        if not aws_policy or not oci_group:
            return jsonify({"error": "Missing required fields: aws_policy and oci_group"}), 400
        
        logger.info(f"Generating advanced policy for group: {oci_group}, resource type: {resource_type}")
        oci_policy = translate_advanced_policy(aws_policy, oci_group, resource_type, resource_ocid)
        errors = validate_policy(oci_policy)
        
        return jsonify({"policy": oci_policy, "errors": errors})
    
    except Exception as e:
        logger.exception(f"Error generating advanced policy: {str(e)}")
        return jsonify({"error": f"Error generating policy: {str(e)}"}), 500

@policy_routes.route('/api/run-policy-reference-parser', methods=['POST'])
def policy_reference_parser():
    """
    Run the policy reference parser to update the OCI policy reference data
    """
    try:
        logger.info("Running OCI policy reference parser")
        result = run_policy_parser()
        return jsonify(result)
    except Exception as e:
        logger.exception(f"Error running policy reference parser: {str(e)}")
        return jsonify({
            "success": False, 
            "error": f"Error running policy reference parser: {str(e)}"
        }), 500

@policy_routes.route('/api/service-mappings', methods=['GET'])
def get_service_mappings():
    """
    Returns all AWS to OCI service mappings
    """
    try:
        # Format the mappings for display
        formatted_mappings = []
        
        # Group the mappings by category based on Oracle documentation
        categories = {
            "Compute": ["ec2", "auto-scaling", "elastic-beanstalk", "batch", "ecs", "eks", "lightsail", "lambda", "outposts", "fargate"],
            "Storage": ["s3", "s3-glacier", "ebs", "efs", "storage-gateway", "backup"],
            "Database": ["rds", "dynamodb", "elasticache", "redshift", "neptune", "timestream", "documentdb", "keyspaces"],
            "Networking & Content Delivery": ["vpc", "cloudfront", "route53", "direct-connect", "api-gateway", "global-accelerator", "transit-gateway", "app-mesh", "cloud-map", "elb", "cloudmap"],
            "Security, Identity & Compliance": ["iam", "organizations", "cognito", "directory-service", "acm", "kms", "secrets-manager", "cloudhsm", "guardduty", "inspector", "artifact", "security-hub", "shield", "waf"],
            "Management & Governance": ["cloudwatch", "cloudtrail", "config", "cloud-formation", "systems-manager", "cloudmap", "license-manager", "control-tower", "service-catalog", "app-config", "cost-explorer", "trusted-advisor"],
            "Analytics": ["athena", "emr", "cloudsearch", "elasticsearch", "kinesis", "data-pipeline", "quicksight", "data-exchange", "glue", "lake-formation", "msk"],
            "Integration": ["sns", "sqs", "eventbridge", "step-functions", "mq", "appsync"],
            "Developer Tools": ["codestar", "codecommit", "codepipeline", "codebuild", "codedeploy", "cloud9", "x-ray"]
        }
        
        for category, services in categories.items():
            category_mappings = []
            for service in services:
                if service in SERVICE_MAPPINGS:
                    category_mappings.append({
                        "aws_service": service,
                        "aws_service_name": get_aws_service_full_name(service),
                        "oci_service": SERVICE_MAPPINGS[service],
                        "oci_service_name": get_oci_service_full_name(SERVICE_MAPPINGS[service])
                    })
            
            formatted_mappings.append({
                "category": category,
                "mappings": category_mappings
            })
            
        # Also include the flat mapping for API consumers
        flat_mappings = {aws: oci for aws, oci in SERVICE_MAPPINGS.items()}
        
        return jsonify({
            "categorized_mappings": formatted_mappings,
            "mappings": flat_mappings
        })
        
    except Exception as e:
        logger.exception(f"Error retrieving service mappings: {str(e)}")
        return jsonify({"error": f"Error retrieving service mappings: {str(e)}"}), 500

def get_aws_service_full_name(short_name):
    """Helper function to get the full AWS service name"""
    aws_service_names = {
        # Compute
        "ec2": "Amazon EC2",
        "auto-scaling": "AWS Auto Scaling",
        "elastic-beanstalk": "AWS Elastic Beanstalk",
        "batch": "AWS Batch",
        "ecs": "Amazon ECS",
        "eks": "Amazon EKS",
        "lightsail": "Amazon Lightsail",
        "lambda": "AWS Lambda",
        "outposts": "AWS Outposts",
        "fargate": "AWS Fargate",
        
        # Storage
        "s3": "Amazon S3",
        "s3-glacier": "Amazon S3 Glacier",
        "ebs": "Amazon EBS",
        "efs": "Amazon EFS",
        "storage-gateway": "AWS Storage Gateway",
        "backup": "AWS Backup",
        
        # Database
        "rds": "Amazon RDS",
        "dynamodb": "Amazon DynamoDB",
        "elasticache": "Amazon ElastiCache",
        "redshift": "Amazon Redshift",
        "neptune": "Amazon Neptune",
        "timestream": "Amazon Timestream",
        "documentdb": "Amazon DocumentDB",
        "keyspaces": "Amazon Keyspaces",
        
        # Networking & Content Delivery
        "vpc": "Amazon VPC",
        "cloudfront": "Amazon CloudFront",
        "route53": "Amazon Route 53",
        "direct-connect": "AWS Direct Connect",
        "api-gateway": "Amazon API Gateway",
        "global-accelerator": "AWS Global Accelerator",
        "transit-gateway": "AWS Transit Gateway",
        "app-mesh": "AWS App Mesh",
        "cloud-map": "AWS Cloud Map",
        "elb": "Elastic Load Balancing",
        "cloudmap": "AWS Cloud Map",
        
        # Security, Identity & Compliance
        "iam": "AWS IAM",
        "organizations": "AWS Organizations",
        "cognito": "Amazon Cognito",
        "directory-service": "AWS Directory Service",
        "acm": "AWS Certificate Manager",
        "kms": "AWS KMS",
        "secrets-manager": "AWS Secrets Manager",
        "cloudhsm": "AWS CloudHSM",
        "guardduty": "Amazon GuardDuty",
        "inspector": "Amazon Inspector",
        "artifact": "AWS Artifact",
        "security-hub": "AWS Security Hub",
        "shield": "AWS Shield",
        "waf": "AWS WAF",
        
        # Management & Governance
        "cloudwatch": "Amazon CloudWatch",
        "cloudtrail": "AWS CloudTrail",
        "config": "AWS Config",
        "cloud-formation": "AWS CloudFormation",
        "systems-manager": "AWS Systems Manager",
        "license-manager": "AWS License Manager",
        "control-tower": "AWS Control Tower",
        "service-catalog": "AWS Service Catalog",
        "app-config": "AWS AppConfig",
        "cost-explorer": "AWS Cost Explorer",
        "trusted-advisor": "AWS Trusted Advisor",
        
        # Analytics
        "athena": "Amazon Athena",
        "emr": "Amazon EMR",
        "cloudsearch": "Amazon CloudSearch",
        "elasticsearch": "Amazon Elasticsearch Service",
        "kinesis": "Amazon Kinesis",
        "data-pipeline": "AWS Data Pipeline",
        "quicksight": "Amazon QuickSight",
        "data-exchange": "AWS Data Exchange",
        "glue": "AWS Glue",
        "lake-formation": "AWS Lake Formation",
        "msk": "Amazon MSK",
        
        # Integration
        "sns": "Amazon SNS",
        "sqs": "Amazon SQS",
        "eventbridge": "Amazon EventBridge",
        "step-functions": "AWS Step Functions",
        "mq": "Amazon MQ",
        "appsync": "AWS AppSync",
        
        # Developer Tools
        "codestar": "AWS CodeStar",
        "codecommit": "AWS CodeCommit",
        "codepipeline": "AWS CodePipeline",
        "codebuild": "AWS CodeBuild",
        "codedeploy": "AWS CodeDeploy",
        "cloud9": "AWS Cloud9",
        "x-ray": "AWS X-Ray"
    }
    return aws_service_names.get(short_name, f"AWS {short_name.title()}")

def get_oci_service_full_name(short_name):
    """Helper function to get the full OCI service name"""
    oci_service_names = {
        # Compute
        "compute": "OCI Compute",
        "instance-pools": "OCI Instance Pools",
        "resource-manager": "OCI Resource Manager",
        "batch": "OCI Batch Service",
        "container-engine": "OCI Container Engine",
        "container-engine-kubernetes": "OCI Container Engine for Kubernetes",
        "functions": "OCI Functions",
        "dedicated-region": "OCI Dedicated Region",
        "container-instances": "OCI Container Instances",
        
        # Storage
        "object-storage": "OCI Object Storage",
        "archive-storage": "OCI Archive Storage",
        "block-volume": "OCI Block Volume",
        "file-storage": "OCI File Storage",
        "storage-gateway": "OCI Storage Gateway",
        "backup-service": "OCI Backup Service",
        
        # Database
        "database": "OCI Database",
        "nosql-database": "OCI NoSQL Database",
        "cache": "OCI Cache",
        "autonomous-data-warehouse": "OCI Autonomous Data Warehouse",
        "graph-studio": "OCI Graph Studio",
        "mysql-heatwave": "OCI MySQL HeatWave",
        
        # Networking
        "vcn": "OCI Virtual Cloud Network",
        "cdn": "OCI Content Delivery Network",
        "dns": "OCI DNS",
        "fastconnect": "OCI FastConnect",
        "api-gateway": "OCI API Gateway",
        "waf": "OCI Web Application Firewall",
        "drg": "OCI Dynamic Routing Gateway",
        "service-mesh": "OCI Service Mesh",
        "load-balancer": "OCI Load Balancer",
        
        # Security & Identity
        "identity": "OCI Identity and Access Management",
        "compartments": "OCI Compartments",
        "identity-cloud-service": "OCI Identity Cloud Service",
        "identity-domains": "OCI Identity Domains",
        "certificates": "OCI Certificates",
        "vault": "OCI Vault",
        "dedicated-vault": "OCI Dedicated Vault",
        "cloud-guard": "OCI Cloud Guard",
        "vulnerability-scanning": "OCI Vulnerability Scanning",
        "compliance": "OCI Compliance",
        "security-advisor": "OCI Security Advisor",
        "web-application-firewall": "OCI Web Application Firewall",
        
        # Management
        "monitoring": "OCI Monitoring",
        "audit": "OCI Audit",
        "operations-insights": "OCI Operations Insights",
        "license-manager": "OCI License Manager",
        "security-zones": "OCI Security Zones",
        "marketplace": "OCI Marketplace",
        "cost-analysis": "OCI Cost Analysis",
        "optimizer": "OCI Optimizer",
        
        # Analytics
        "data-science": "OCI Data Science",
        "data-flow": "OCI Data Flow",
        "search-service": "OCI Search Service",
        "streaming": "OCI Streaming",
        "data-integration": "OCI Data Integration",
        "analytics-cloud": "OCI Analytics Cloud",
        "data-catalog": "OCI Data Catalog",
        
        # Integration
        "notifications": "OCI Notifications",
        "queue": "OCI Queue",
        "events-service": "OCI Events Service",
        "workflow": "OCI Workflow",
        
        # Developer Tools
        "devops": "OCI DevOps",
        "cloud-shell": "OCI Cloud Shell",
        "application-performance-monitoring": "OCI Application Performance Monitoring"
    }
    return oci_service_names.get(short_name, f"OCI {short_name.replace('-', ' ').title()}")
