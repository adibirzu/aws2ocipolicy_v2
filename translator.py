import json
import logging
import re
from common_policies import get_common_policies_for_aws_action, get_common_policy_set
from oci_policy_templates import get_template_for_aws_service, OCIPolicyTemplates

logger = logging.getLogger(__name__)

# AWS to OCI service mappings based on Oracle documentation
# Sources:
# - https://docs.oracle.com/en/solutions/oci-for-aws-professionals/
# - https://docs.oracle.com/en-us/iaas/Content/services.htm
# - https://aws.amazon.com/products/
SERVICE_MAPPINGS = {
    # Compute
    "ec2": "compute",
    "auto-scaling": "instance-pools",
    "elastic-beanstalk": "resource-manager",
    "ecs": "container-engine",
    "ecr": "container-registry",
    "eks": "container-engine-kubernetes",
    "lightsail": "instances",
    "lambda": "functions",
    "outposts": "dedicated-region",
    "fargate": "container-instances",
    "server-less": "functions",
    "app-runner": "container-instances",
    "ec2-auto-scaling": "instance-pools",
    
    # Storage
    "s3": "object-storage",
    "s3-glacier": "object-storage",
    "s3express": "object-storage",
    "ebs": "block-volume",
    "efs": "file-storage",
    "elasticfilesystem": "file-storage",
    "storage-gateway": "storage-gateway",
    "backup": "disaster-recovery",
    "fsx": "file-storage",
    "snow-family": "data-transfer",
    "aws-backup": "disaster-recovery",
    "cloudendure-disaster-recovery": "disaster-recovery",
    
    # Database
    "rds": "database",
    "dynamodb": "nosql-database",
    "elasticache": "cache",
    "redshift": "autonomous-data-warehouse",
    "neptune": "graph-studio",
    "timestream": "mysql-heatwave",
    "documentdb": "mysql-heatwave",
    "keyspaces": "nosql-database",
    "memorydb": "cache",
    "database-migration-service": "database-migration",
    "quantum-ledger-database": "blockchain",
    "aurora": "mysql-heatwave",
    "qldb": "blockchain",
    "opensearch-service": "search-service",
    
    # Security, Identity & Compliance
    "iam": "identity",
    "organizations": "identity",
    "cognito": "identity-cloud-service",
    "directory-service": "identity-domains",
    "acm": "certificates", # Certificate Manager
    "acm-pca": "acm-pca", # Certificate Authority (CA) service
    "kms": "kms", # Key Management
    "secrets-manager": "vault", # Secrets Management
    "secretsmanager": "vault", # Alternative name for Secrets Manager
    "cloudhsm": "kms", # Hardware Security Modules (HSM)
    "guardduty": "cloud-guard",
    "inspector": "vulnerability-scanning",
    "artifact": "compliance",
    "security-hub": "security-advisor",
    "shield": "waf-protection",
    "waf": "web-application-firewall",
    
    # Networking & Content Delivery
    "vpc": "vcn",
    "cloudfront": "cdn",
    "route53": "dns",
    "direct-connect": "fastconnect",
    "api-gateway": "api-gateway",
    "elb": "load-balancer",
    
    # Management & Governance
    "cloudwatch": "monitoring",
    "cloudtrail": "audit",
    "config": "resource-manager",
    "cloud-formation": "resource-manager",
    "systems-manager": "operations-insights",
    "cloudmap": "resource-manager",
    "license-manager": "license-manager",
    
    # Analytics
    "athena": "data-science",
    "emr": "data-flow",
    "kinesis": "streaming",
    "data-pipeline": "data-integration",
    "glue": "data-integration",
    
    # Integration
    "sns": "notifications",
    "notifications": "notifications",
    "sqs": "queue",
    "queue": "queue",
    "eventbridge": "events",
    "step-functions": "functions",
    
    # Other
    "all-services": "all-resources"
}

# OCI resource types based on official documentation
OCI_RESOURCE_TYPES = {
    # Compute resources
    "compute": [
        "compute-cluster",
        "cluster-network",
        "dedicated-vm-host",
        "image",
        "instance",
        "instance-family",
        "instance-pool",
        "volume",
        "volume-family",
        "boot-volume",
        "volume-backup"
    ],
    
    # Object Storage resources
    "object-storage": [
        "object",
        "bucket",
        "namespace"
    ],
    
    # Networking resources
    "vcn": [
        "vcn",
        "subnet",
        "security-list",
        "route-table",
        "internet-gateway",
        "network-security-group",
        "drg",
        "public-ip"
    ],
    
    # Database resources
    "database": [
        "database",
        "db-system",
        "db-home",
        "backup"
    ],
    
    # Identity resources
    "identity": [
        "user",
        "group",
        "dynamic-group",
        "policy",
        "compartment"
    ],
    
    # Functions resources
    "functions": [
        "function",
        "application"
    ],
    
    # All resources type for universal access
    "all-resources": []
}

# AWS action to OCI verb and resource mappings - Based on CorePolicyReference
ACTION_MAPPINGS = {
    # Object Storage
    "s3:ListBucket": ("inspect", "object-storage", "buckets"),
    "s3:GetObject": ("read", "object-storage", "objects"),
    "s3:PutObject": ("manage", "object-storage", "objects"),
    "s3:DeleteObject": ("manage", "object-storage", "objects"),
    "s3:CreateBucket": ("manage", "object-storage", "buckets"),
    "s3:DeleteBucket": ("manage", "object-storage", "buckets"),
    
    # Compute - uses plural 'instances' per CorePolicyReference
    "ec2:DescribeInstances": ("inspect", "compute", "instances"),
    "ec2:RunInstances": ("manage", "compute", "instances"),
    "ec2:StartInstances": ("use", "compute", "instances"),
    "ec2:StopInstances": ("use", "compute", "instances"),
    "ec2:TerminateInstances": ("manage", "compute", "instances"),
    "ec2:CreateImage": ("manage", "compute", "images"),
    "ec2:DescribeImages": ("inspect", "compute", "images"),
    "ec2:DeleteImage": ("manage", "compute", "images"),
    "ec2:CreateVolume": ("manage", "block-volume", "volumes"),
    "ec2:DeleteVolume": ("manage", "block-volume", "volumes"),
    "ec2:AttachVolume": ("manage", "block-volume", "volumes"),
    "ec2:DetachVolume": ("manage", "block-volume", "volumes"),
    
    # Networking - using correct CorePolicyReference resources
    "ec2:CreateVpc": ("manage", "vcn", "virtual-networks"),
    "ec2:DeleteVpc": ("manage", "vcn", "virtual-networks"),
    "ec2:CreateSubnet": ("manage", "vcn", "subnets"),
    "ec2:DeleteSubnet": ("manage", "vcn", "subnets"),
    "ec2:CreateSecurityGroup": ("manage", "vcn", "network-security-groups"),
    "ec2:DeleteSecurityGroup": ("manage", "vcn", "network-security-groups"),
    "ec2:CreateRouteTable": ("manage", "vcn", "route-tables"),
    "ec2:DeleteRouteTable": ("manage", "vcn", "route-tables"),
    "ec2:CreateInternetGateway": ("manage", "vcn", "internet-gateways"),
    "ec2:DeleteInternetGateway": ("manage", "vcn", "internet-gateways"),
    "ec2:AllocateAddress": ("manage", "vcn", "public-ips"),
    "ec2:ReleaseAddress": ("manage", "vcn", "public-ips"),
    
    # IAM
    "iam:ListRoles": ("inspect", "identity", "group"),
    "iam:GetRole": ("read", "identity", "group"),
    "iam:CreateRole": ("manage", "identity", "group"),
    "iam:DeleteRole": ("manage", "identity", "group"),
    "iam:ListUsers": ("inspect", "identity", "user"),
    "iam:GetUser": ("read", "identity", "user"),
    "iam:CreateUser": ("manage", "identity", "user"),
    "iam:DeleteUser": ("manage", "identity", "user"),
    "iam:ListGroups": ("inspect", "identity", "group"),
    "iam:GetGroup": ("read", "identity", "group"),
    "iam:CreateGroup": ("manage", "identity", "group"),
    "iam:DeleteGroup": ("manage", "identity", "group"),
    "iam:CreatePolicy": ("manage", "identity", "policy"),
    "iam:DeletePolicy": ("manage", "identity", "policy"),
    "iam:GetPolicy": ("read", "identity", "policy"),
    "iam:ListPolicies": ("inspect", "identity", "policy"),
    
    # Database
    "rds:DescribeDBInstances": ("inspect", "database", "db-system"),
    "rds:CreateDBInstance": ("manage", "database", "db-system"),
    "rds:DeleteDBInstance": ("manage", "database", "db-system"),
    "rds:StartDBInstance": ("use", "database", "db-system"),
    "rds:StopDBInstance": ("use", "database", "db-system"),
    "rds:CreateDBSnapshot": ("manage", "database", "backup"),
    "rds:DeleteDBSnapshot": ("manage", "database", "backup"),
    
    # Lambda/Functions
    "lambda:ListFunctions": ("inspect", "functions", "function"),
    "lambda:GetFunction": ("read", "functions", "function"),
    "lambda:CreateFunction": ("manage", "functions", "function"),
    "lambda:DeleteFunction": ("manage", "functions", "function"),
    "lambda:InvokeFunction": ("use", "functions", "function"),
    "lambda:UpdateFunctionCode": ("manage", "functions", "function"),
    
    # KMS/Vault
    "kms:ListKeys": ("inspect", "vault", "key"),
    "kms:DescribeKey": ("read", "vault", "key"),
    "kms:CreateKey": ("manage", "vault", "key"),
    "kms:ScheduleKeyDeletion": ("manage", "vault", "key"),
    "kms:Encrypt": ("use", "vault", "key"),
    "kms:Decrypt": ("use", "vault", "key"),
    
    # DynamoDB/NoSQL
    "dynamodb:ListTables": ("inspect", "nosql-database", "table"),
    "dynamodb:DescribeTable": ("read", "nosql-database", "table"),
    "dynamodb:CreateTable": ("manage", "nosql-database", "table"),
    "dynamodb:DeleteTable": ("manage", "nosql-database", "table"),
    "dynamodb:GetItem": ("read", "nosql-database", "row"),
    "dynamodb:PutItem": ("manage", "nosql-database", "row"),
    "dynamodb:DeleteItem": ("manage", "nosql-database", "row"),
    
    # Generic patterns
    "*:List*": ("inspect", "{service}", ""),
    "*:Get*": ("read", "{service}", ""),
    "*:Describe*": ("inspect", "{service}", ""),
    "*:Create*": ("manage", "{service}", ""),
    "*:Delete*": ("manage", "{service}", ""),
    "*:Update*": ("manage", "{service}", ""),
    "*:Put*": ("manage", "{service}", ""),
    "*:*": ("manage", "all-resources", "")
}

# Import the build_conditions function for policy conditions
from validators import build_conditions

# OCI resource type mappings for common services based on CorePolicyReference
SERVICE_TO_RESOURCE_TYPE = {
    # Core Services
    "compute": "instances", # CorePolicyReference uses plural 'instances'
    "block-volume": "volumes", # For Block Volume
    "object-storage": "objects",
    "object-storage-bucket": "buckets", # For bucket operations
    "file-storage": "file-systems",
    "vcn": "virtual-networks",
    "subnet": "subnets",
    "security-list": "security-lists",
    "network-security-group": "network-security-groups",
    "load-balancer": "load-balancers",
    
    # Database
    "database": "databases",
    "autonomous-database": "autonomous-databases",
    "mysql": "mysql-db-systems",
    "nosql-database": "tables",
    
    # Identity
    "identity": "users", # Default to users, but can be overridden
    "identity-group": "groups",
    "identity-policy": "policies",
    "identity-compartment": "compartments",
    
    # Others
    "functions": "functions",
    "vault": "keys",
    "monitoring": "alarms",
    "audit": "audit-events",
    "events": "rules",
    "notifications": "topics"
}

def translate_simple_policy(aws_policy_json, oci_group_name, use_identity_domains=False, identity_domain_name=None, use_templates=True):
    """
    Translates a simple AWS policy to an OCI policy using OCI Common Policy format.
    Uses Oracle's official common policy templates by default.
    
    Args:
        aws_policy_json (str): AWS policy JSON as a string
        oci_group_name (str): OCI group name
        use_identity_domains (bool): Whether to use Identity Domains policy format
        identity_domain_name (str, optional): Identity domain name for domain-specific policies
        use_templates (bool): Whether to use Oracle's Common Policy templates (default: True)
        
    Returns:
        str: OCI policy statements as a string
    """
    try:
        aws_policy = json.loads(aws_policy_json)
        statements = aws_policy.get("Statement", [])
        
        # Handle case where Statement is a single object instead of an array
        if not isinstance(statements, list):
            statements = [statements]
        
        # Process each statement to generate appropriate OCI policies
        oci_policies = set()  # Use a set to avoid duplicates
        compartment_scope = "tenancy"  # Default scope
        
        # Track services mentioned across all statements
        all_aws_services = set()
        
        # First pass: collect all AWS services used in policy
        for stmt in statements:
            # Process actions
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
                
            for action in actions:
                parts = action.split(":")
                aws_service = parts[0] if len(parts) >= 2 else ""
                if aws_service:
                    all_aws_services.add(aws_service)
        
        # If use_templates is enabled and we have AWS services, use comprehensive templates
        if use_templates and all_aws_services:
            # For each AWS service, get the appropriate OCI policy template
            for aws_service in all_aws_services:
                template_policies = get_template_for_aws_service(aws_service, oci_group_name, compartment_scope)
                for policy in template_policies:
                    oci_policies.add(policy)
            
            # Return the comprehensive template policies
            if oci_policies:
                return "\n".join(oci_policies)
        
        # If template approach didn't work or is disabled, use previous approach
        for stmt in statements:
            effect = stmt.get("Effect", "")
            if effect.lower() != "allow":
                logger.warning(f"Non-Allow effect encountered in policy: {effect}. OCI only supports Allow policies.")
                continue
            
            # Process actions
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            
            # Process resources
            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
            
            # Extract verbs and services from actions
            for action in actions:
                # First, try to use common policy templates from the mapping
                common_policies = get_common_policies_for_aws_action(action, oci_group_name, compartment_scope)
                
                # If common policies are found, add them to the result list
                if common_policies:
                    for policy in common_policies:
                        oci_policies.add(policy)
                else:
                    # Extract service from action for custom policy generation
                    parts = action.split(":")
                    aws_service = parts[0] if len(parts) >= 2 else ""
                    
                    # Map AWS service to OCI service
                    oci_service = SERVICE_MAPPINGS.get(aws_service, aws_service)
                    
                    # For EC2 services, prefer resource-family approach
                    if aws_service == "ec2":
                        if "RunInstances" in action or "Instance" in action:
                            # Use instance-family for compute operations
                            policy = f"Allow group {oci_group_name} to manage instance-family in {compartment_scope}"
                            oci_policies.add(policy)
                            # Add volume-family access for instance operations
                            policy = f"Allow group {oci_group_name} to manage volume-family in {compartment_scope}"
                            oci_policies.add(policy)
                            # Add networking access for instance operations
                            policy = f"Allow group {oci_group_name} to manage virtual-network-family in {compartment_scope}"
                            oci_policies.add(policy)
                        elif "Describe" in action:
                            # Read access for describe operations
                            policy = f"Allow group {oci_group_name} to read instance-family in {compartment_scope}"
                            oci_policies.add(policy)
                            policy = f"Allow group {oci_group_name} to read volume-family in {compartment_scope}"
                            oci_policies.add(policy)
                            policy = f"Allow group {oci_group_name} to read virtual-network-family in {compartment_scope}"
                            oci_policies.add(policy)
                        else:
                            # Fallback to mapped action using resource families when possible
                            if "Volume" in action:
                                policy = f"Allow group {oci_group_name} to manage volume-family in {compartment_scope}"
                                oci_policies.add(policy)
                            elif "Vpc" in action or "NetworkInterface" in action or "SecurityGroup" in action:
                                policy = f"Allow group {oci_group_name} to manage virtual-network-family in {compartment_scope}"
                                oci_policies.add(policy)
                            else:
                                # Generic compute permission with instance-family
                                policy = f"Allow group {oci_group_name} to manage instance-family in {compartment_scope}"
                                oci_policies.add(policy)
                    
                    # For S3 services, use bucket and object permissions
                    elif aws_service == "s3":
                        if "Get" in action or "List" in action:
                            policy = f"Allow group {oci_group_name} to read buckets in {compartment_scope}"
                            oci_policies.add(policy)
                            policy = f"Allow group {oci_group_name} to read objects in {compartment_scope}"
                            oci_policies.add(policy)
                        else:
                            policy = f"Allow group {oci_group_name} to manage buckets in {compartment_scope}"
                            oci_policies.add(policy)
                            policy = f"Allow group {oci_group_name} to manage objects in {compartment_scope}"
                            oci_policies.add(policy)
                    
                    # For IAM services
                    elif aws_service == "iam":
                        if "User" in action:
                            policy = f"Allow group {oci_group_name} to manage users in {compartment_scope}"
                            oci_policies.add(policy)
                        elif "Group" in action:
                            policy = f"Allow group {oci_group_name} to manage groups in {compartment_scope}"
                            oci_policies.add(policy)
                        elif "Policy" in action:
                            policy = f"Allow group {oci_group_name} to manage policies in {compartment_scope}"
                            oci_policies.add(policy)
                        else:
                            policy = f"Allow group {oci_group_name} to manage users in {compartment_scope}"
                            oci_policies.add(policy)
                    
                    # Fallback for all other actions to the original mapping approach
                    else:
                        # Map AWS action to OCI verb and determine resource type
                        if action in ACTION_MAPPINGS:
                            verb, service, action_resource_type = ACTION_MAPPINGS[action]
                        elif "Describe" in action or "List" in action or "Get" in action:
                            verb = "read"
                            service = oci_service
                        else:
                            # Default fallback - assume manage permission
                            verb = "manage"
                            service = oci_service
                        
                        # Create the OCI policy statement with resource family if available
                        if service == "compute":
                            policy = f"Allow group {oci_group_name} to {verb} instance-family in {compartment_scope}"
                        elif service == "block-volume":
                            policy = f"Allow group {oci_group_name} to {verb} volume-family in {compartment_scope}"
                        elif service == "vcn":
                            policy = f"Allow group {oci_group_name} to {verb} virtual-network-family in {compartment_scope}"
                        elif service == "database":
                            policy = f"Allow group {oci_group_name} to {verb} database-family in {compartment_scope}"
                        else:
                            policy = f"Allow group {oci_group_name} to {verb} {service} in {compartment_scope}"
                        
                        oci_policies.add(policy)
        
        # Return joined policies
        return "\n".join(oci_policies)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse AWS policy: {aws_policy_json}")
        raise ValueError("Invalid AWS policy JSON format")
    except Exception as e:
        logger.exception(f"Error translating simple policy: {str(e)}")
        raise

def translate_advanced_policy(aws_policy_json, oci_group_name, resource_type, resource_ocid):
    """
    Translates an AWS policy to an OCI policy with advanced conditions 
    targeting specific resources by OCID.
    
    Args:
        aws_policy_json (str): AWS policy JSON as a string
        oci_group_name (str): OCI group name
        resource_type (str): OCI resource type (e.g., "instance", "bucket")
        resource_ocid (str): OCI resource OCID to target in the policy
        
    Returns:
        str: OCI policy statements as a string
    """
    try:
        aws_policy = json.loads(aws_policy_json)
        statements = aws_policy.get("Statement", [])
        
        # Handle case where Statement is a single object instead of an array
        if not isinstance(statements, list):
            statements = [statements]
            
        # Process each statement to generate appropriate OCI policies
        oci_policies = []
        compartment_scope = "tenancy"  # Default scope
            
        for stmt in statements:
            effect = stmt.get("Effect", "")
            if effect.lower() != "allow":
                logger.warning(f"Non-Allow effect encountered in policy: {effect}. OCI only supports Allow policies.")
                continue
                
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
                
            resources = stmt.get("Resource", ["*"])
            if isinstance(resources, str):
                resources = [resources]
                
            conditions = stmt.get("Condition", {})
            
            # Extract verbs and services from actions
            for action in actions:
                # Extract service from action
                parts = action.split(":")
                aws_service = parts[0] if len(parts) >= 2 else ""
                
                # Map AWS service to OCI service
                oci_service = SERVICE_MAPPINGS.get(aws_service, aws_service)
                
                # Map AWS action to OCI verb
                if action in ACTION_MAPPINGS:
                    verb, service, _ = ACTION_MAPPINGS[action]
                elif aws_service == "ec2" and "Describe" in action:
                    verb = "inspect"
                    service = "compute"
                else:
                    # Default fallback - assume manage permission
                    verb = "manage"
                    service = oci_service
                
                # Map AWS action to OCI verb and determine resource type
                specific_resource_type = resource_type  # Use user-provided resource type
                if action in ACTION_MAPPINGS:
                    verb, service, action_resource_type = ACTION_MAPPINGS[action]
                    if not specific_resource_type:
                        specific_resource_type = action_resource_type if action_resource_type else SERVICE_TO_RESOURCE_TYPE.get(service)
                elif aws_service == "ec2" and "Describe" in action:
                    verb = "inspect"
                    service = "compute"
                    if not specific_resource_type:
                        specific_resource_type = "instance-family"
                else:
                    # Default fallback - assume manage permission
                    verb = "manage"
                    service = oci_service
                    if not specific_resource_type:
                        specific_resource_type = SERVICE_TO_RESOURCE_TYPE.get(service)
                
                # Create the OCI policy statement with resource type if available
                if specific_resource_type:
                    oci_policy = f"Allow group {oci_group_name} to {verb} {service} {specific_resource_type} in {compartment_scope}"
                else:
                    oci_policy = f"Allow group {oci_group_name} to {verb} {service} in {compartment_scope}"
                
                # Add OCID-specific condition if provided
                if resource_ocid and specific_resource_type:
                    oci_policy += f" where target.{specific_resource_type}.id = '{resource_ocid}'"
                
                # Add policy if not duplicate
                if oci_policy not in oci_policies:
                    oci_policies.append(oci_policy)
                
        return "\n".join(oci_policies)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse AWS policy: {aws_policy_json}")
        raise ValueError("Invalid AWS policy JSON format")
    except Exception as e:
        logger.exception(f"Error translating advanced policy: {str(e)}")
        raise

# Sample OCIDs for testing
SAMPLE_OCIDS = {
    "compartment": "ocid1.compartment.oc1..aaaaaaaaxuysohm7szz7epkxmxfz3wm5kyjurec3znvcprcokfp74h6rzaza",
    "user": "ocid1.user.oc1..aaaaaaaafmmxeov47iujhxpgvogeagn5i6ksdhjjgwcfwz5fvhi2qvgvj4za",
    "group": "ocid1.group.oc1..aaaaaaaahnwrjwylulraxvpofycm52xuq4gl6ravxqbovxbxwi3fz6mw2cta",
    "bucket": "ocid1.bucket.oc1.iad.aaaaaaaaqjtzeqzigym5q74fudtnvsmf4zkzgpwsz7lhgviwmzpnz35krr4a",
    "instance": "ocid1.instance.oc1.iad.aaaaaaaav2kjpnx2rxufvh23wp5dnxtercoelkzpm6omisdb3gc7zxevhba",
    "vcn": "ocid1.vcn.oc1.iad.aaaaaaaajnyvvuugodbpermajwvchsydyjk5khjul2sdzphecqnmh6tlkceq"
}
