import json
import logging
import re

logger = logging.getLogger(__name__)

# AWS to OCI service mappings based on Oracle documentation
# Source: https://docs.oracle.com/en/solutions/oci-for-aws-professionals/
SERVICE_MAPPINGS = {
    # Compute
    "ec2": "compute",
    "auto-scaling": "instance-pools",
    "elastic-beanstalk": "resource-manager",
    "batch": "batch",
    "ecs": "container-engine",
    "ecr": "container-registry", # Added ECR mapping
    "eks": "container-engine-kubernetes",
    "lightsail": "compute",
    "lambda": "functions",
    "outposts": "dedicated-region",
    "fargate": "container-instances",
    
    # Storage
    "s3": "object-storage",
    "s3-glacier": "archive-storage",
    "s3express": "object-storage", # Added S3 Express mapping
    "ebs": "block-volume",
    "efs": "file-storage",
    "elasticfilesystem": "file-storage", # Added explicit EFS mapping
    "storage-gateway": "storage-gateway",
    "backup": "backup-service",
    
    # Database
    "rds": "database",
    "dynamodb": "nosql-database",
    "elasticache": "cache",
    "redshift": "autonomous-data-warehouse",
    "neptune": "graph-studio",
    "timestream": "mysql-heatwave",
    "documentdb": "mysql-heatwave",
    "keyspaces": "nosql-database",
    
    # Networking & Content Delivery
    "vpc": "vcn",
    "cloudfront": "cdn",
    "route53": "dns",
    "direct-connect": "fastconnect",
    "api-gateway": "api-gateway",
    "global-accelerator": "waf",
    "transit-gateway": "drg",
    "app-mesh": "service-mesh",
    "cloud-map": "service-mesh",
    "elb": "load-balancer",
    "cloudmap": "dns",
    
    # Security, Identity & Compliance
    "iam": "identity",
    "organizations": "identity", # Changed from compartments to identity
    "cognito": "identity-cloud-service",
    "directory-service": "identity-domains",
    "acm": "certificates",
    "kms": "vault",
    "secrets-manager": "vault",
    "secretsmanager": "vault", # Added explicit SecretManager mapping
    "cloudhsm": "dedicated-vault",
    "guardduty": "cloud-guard",
    "inspector": "vulnerability-scanning",
    "artifact": "compliance",
    "security-hub": "security-advisor",
    "shield": "waf-protection",
    "waf": "web-application-firewall",
    
    # Management & Governance
    "cloudwatch": "monitoring",
    "cloudtrail": "audit",
    "config": "resource-manager",
    "cloud-formation": "resource-manager",
    "systems-manager": "operations-insights",
    "cloudmap": "resource-manager",
    "license-manager": "license-manager",
    "control-tower": "security-zones",
    "service-catalog": "marketplace",
    "app-config": "resource-manager",
    "cost-explorer": "cost-analysis",
    "trusted-advisor": "optimizer",
    
    # Analytics
    "athena": "data-science",
    "emr": "data-flow",
    "cloudsearch": "search-service",
    "elasticsearch": "search-service",
    "kinesis": "streaming",
    "data-pipeline": "data-integration",
    "quicksight": "analytics-cloud",
    "data-exchange": "data-catalog",
    "glue": "data-integration",
    "lake-formation": "data-catalog",
    "msk": "streaming",
    
    # Integration
    "sns": "notification-service", # Changed to notification-service
    "notifications": "notification-service", # Added explicit notifications mapping
    "sqs": "streaming", # Changed from queue to streaming
    "queue": "streaming", # Added explicit queue mapping
    "eventbridge": "events-service",
    "step-functions": "workflow",
    "mq": "streaming",
    "appsync": "api-gateway",
    
    # Developer Tools
    "codestar": "devops",
    "codecommit": "devops",
    "codepipeline": "devops",
    "codebuild": "devops",
    "codedeploy": "devops",
    "cloud9": "cloud-shell",
    "x-ray": "application-performance-monitoring"
}

# OCI resource types based on official documentation
# Source: https://docs.oracle.com/en-us/iaas/Content/Identity/policyreference/corepolicyreference_topic-ResourceTypes.htm
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
        "capacity-reservation",
        "capacity-reservation-instance",
        "boot-volume-backup",
        "volume-backup",
        "boot-volume",
        "volume",
        "volume-group",
        "volume-group-backup",
        "compute-management"
    ],
    
    # Object Storage resources
    "object-storage": [
        "object",
        "bucket",
        "namespace",
        "multipart-upload",
        "preauthrequest"
    ],
    
    # Networking resources
    "vcn": [
        "vcn",
        "subnet",
        "security-list",
        "route-table",
        "dhcp-options",
        "internet-gateway",
        "network-security-group",
        "network-security-group-security-rule",
        "nat-gateway",
        "drg",
        "drg-attachment",
        "local-peering-gateway",
        "public-ip",
        "cpe",
        "ip-sec-connection",
        "ipv6",
        "vlan",
        "vtap",
        "service-gateway"
    ],
    
    # Load Balancer resources
    "load-balancer": [
        "load-balancer",
        "backend-set",
        "certificate",
        "backend",
        "listener",
        "path-route-set",
        "hostname",
        "rule-set",
        "listener-rule-set"
    ],
    
    # Database resources
    "database": [
        "database",
        "db-system",
        "db-home",
        "db-node",
        "backup",
        "autonomous-database",
        "autonomous-container-database",
        "autonomous-backup",
        "autonomous-vm-cluster",
        "cloud-vm-cluster",
        "exadata-infrastructure",
        "key-store",
        "cloud-exadata-infrastructure"
    ],
    
    # Identity resources
    "identity": [
        "user",
        "group",
        "dynamic-group",
        "policy",
        "tag-namespace",
        "tag",
        "compartment",
        "authentication-policy",
        "network-source"
    ],
    
    # Functions resources
    "functions": [
        "function",
        "application"
    ],
    
    # Vault resources (KMS)
    "vault": [
        "vault",
        "key",
        "secret"
    ],
    
    # Nosql Database resources
    "nosql-database": [
        "table",
        "index",
        "row"
    ],
    
    # File Storage resources
    "file-storage": [
        "file-system",
        "mount-target",
        "export-set",
        "export",
        "snapshot"
    ],
    
    # Container Registry resources (ECR equivalent)
    "container-registry": [
        "repository",
        "image"
    ],
    
    # Notification Service resources
    "notification-service": [
        "topic",
        "subscription"
    ],
    
    # Streaming Service resources (SQS/Queue equivalent)
    "streaming": [
        "stream",
        "stream-pool",
        "connect-harness",
        "message"
    ],
    
    # All resources type for universal access
    "all-resources": []
}

# AWS action to OCI verb and resource mappings
ACTION_MAPPINGS = {
    # Object Storage
    "s3:ListBucket": ("inspect", "object-storage", "bucket"),
    "s3:GetObject": ("read", "object-storage", "object"),
    "s3:PutObject": ("manage", "object-storage", "object"),
    "s3:DeleteObject": ("manage", "object-storage", "object"),
    "s3:CreateBucket": ("manage", "object-storage", "bucket"),
    "s3:DeleteBucket": ("manage", "object-storage", "bucket"),
    
    # Compute
    "ec2:DescribeInstances": ("inspect", "compute", "instance"),
    "ec2:RunInstances": ("manage", "compute", "instance"),
    "ec2:StartInstances": ("use", "compute", "instance"),
    "ec2:StopInstances": ("use", "compute", "instance"),
    "ec2:TerminateInstances": ("manage", "compute", "instance"),
    "ec2:CreateImage": ("manage", "compute", "image"),
    "ec2:DescribeImages": ("inspect", "compute", "image"),
    "ec2:DeleteImage": ("manage", "compute", "image"),
    "ec2:CreateVolume": ("manage", "compute", "volume"),
    "ec2:DeleteVolume": ("manage", "compute", "volume"),
    "ec2:AttachVolume": ("manage", "compute", "volume"),
    "ec2:DetachVolume": ("manage", "compute", "volume"),
    
    # Networking
    "ec2:CreateVpc": ("manage", "vcn", "vcn"),
    "ec2:DeleteVpc": ("manage", "vcn", "vcn"),
    "ec2:CreateSubnet": ("manage", "vcn", "subnet"),
    "ec2:DeleteSubnet": ("manage", "vcn", "subnet"),
    "ec2:CreateSecurityGroup": ("manage", "vcn", "network-security-group"),
    "ec2:DeleteSecurityGroup": ("manage", "vcn", "network-security-group"),
    "ec2:CreateRouteTable": ("manage", "vcn", "route-table"),
    "ec2:DeleteRouteTable": ("manage", "vcn", "route-table"),
    "ec2:CreateInternetGateway": ("manage", "vcn", "internet-gateway"),
    "ec2:DeleteInternetGateway": ("manage", "vcn", "internet-gateway"),
    "ec2:AllocateAddress": ("manage", "vcn", "public-ip"),
    "ec2:ReleaseAddress": ("manage", "vcn", "public-ip"),
    
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
    
    # EFS/File Storage
    "elasticfilesystem:CreateFileSystem": ("manage", "file-storage", "file-system"),
    "elasticfilesystem:DeleteFileSystem": ("manage", "file-storage", "file-system"),
    "elasticfilesystem:DescribeFileSystems": ("inspect", "file-storage", "file-system"),
    "elasticfilesystem:CreateMountTarget": ("manage", "file-storage", "mount-target"),
    "elasticfilesystem:DeleteMountTarget": ("manage", "file-storage", "mount-target"),
    
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

def translate_simple_policy(aws_policy_json, oci_group_name):
    """
    Translates a simple AWS policy to an OCI policy.
    
    Args:
        aws_policy_json (str): AWS policy JSON as a string
        oci_group_name (str): OCI group name
        
    Returns:
        str: OCI policy statements as a string
    """
    try:
        aws_policy = json.loads(aws_policy_json)
        statements = aws_policy.get("Statement", [])
        
        # Handle case where Statement is a single object instead of an array
        if not isinstance(statements, list):
            statements = [statements]
            
        # Group actions by verb and resource to consolidate policies
        policy_groups = {}
        
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
            condition_str = build_conditions(conditions, None, None)
            
            for action in actions:
                # Map AWS action to OCI verb and resource
                verb, resource = map_action(action)
                
                # Create a key to group similar policies
                key = (verb, resource, condition_str)
                
                if key not in policy_groups:
                    policy_groups[key] = True
        
        # Build consolidated policies
        oci_policies = []
        compartment_scope = "tenancy"
        
        for (verb, resource, condition_str), _ in policy_groups.items():
            policy = f"Allow group {oci_group_name} to {verb} {resource} in {compartment_scope}"
            
            if condition_str:
                policy += f" where {condition_str}"
                
            if policy not in oci_policies:  # Avoid duplicates
                oci_policies.append(policy)
                
        return "\n".join(oci_policies)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse AWS policy: {aws_policy_json}")
        raise ValueError("Invalid AWS policy JSON format")
    except Exception as e:
        logger.exception(f"Error translating simple policy: {str(e)}")
        raise

def parse_aws_action(action):
    """
    Parses an AWS action into service and operation components.
    
    Args:
        action (str): AWS action (e.g., "s3:GetObject")
        
    Returns:
        tuple: (service, operation) pair
    """
    parts = action.split(":")
    if len(parts) >= 2:
        return parts[0], parts[1]
    else:
        return "", action

def translate_advanced_policy(aws_policy_json, oci_group_name, resource_type, resource_ocid):
    """
    Translates an AWS policy to an OCI policy with advanced conditions.
    
    Args:
        aws_policy_json (str): AWS policy JSON as a string
        oci_group_name (str): OCI group name
        resource_type (str): OCI resource type
        resource_ocid (str): OCI resource OCID
        
    Returns:
        str: OCI policy statements as a string
    """
    try:
        aws_policy = json.loads(aws_policy_json)
        statements = aws_policy.get("Statement", [])
        
        # Handle case where Statement is a single object instead of an array
        if not isinstance(statements, list):
            statements = [statements]
            
        oci_policies = []
        
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
            condition_str = build_conditions(conditions, resource_type, resource_ocid)
            
            for action in actions:
                verb, resource = map_action(action)
                policy = f"Allow group {oci_group_name} to {verb} {resource} in tenancy"
                
                if condition_str:
                    policy += f" where {condition_str}"
                    
                if policy not in oci_policies:  # Avoid duplicates
                    oci_policies.append(policy)
                
        return "\n".join(oci_policies)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse AWS policy: {aws_policy_json}")
        raise ValueError("Invalid AWS policy JSON format")
    except Exception as e:
        logger.exception(f"Error translating advanced policy: {str(e)}")
        raise

def map_action(action):
    """
    Maps an AWS action to OCI verb and resource.
    
    Args:
        action (str): AWS action (e.g., "s3:GetObject")
        
    Returns:
        tuple: (verb, resource) pair for OCI policy
    """
    # Extract service from action
    parts = action.split(":")
    aws_service = parts[0] if len(parts) >= 2 else ""
    
    # Map AWS service to OCI service
    oci_service = SERVICE_MAPPINGS.get(aws_service, aws_service)
    
    # Check for exact matches first
    if action in ACTION_MAPPINGS:
        verb, service, resource_type = ACTION_MAPPINGS[action]
        
        # Format the resource string based on resource type
        if resource_type:
            resource = f"{service} {resource_type}"
        else:
            resource = service
            
        return (verb, resource)
    
    # Try pattern matching
    for pattern, mapping in ACTION_MAPPINGS.items():
        if "*" in pattern:
            regex_pattern = pattern.replace("*", ".*")
            if re.match(regex_pattern, action):
                verb, service_pattern, resource_pattern = mapping
                
                # Replace {service} placeholder with actual OCI service name
                service = service_pattern.replace("{service}", oci_service)
                
                # For generic mappings, use the actual service
                if not resource_pattern:
                    return (verb, service)
                
                # Otherwise, combine service and resource
                resource = f"{service} {resource_pattern}"
                return (verb, resource)
    
    # Default fallback
    logger.warning(f"No mapping found for action: {action}, using default")
    return ("use", oci_service)

# Sample OCIDs for testing - in a real implementation, these would come from actual OCI resources
SAMPLE_OCIDS = {
    "compartment": "ocid1.compartment.oc1..aaaaaaaaxuysohm7szz7epkxmxfz3wm5kyjurec3znvcprcokfp74h6rzaza",
    "user": "ocid1.user.oc1..aaaaaaaafmmxeov47iujhxpgvogeagn5i6ksdhjjgwcfwz5fvhi2qvgvj4za",
    "group": "ocid1.group.oc1..aaaaaaaahnwrjwylulraxvpofycm52xuq4gl6ravxqbovxbxwi3fz6mw2cta",
    "bucket": "ocid1.bucket.oc1.iad.aaaaaaaaqjtzeqzigym5q74fudtnvsmf4zkzgpwsz7lhgviwmzpnz35krr4a",
    "instance": "ocid1.instance.oc1.iad.aaaaaaaav2kjpnx2rxufvh23wp5dnxtercoelkzpm6omisdb3gc7zxevhba"
}

def build_conditions(conditions, resource_type, resource_ocid):
    """
    Builds OCI policy conditions from AWS conditions.
    
    Args:
        conditions (dict): AWS policy conditions
        resource_type (str): OCI resource type
        resource_ocid (str): OCI resource OCID
        
    Returns:
        str: OCI condition string
    """
    if not conditions:
        return ""
    
    conds = []
    
    # Handle resource constraints with proper OCID
    if resource_ocid and resource_type:
        # Validate the OCID format
        from validators import validate_resource_ocid
        if validate_resource_ocid(resource_ocid):
            conds.append(f"target.{resource_type}.id = '{resource_ocid}'")
        else:
            logger.warning(f"Invalid OCID format: {resource_ocid}. This may result in invalid policy conditions.")
            conds.append(f"target.{resource_type}.id = '{resource_ocid}'")
    
    # Process standard condition operators
    for operator, content in conditions.items():
        for key, values in content.items():
            # Map AWS condition keys to OCI condition variables
            
            # Object Storage specific conditions
            if key.startswith("s3:"):
                if key == "s3:prefix":
                    if isinstance(values, str):
                        values = [values]
                    prefix_conds = " or ".join([f"request.object.name.startsWith('{v}')" for v in values])
                    conds.append(f"({prefix_conds})")
                elif key == "s3:max-keys":
                    if operator == "NumericLessThanEquals":
                        conds.append(f"request.object.fetch.max <= {values}")
                elif key == "s3:delimiter":
                    if isinstance(values, str):
                        values = [values]
                    delimiter_conds = " or ".join([f"request.object.delimiter = '{v}'" for v in values])
                    conds.append(f"({delimiter_conds})")
            
            # IP address conditions
            elif key == "aws:SourceIp":
                if isinstance(values, str):
                    values = [values]
                ip_conds = " or ".join([f"request.ipAddress = '{v}'" for v in values])
                conds.append(f"({ip_conds})")
            
            # Date/time conditions
            elif key == "aws:CurrentTime":
                if operator == "DateGreaterThan":
                    conds.append(f"request.time > '{values}'")
                elif operator == "DateLessThan":
                    conds.append(f"request.time < '{values}'")
                elif operator == "DateGreaterThanEquals":
                    conds.append(f"request.time >= '{values}'")
                elif operator == "DateLessThanEquals":
                    conds.append(f"request.time <= '{values}'")
            
            # Tag-based conditions
            elif key.startswith("aws:TagKeys") or key.startswith("aws:ResourceTag/") or key.startswith("aws:RequestTag/"):
                if operator in ["StringEquals", "StringEqualsIfExists"]:
                    if isinstance(values, str):
                        values = [values]
                    tag_name = key.replace("aws:ResourceTag/", "").replace("aws:RequestTag/", "")
                    tag_conds = " or ".join([f"target.resource.tag.{tag_name} = '{v}'" for v in values])
                    conds.append(f"({tag_conds})")
            
            # Principal/User identity conditions
            elif key in ["aws:PrincipalArn", "aws:PrincipalAccount", "aws:UserId", "aws:username"]:
                if operator == "StringEquals":
                    if isinstance(values, str):
                        values = [values]
                    
                    # Use appropriate OCI condition variable based on AWS key
                    if key == "aws:PrincipalArn":
                        # Replace AWS ARN with OCI principal format
                        principal_conds = " or ".join([f"request.principal.id = 'ocid1.user.oc1..example'" for v in values])
                        conds.append(f"({principal_conds})")
                    elif key == "aws:PrincipalAccount":
                        principal_conds = " or ".join([f"request.principal.type = 'user'" for v in values])
                        conds.append(f"({principal_conds})")
                    elif key == "aws:UserId":
                        user_conds = " or ".join([f"request.user.id = '{SAMPLE_OCIDS['user']}'" for v in values])
                        conds.append(f"({user_conds})")
                    elif key == "aws:username":
                        user_conds = " or ".join([f"request.user.name = '{v}'" for v in values])
                        conds.append(f"({user_conds})")
            
            # Secure transport condition
            elif key == "aws:SecureTransport":
                if operator == "Bool":
                    if isinstance(values, bool):
                        secure_value = 'true' if values else 'false'
                        conds.append(f"request.secure = '{secure_value}'")
                    elif isinstance(values, str):
                        secure_value = values.lower()
                        if secure_value in ['true', 'false']:
                            conds.append(f"request.secure = '{secure_value}'")
            
            # VPC/VCN conditions
            elif key == "aws:SourceVpc":
                if isinstance(values, str):
                    values = [values]
                # Map AWS VPC IDs to OCI VCN OCIDs
                vcn_conds = " or ".join([f"request.networkSource.vcnId = '{SAMPLE_OCIDS.get('vcn', 'ocid1.vcn.oc1.iad.example')}'" for v in values])
                conds.append(f"({vcn_conds})")
            
            elif key == "aws:SourceVpce":
                if isinstance(values, str):
                    values = [values]
                # VPC Endpoints don't have a direct equivalent in OCI, map to network sources
                vpce_conds = " or ".join([f"request.networkSource.type = 'VCN_SUBNET'" for v in values])
                conds.append(f"({vpce_conds})")
            
            # Resource type condition
            elif key == "aws:ResourceType":
                if isinstance(values, str):
                    values = [values]
                
                # Map AWS resource types to OCI resource types
                aws_to_oci_resource_type = {
                    "AWS::S3::Bucket": "object-storage.bucket",
                    "AWS::EC2::Instance": "compute.instance",
                    "AWS::IAM::User": "identity.user",
                    "AWS::IAM::Role": "identity.group",
                    "AWS::DynamoDB::Table": "nosql-database.table",
                    "AWS::Lambda::Function": "functions.function",
                    "AWS::RDS::DBInstance": "database.db-system"
                }
                
                mapped_values = [aws_to_oci_resource_type.get(v, f"resource.type.{v}") for v in values]
                type_conds = " or ".join([f"target.resource.type = '{v}'" for v in mapped_values])
                conds.append(f"({type_conds})")
            
            # Resource ARN conditions - convert to OCI resource OCIDs
            elif key == "aws:ResourceArn" or key.startswith("arn:aws:"):
                if operator in ["StringEquals", "ArnEquals", "ArnLike"]:
                    if isinstance(values, str):
                        values = [values]
                    
                    # Convert AWS ARNs to OCI resource references
                    resource_conds = []
                    for arn in values:
                        # Parse ARN to identify resource type
                        if arn.startswith("arn:aws:s3:::"):
                            # S3 bucket ARN
                            bucket_name = arn.split(":")[-1]
                            resource_conds.append(f"target.object-storage.bucket.name = '{bucket_name}'")
                        elif arn.startswith("arn:aws:ec2:"):
                            # EC2 instance ARN
                            resource_conds.append(f"target.compute.instance.id = '{SAMPLE_OCIDS['instance']}'")
                        elif arn.startswith("arn:aws:iam:"):
                            # IAM resource ARN
                            if ":user/" in arn:
                                resource_conds.append(f"target.identity.user.id = '{SAMPLE_OCIDS['user']}'")
                            elif ":role/" in arn:
                                resource_conds.append(f"target.identity.group.id = '{SAMPLE_OCIDS['group']}'")
                        else:
                            # Generic resource reference
                            resource_conds.append(f"target.resource.id = 'ocid1.resource.oc1..example'")
                    
                    if resource_conds:
                        conds.append("(" + " or ".join(resource_conds) + ")")
    
    # If we have multiple conditions, join them with AND
    if conds:
        return " and ".join(conds)
    else:
        return ""
