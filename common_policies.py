"""
Common OCI policy templates based on Oracle documentation.
https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/commonpolicies.htm
"""

# Common policy templates by service area
COMMON_POLICIES = {
    # COMPUTE policies
    "compute": {
        "launch_instances": [
            "Allow group {group} to manage instance-family in {scope}",
            "Allow group {group} to manage volume-family in {scope}",
            "Allow group {group} to manage virtual-network-family in {scope}"
        ],
        "manage_instances": [
            "Allow group {group} to manage instance-family in {scope}",
            "Allow group {group} to manage volume-family in {scope}",
            "Allow group {group} to manage virtual-network-family in {scope}",
            "Allow group {group} to inspect compartments in {scope}"
        ],
        "work_with_instances": [
            "Allow group {group} to read instance-family in {scope}",
            "Allow group {group} to read volume-family in {scope}",
            "Allow group {group} to read virtual-network-family in {scope}"
        ]
    },
    
    # STORAGE policies
    "storage": {
        "manage_buckets": [
            "Allow group {group} to manage buckets in {scope}",
            "Allow group {group} to manage objects in {scope}"
        ],
        "read_buckets": [
            "Allow group {group} to read buckets in {scope}",
            "Allow group {group} to read objects in {scope}"
        ],
        "manage_block_volumes": [
            "Allow group {group} to manage volume-family in {scope}"
        ]
    },
    
    # NETWORKING policies
    "networking": {
        "manage_vcns": [
            "Allow group {group} to manage virtual-network-family in {scope}"
        ],
        "read_vcns": [
            "Allow group {group} to read virtual-network-family in {scope}"
        ]
    },
    
    # DATABASE policies
    "database": {
        "manage_databases": [
            "Allow group {group} to manage database-family in {scope}"
        ],
        "read_databases": [
            "Allow group {group} to read database-family in {scope}"
        ]
    },
    
    # IAM policies
    "identity": {
        "manage_users": [
            "Allow group {group} to manage users in {scope}"
        ],
        "manage_groups": [
            "Allow group {group} to manage groups in {scope}"
        ],
        "manage_policies": [
            "Allow group {group} to manage policies in {scope}"
        ],
        "manage_compartments": [
            "Allow group {group} to manage compartments in {scope}"
        ]
    },
    
    # KEY Management policies - based on the OCI Key Policy Reference documentation
    "kms": {
        "manage_keys": [
            "Allow group {group} to manage key-family in {scope}",
            "Allow group {group} to manage vault-family in {scope}"
        ],
        "use_keys": [
            "Allow group {group} to use key-family in {scope}",
            "Allow group {group} to read vault-family in {scope}"
        ],
        "inspect_keys": [
            "Allow group {group} to inspect key-family in {scope}",
            "Allow group {group} to inspect vault-family in {scope}"
        ]
    },
    
    # VAULT/Secret policies
    "vault": {
        "manage_secrets": [
            "Allow group {group} to manage secret-family in {scope}",
            "Allow group {group} to manage vault-family in {scope}"
        ],
        "use_secrets": [
            "Allow group {group} to use secret-family in {scope}",
            "Allow group {group} to read vault-family in {scope}"
        ]
    },
    
    # Certificate Management policies 
    "certificates": {
        "manage_certificates": [
            "Allow group {group} to manage certificate-family in {scope}"
        ],
        "read_certificates": [
            "Allow group {group} to read certificate-family in {scope}"
        ]
    },
    
    # Certificate Authority policies
    "acm-pca": {
        "manage_ca": [
            "Allow group {group} to manage certificate-family in {scope}",
            "Allow group {group} to manage acm-pca in {scope}"
        ],
        "read_ca": [
            "Allow group {group} to read certificate-family in {scope}",
            "Allow group {group} to read acm-pca in {scope}"
        ]
    }
}

# Action to policy type mapping
ACTION_TO_POLICY_TYPE = {
    # Compute
    "ec2:RunInstances": ("compute", "launch_instances"),
    "ec2:StartInstances": ("compute", "manage_instances"),
    "ec2:StopInstances": ("compute", "manage_instances"),
    "ec2:TerminateInstances": ("compute", "manage_instances"),
    "ec2:DescribeInstances": ("compute", "work_with_instances"),
    "ec2:CreateImage": ("compute", "manage_instances"),
    "ec2:DeleteImage": ("compute", "manage_instances"),
    "ec2:CreateVolume": ("compute", "manage_instances"),
    "ec2:DeleteVolume": ("compute", "manage_instances"),
    "ec2:AttachVolume": ("compute", "manage_instances"),
    "ec2:DetachVolume": ("compute", "manage_instances"),
    
    # Storage
    "s3:ListBucket": ("storage", "read_buckets"),
    "s3:GetObject": ("storage", "read_buckets"),
    "s3:PutObject": ("storage", "manage_buckets"),
    "s3:DeleteObject": ("storage", "manage_buckets"),
    "s3:CreateBucket": ("storage", "manage_buckets"),
    "s3:DeleteBucket": ("storage", "manage_buckets"),
    
    # Networking
    "ec2:CreateVpc": ("networking", "manage_vcns"),
    "ec2:DeleteVpc": ("networking", "manage_vcns"),
    "ec2:CreateSubnet": ("networking", "manage_vcns"),
    "ec2:DeleteSubnet": ("networking", "manage_vcns"),
    "ec2:CreateSecurityGroup": ("networking", "manage_vcns"),
    "ec2:DeleteSecurityGroup": ("networking", "manage_vcns"),
    "ec2:CreateRouteTable": ("networking", "manage_vcns"),
    "ec2:DeleteRouteTable": ("networking", "manage_vcns"),
    "ec2:CreateInternetGateway": ("networking", "manage_vcns"),
    "ec2:DeleteInternetGateway": ("networking", "manage_vcns"),
    
    # IAM
    "iam:ListUsers": ("identity", "manage_users"),
    "iam:GetUser": ("identity", "manage_users"),
    "iam:CreateUser": ("identity", "manage_users"),
    "iam:DeleteUser": ("identity", "manage_users"),
    "iam:ListGroups": ("identity", "manage_groups"),
    "iam:GetGroup": ("identity", "manage_groups"),
    "iam:CreateGroup": ("identity", "manage_groups"),
    "iam:DeleteGroup": ("identity", "manage_groups"),
    "iam:ListPolicies": ("identity", "manage_policies"),
    "iam:GetPolicy": ("identity", "manage_policies"),
    "iam:CreatePolicy": ("identity", "manage_policies"),
    "iam:DeletePolicy": ("identity", "manage_policies"),
    
    # KMS (Key Management Service)
    "kms:ListKeys": ("kms", "inspect_keys"),
    "kms:DescribeKey": ("kms", "inspect_keys"),
    "kms:CreateKey": ("kms", "manage_keys"),
    "kms:ScheduleKeyDeletion": ("kms", "manage_keys"),
    "kms:Encrypt": ("kms", "use_keys"),
    "kms:Decrypt": ("kms", "use_keys"),
    "kms:GenerateDataKey": ("kms", "use_keys"),
    "kms:ReEncrypt": ("kms", "use_keys"),
    "kms:EnableKey": ("kms", "manage_keys"),
    "kms:DisableKey": ("kms", "manage_keys"),
    
    # Certificate Authority
    "acm-pca:ListCertificateAuthorities": ("acm-pca", "read_ca"),
    "acm-pca:GetCertificateAuthority": ("acm-pca", "read_ca"),
    "acm-pca:CreateCertificateAuthority": ("acm-pca", "manage_ca"),
    "acm-pca:DeleteCertificateAuthority": ("acm-pca", "manage_ca"),
    "acm-pca:IssueCertificate": ("acm-pca", "manage_ca"),
    "acm-pca:RevokeCertificate": ("acm-pca", "manage_ca"),
    
    # Certificate Manager
    "acm:ListCertificates": ("certificates", "read_certificates"),
    "acm:GetCertificate": ("certificates", "read_certificates"),
    "acm:RequestCertificate": ("certificates", "manage_certificates"),
    "acm:DeleteCertificate": ("certificates", "manage_certificates"),
    "acm:ImportCertificate": ("certificates", "manage_certificates")
}

# AWS service to OCI service area mapping
AWS_SERVICE_TO_AREA = {
    "ec2": "compute",
    "s3": "storage",
    "vpc": "networking",
    "iam": "identity",
    "rds": "database",
    "dynamodb": "database",
    "elb": "networking",
    "lambda": "functions",
    "kms": "security",
    "cloudwatch": "monitoring"
}

def get_common_policies_for_aws_action(aws_action, group_name, scope="tenancy"):
    """
    Get common OCI policies for a given AWS action.
    
    Args:
        aws_action (str): AWS action (e.g., "ec2:RunInstances")
        group_name (str): OCI group name
        scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
    Returns:
        list: List of common OCI policies
    """
    if aws_action in ACTION_TO_POLICY_TYPE:
        service_area, policy_type = ACTION_TO_POLICY_TYPE[aws_action]
        policies = COMMON_POLICIES.get(service_area, {}).get(policy_type, [])
        return [policy.format(group=group_name, scope=scope) for policy in policies]
    
    # If no direct mapping, try to infer from service
    parts = aws_action.split(":")
    if len(parts) >= 2:
        aws_service = parts[0]
        if aws_service in AWS_SERVICE_TO_AREA:
            service_area = AWS_SERVICE_TO_AREA[aws_service]
            # Default to manage policies for the service area
            for policy_type in COMMON_POLICIES.get(service_area, {}):
                if "manage" in policy_type:
                    policies = COMMON_POLICIES[service_area][policy_type]
                    return [policy.format(group=group_name, scope=scope) for policy in policies]
    
    return []

def get_common_policy_set(service_area, policy_type, group_name, scope="tenancy"):
    """
    Get a specific set of common OCI policies.
    
    Args:
        service_area (str): Service area (e.g., "compute", "storage")
        policy_type (str): Policy type (e.g., "launch_instances", "manage_buckets")
        group_name (str): OCI group name
        scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
    Returns:
        list: List of common OCI policies
    """
    policies = COMMON_POLICIES.get(service_area, {}).get(policy_type, [])
    return [policy.format(group=group_name, scope=scope) for policy in policies]
