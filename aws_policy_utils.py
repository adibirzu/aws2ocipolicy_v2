"""
AWS Policy Generation Utilities

This module provides utilities for generating AWS IAM policies.
It converts user input from the web interface into properly formatted AWS policies.
"""

import json
from awspolicy import Statement, PolicyBase, KmsPolicy, BucketPolicy, IamRoleTrustPolicy

def generate_policy_from_params(effect, service, actions, resources, conditions=None):
    """
    Generate an AWS IAM policy document from the provided parameters
    
    Args:
        effect (str): The effect of the policy ("Allow" or "Deny")
        service (str): The AWS service (e.g., "s3", "ec2", "iam")
        actions (list): List of actions to include (e.g., ["s3:GetObject", "s3:PutObject"])
        resources (list): List of resources ARNs (or ["*"] for all resources)
        conditions (list, optional): List of condition dictionaries with operator, key, and value
            Example: [{"operator": "StringEquals", "key": "aws:SourceIp", "value": "203.0.113.0/24"}]
            
    Returns:
        str: The generated policy document as a JSON string
    """
    # Create a basic policy structure
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": effect,
                "Action": actions,
                "Resource": resources
            }
        ]
    }
    
    # Add conditions if provided
    if conditions and len(conditions) > 0:
        condition_block = {}
        
        for condition in conditions:
            operator = condition.get("operator")
            key = condition.get("key")
            value = condition.get("value")
            
            if operator and key and value:
                if operator not in condition_block:
                    condition_block[operator] = {}
                
                condition_block[operator][key] = value
        
        if condition_block:
            policy["Statement"][0]["Condition"] = condition_block
    
    # Return the policy as a formatted JSON string
    return json.dumps(policy, indent=2)

def generate_resource_based_policy(effect, service, actions, principal_type, principal_value, resources, conditions=None):
    """
    Generate a resource-based AWS IAM policy (like bucket policies, role trust relationships)
    
    Args:
        effect (str): The effect of the policy ("Allow" or "Deny")
        service (str): The AWS service (e.g., "s3", "lambda", "iam")
        actions (list): List of actions to include
        principal_type (str): Type of principal ("AWS", "Service", etc.)
        principal_value (str): Value of principal (account ID, service name)
        resources (list): List of resources ARNs
        conditions (list, optional): List of condition dictionaries
            
    Returns:
        str: The generated policy document as a JSON string
    """
    # Create a basic policy structure with Principal
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": effect,
                "Principal": {
                    principal_type: principal_value
                },
                "Action": actions,
                "Resource": resources
            }
        ]
    }
    
    # Add conditions if provided
    if conditions and len(conditions) > 0:
        condition_block = {}
        
        for condition in conditions:
            operator = condition.get("operator")
            key = condition.get("key")
            value = condition.get("value")
            
            if operator and key and value:
                if operator not in condition_block:
                    condition_block[operator] = {}
                
                condition_block[operator][key] = value
        
        if condition_block:
            policy["Statement"][0]["Condition"] = condition_block
    
    # Return the policy as a formatted JSON string
    return json.dumps(policy, indent=2)

def get_common_actions_for_service(service):
    """
    Returns common actions for a given AWS service
    
    Args:
        service (str): The AWS service name (e.g., "s3", "ec2", "iam")
        
    Returns:
        list: List of common actions for the service
    """
    service_actions = {
        # S3 related actions
        's3': [
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
            's3:ListBucket',
            's3:CreateBucket',
            's3:DeleteBucket',
            's3:GetBucketPolicy',
            's3:PutBucketPolicy',
            's3:GetBucketLocation',
            's3:ListAllMyBuckets',
            's3:GetObjectTagging',
            's3:PutObjectTagging'
        ],
        
        # EC2 related actions
        'ec2': [
            'ec2:DescribeInstances',
            'ec2:RunInstances',
            'ec2:StartInstances',
            'ec2:StopInstances',
            'ec2:TerminateInstances',
            'ec2:CreateImage',
            'ec2:DescribeImages',
            'ec2:DeleteImage',
            'ec2:CreateVolume',
            'ec2:DeleteVolume',
            'ec2:AttachVolume',
            'ec2:DetachVolume',
            'ec2:DescribeVolumes',
            'ec2:CreateTags',
            'ec2:DeleteTags'
        ],
        
        # IAM related actions
        'iam': [
            'iam:CreateUser',
            'iam:DeleteUser',
            'iam:GetUser',
            'iam:ListUsers',
            'iam:CreateGroup',
            'iam:DeleteGroup',
            'iam:GetGroup',
            'iam:ListGroups',
            'iam:CreateRole',
            'iam:DeleteRole',
            'iam:GetRole',
            'iam:ListRoles',
            'iam:CreatePolicy',
            'iam:DeletePolicy',
            'iam:GetPolicy',
            'iam:ListPolicies'
        ],
        
        # RDS related actions
        'rds': [
            'rds:CreateDBInstance',
            'rds:DeleteDBInstance',
            'rds:DescribeDBInstances',
            'rds:ModifyDBInstance',
            'rds:StartDBInstance',
            'rds:StopDBInstance',
            'rds:CreateDBSnapshot',
            'rds:DeleteDBSnapshot',
            'rds:DescribeDBSnapshots',
            'rds:RestoreDBInstanceFromSnapshot'
        ],
        
        # Lambda related actions
        'lambda': [
            'lambda:CreateFunction',
            'lambda:DeleteFunction',
            'lambda:GetFunction',
            'lambda:InvokeFunction',
            'lambda:ListFunctions',
            'lambda:UpdateFunctionCode',
            'lambda:UpdateFunctionConfiguration'
        ],
        
        # DynamoDB related actions
        'dynamodb': [
            'dynamodb:CreateTable',
            'dynamodb:DeleteTable',
            'dynamodb:DescribeTable',
            'dynamodb:ListTables',
            'dynamodb:GetItem',
            'dynamodb:PutItem',
            'dynamodb:UpdateItem',
            'dynamodb:DeleteItem',
            'dynamodb:Query',
            'dynamodb:Scan'
        ],
        
        # Cloudwatch related actions
        'cloudwatch': [
            'cloudwatch:PutMetricData',
            'cloudwatch:GetMetricData',
            'cloudwatch:GetMetricStatistics',
            'cloudwatch:ListMetrics',
            'cloudwatch:PutMetricAlarm',
            'cloudwatch:DeleteAlarms',
            'cloudwatch:DescribeAlarms'
        ],
        
        # SNS related actions
        'sns': [
            'sns:CreateTopic',
            'sns:DeleteTopic',
            'sns:ListTopics',
            'sns:Subscribe',
            'sns:Unsubscribe',
            'sns:Publish'
        ],
        
        # SQS related actions
        'sqs': [
            'sqs:CreateQueue',
            'sqs:DeleteQueue',
            'sqs:ListQueues',
            'sqs:SendMessage',
            'sqs:ReceiveMessage',
            'sqs:DeleteMessage'
        ],
        
        # KMS related actions
        'kms': [
            'kms:CreateKey',
            'kms:DescribeKey',
            'kms:EnableKey',
            'kms:DisableKey',
            'kms:ScheduleKeyDeletion',
            'kms:ListKeys',
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:GenerateDataKey'
        ]
    }
    
    # Return actions for the requested service, or an empty list if not found
    return service_actions.get(service, [])

def get_common_condition_operators():
    """
    Returns a list of common condition operators used in AWS IAM policies
    
    Returns:
        dict: Dictionary mapping operator category to list of operators
    """
    return {
        "String Conditions": [
            "StringEquals",
            "StringNotEquals",
            "StringEqualsIgnoreCase",
            "StringNotEqualsIgnoreCase",
            "StringLike",
            "StringNotLike"
        ],
        "Numeric Conditions": [
            "NumericEquals",
            "NumericNotEquals",
            "NumericLessThan",
            "NumericLessThanEquals",
            "NumericGreaterThan",
            "NumericGreaterThanEquals"
        ],
        "Date Conditions": [
            "DateEquals",
            "DateNotEquals",
            "DateLessThan",
            "DateLessThanEquals",
            "DateGreaterThan",
            "DateGreaterThanEquals"
        ],
        "Boolean Conditions": [
            "Bool"
        ],
        "IP Address Conditions": [
            "IpAddress",
            "NotIpAddress"
        ],
        "ARN Conditions": [
            "ArnEquals",
            "ArnLike",
            "ArnNotEquals",
            "ArnNotLike"
        ],
        "Binary Conditions": [
            "BinaryEquals"
        ],
        "Multi-value Conditions": [
            "ForAllValues:StringEquals",
            "ForAllValues:StringLike",
            "ForAnyValue:StringEquals",
            "ForAnyValue:StringLike"
        ]
    }

def get_common_condition_keys():
    """
    Returns a list of common condition keys used in AWS IAM policies
    
    Returns:
        list: List of common condition keys
    """
    return [
        "aws:CurrentTime",
        "aws:EpochTime",
        "aws:PrincipalTag/${TagKey}",
        "aws:RequestTag/${TagKey}",
        "aws:ResourceTag/${TagKey}",
        "aws:SecureTransport",
        "aws:SourceIp",
        "aws:SourceVpc",
        "aws:SourceVpce",
        "aws:UserAgent",
        "aws:userid",
        "aws:username",
        "s3:delimiter",
        "s3:max-keys",
        "s3:prefix",
        "s3:x-amz-acl",
        "s3:x-amz-content-sha256",
        "ec2:Region",
        "ec2:ResourceTag/${TagKey}",
        "ec2:InstanceType",
        "iam:AWSServiceName",
        "iam:PassedToService",
        "iam:PermissionsBoundary"
    ]

def generate_sample_policy():
    """
    Generate a sample AWS IAM policy for demonstration
    
    Returns:
        str: A sample policy JSON string
    """
    # Sample policy to access an S3 bucket with IP restriction
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": "arn:aws:s3:::example-bucket/*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "192.168.1.0/24"
                    }
                }
            },
            {
                "Effect": "Allow",
                "Action": "ec2:DescribeInstances",
                "Resource": "*"
            }
        ]
    }
    
    # Return the policy as a formatted JSON string
    return json.dumps(policy, indent=2)

def analyze_policy(policy_json):
    """
    Analyze an AWS IAM policy and provide insights
    
    Args:
        policy_json (str): JSON string of the AWS IAM policy
        
    Returns:
        dict: Analysis results including actions, resources, and potential concerns
    """
    try:
        # Parse the policy
        policy = json.loads(policy_json)
        
        # Extract important details
        actions = []
        resources = []
        has_wildcards = False
        has_admin_privileges = False
        
        for statement in policy.get("Statement", []):
            if statement.get("Effect") == "Allow":
                # Check for actions
                stmt_actions = statement.get("Action", [])
                if isinstance(stmt_actions, str):
                    stmt_actions = [stmt_actions]
                actions.extend(stmt_actions)
                
                # Check for admin privileges
                if "*" in stmt_actions or "iam:*" in stmt_actions:
                    has_admin_privileges = True
                    
                # Check for resources
                stmt_resources = statement.get("Resource", [])
                if isinstance(stmt_resources, str):
                    stmt_resources = [stmt_resources]
                resources.extend(stmt_resources)
                
                # Check for wildcards in resources
                if "*" in stmt_resources:
                    has_wildcards = True
        
        # Return the analysis
        return {
            "actions": actions,
            "resources": resources,
            "concerns": {
                "has_wildcards": has_wildcards,
                "has_admin_privileges": has_admin_privileges,
                "action_count": len(actions)
            }
        }
    except Exception as e:
        return {"error": str(e)}
