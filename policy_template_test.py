#!/usr/bin/env python3
"""
Test script for the OCI policy template functionality.
Compares the original policy approach with the new template-based approach.
"""

import json
from translator import translate_simple_policy
from oci_policy_templates import OCIPolicyTemplates, get_template_for_aws_service

# Sample AWS policy for a typical EC2 admin role
ec2_admin_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:*"
            ],
            "Resource": "*"
        }
    ]
}

# Sample AWS policy for a security admin
security_admin_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "kms:*",
                "acm:*", 
                "acm-pca:*"
            ],
            "Resource": "*"
        }
    ]
}

# Sample AWS policy for a network admin
network_admin_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateVpc",
                "ec2:DeleteVpc",
                "ec2:CreateSubnet",
                "ec2:DeleteSubnet",
                "ec2:CreateSecurityGroup",
                "ec2:DeleteSecurityGroup",
                "ec2:CreateRouteTable",
                "ec2:DeleteRouteTable"
            ],
            "Resource": "*"
        }
    ]
}

# Test with legacy approach first
print("============= ORIGINAL APPROACH =============")
print("\n--- EC2 Admin Policy (Original Approach) ---")
ec2_legacy = translate_simple_policy(json.dumps(ec2_admin_policy), "ComputeAdmins", use_templates=False)
print(ec2_legacy)

print("\n--- Security Admin Policy (Original Approach) ---")
security_legacy = translate_simple_policy(json.dumps(security_admin_policy), "SecurityAdmins", use_templates=False)
print(security_legacy)

print("\n--- Network Admin Policy (Original Approach) ---")
network_legacy = translate_simple_policy(json.dumps(network_admin_policy), "NetworkAdmins", use_templates=False)
print(network_legacy)

# Now test with template approach
print("\n\n============= TEMPLATE-BASED APPROACH =============")
print("\n--- EC2 Admin Policy (Template Approach) ---")
ec2_template = translate_simple_policy(json.dumps(ec2_admin_policy), "ComputeAdmins", use_templates=True)
print(ec2_template)

print("\n--- Security Admin Policy (Template Approach) ---")
security_template = translate_simple_policy(json.dumps(security_admin_policy), "SecurityAdmins", use_templates=True)
print(security_template)

print("\n--- Network Admin Policy (Template Approach) ---")
network_template = translate_simple_policy(json.dumps(network_admin_policy), "NetworkAdmins", use_templates=True)
print(network_template)

# Direct usage of OCIPolicyTemplates class
print("\n\n============= DIRECT TEMPLATE USAGE =============")
print("\n--- Direct Compute Admin Template ---")
compute_policies = OCIPolicyTemplates.compute_admin_policies("ComputeAdmins")
print("\n".join(compute_policies))

print("\n--- Direct Security Admin Template ---")
security_policies = OCIPolicyTemplates.security_admin_policies("SecurityAdmins")
print("\n".join(security_policies))

print("\n--- Direct Network Admin Template ---")
network_policies = OCIPolicyTemplates.network_admin_policies("NetworkAdmins")
print("\n".join(network_policies))

# Test validation
print("\n\n============= VALIDATING TEMPLATES =============")
from validators import validate_policy

# Validate each set of direct templates
for template_name, policies in [
    ("Compute Admin", OCIPolicyTemplates.compute_admin_policies("ComputeAdmins")),
    ("Security Admin", OCIPolicyTemplates.security_admin_policies("SecurityAdmins")),
    ("Network Admin", OCIPolicyTemplates.network_admin_policies("NetworkAdmins")),
    ("Database Admin", OCIPolicyTemplates.database_admin_policies("DBAdmins")),
    ("Storage Admin", OCIPolicyTemplates.storage_admin_policies("StorageAdmins")),
    ("Identity Admin", OCIPolicyTemplates.identity_admin_policies("IdentityAdmins")),
]:
    policy_str = "\n".join(policies)
    errors = validate_policy(policy_str)
    print(f"\n--- {template_name} Template Validation ---")
    if errors:
        print(f"Validation errors: {errors}")
    else:
        print("✅ VALID - No validation errors")
