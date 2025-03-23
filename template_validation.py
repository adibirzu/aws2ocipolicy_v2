#!/usr/bin/env python3
"""
Standalone script to validate OCI policy templates.
"""

from oci_policy_templates import OCIPolicyTemplates
from validators import validate_policy

def validate_template(template_name, template_function, group_name="Administrators"):
    """
    Validate a template function and print results.
    
    Args:
        template_name (str): Name of the template for display
        template_function: Function that returns policies
        group_name (str): Group name to use in the template
    """
    policies = template_function(group_name)
    policy_str = "\n".join(policies)
    
    print(f"\n{'=' * 50}")
    print(f"VALIDATING: {template_name}")
    print(f"{'-' * 50}")
    print(policy_str)
    print(f"{'-' * 50}")
    
    errors = validate_policy(policy_str)
    if errors:
        print(f"❌ VALIDATION FAILED: {len(errors)} errors")
        for i, error in enumerate(errors, 1):
            print(f"  {i}. {error}")
    else:
        print("✅ VALID - No validation errors")

# Test all template functions
validate_template("Compute Admin", OCIPolicyTemplates.compute_admin_policies)
validate_template("Security Admin", OCIPolicyTemplates.security_admin_policies)
validate_template("Network Admin", OCIPolicyTemplates.network_admin_policies)
validate_template("Database Admin", OCIPolicyTemplates.database_admin_policies)
validate_template("Storage Admin", OCIPolicyTemplates.storage_admin_policies)
validate_template("Identity Admin", OCIPolicyTemplates.identity_admin_policies)
validate_template("Budget Admin", OCIPolicyTemplates.budget_admin_policies)
validate_template("DevOps Admin", OCIPolicyTemplates.devops_policies)
validate_template("Read-Only", OCIPolicyTemplates.read_only_policies)
validate_template("Compute Read-Only", OCIPolicyTemplates.compute_read_only_policies)

# Test custom template
verbs = ["manage", "read"]
resources = ["instance-family", "volume-family"]
validate_template("Custom Template", 
                  lambda group: OCIPolicyTemplates.custom_template(group, verbs, resources))
