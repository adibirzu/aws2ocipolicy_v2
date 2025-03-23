#!/usr/bin/env python3
import sys
import importlib

# Force reload modules to ensure latest changes are used
import validators
import oci_resource_types
importlib.reload(oci_resource_types)
importlib.reload(validators)

from validators import validate_policy
from oci_resource_types import is_valid_oci_resource, STANDALONE_RESOURCES

# Print debug info
print("Current imported modules versions:")
print(f"oci_resource_types module: {oci_resource_types}")
print(f"validators module: {validators}")

# Check standalone resources
print(f"Standalone resources: {STANDALONE_RESOURCES}")
print(f"Is 'acm-pca' a valid resource? {is_valid_oci_resource('acm-pca')}")
print(f"Is 'key-family' a valid resource? {is_valid_oci_resource('key-family')}")

# Define sample policy to validate
policy = '''
Allow group Administrators to inspect key-family in tenancy
Allow group Administrators to inspect vault-family in tenancy
Allow group Administrators to read acm-pca in tenancy
Allow group Administrators to read certificate-family in tenancy
'''.strip()

# Validate the policy
errors = validate_policy(policy)
print(f"Validation errors: {errors}")

# Test individual policies
policies = policy.split('\n')
for idx, p in enumerate(policies):
    print(f"Validating policy {idx+1}: {p}")
    err = validate_policy(p)
    print(f"  - Errors: {err}")
