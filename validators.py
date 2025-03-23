import re
import logging
import os
import sys

logger = logging.getLogger(__name__)
from resource_validation_logger import log_invalid_resource
from oci_resource_types import is_valid_oci_resource, OCI_RESOURCE_FAMILIES, OCI_SERVICE_RESOURCES, STANDALONE_RESOURCES

# Do not import from translator to avoid circular imports
# Will populate these later after resolving imports
SERVICE_MAPPINGS = {}
OCI_RESOURCE_TYPES = {}

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
        if validate_resource_ocid(resource_ocid):
            conds.append(f"target.{resource_type}.id = '{resource_ocid}'")
        else:
            logger.warning(f"Invalid OCID format: {resource_ocid}. This may result in invalid policy conditions.")
            conds.append(f"target.{resource_type}.id = '{resource_ocid}'")
    
    # Process standard condition operators
    # This is a simplified implementation
    for operator, content in conditions.items():
        for key, values in content.items():
            # Object Storage specific conditions
            if key.startswith("s3:"):
                if key == "s3:prefix":
                    prefix_conds = []
                    if isinstance(values, str):
                        values = [values]
                    for v in values:
                        prefix_conds.append(f"target.object.name like '{v}%'")
                    if prefix_conds:
                        conds.append("(" + " or ".join(prefix_conds) + ")")
    
    # Join conditions with AND
    if conds:
        return " and ".join(conds)
    else:
        return ""

# OCI policy format regex patterns
# Standard OCI policy format
STD_POLICY_PATTERN = r"^Allow\s+group\s+[\w\s-]+\s+to\s+(inspect|read|use|manage)\s+[\w\s-]+\s+in\s+(tenancy|compartment)(\s+where\s+.+)?$"
# Identity Domains policy format
ID_POLICY_PATTERN = r"^Allow\s+group\s+[\w\s-]+\s+(iam:admin|iam:read|iam:use)\s+resource-type\.[\w-]+(\s+where\s+.+)?$"
# Combined pattern for validation
POLICY_PATTERN = f"({STD_POLICY_PATTERN})|({ID_POLICY_PATTERN})"

GROUP_NAME_PATTERN = r"^[\w\s-]+$"
RESOURCE_PATTERN = r"^[\w\s-]+$"
CONDITION_PATTERN = r"^[\w\s().=<>'\"]+(\s+(and|or)\s+[\w\s().=<>'\"]+)*$"

# OCI verbs
OCI_VERBS = ["inspect", "read", "use", "manage"]

# Identity Domains verbs
ID_VERBS = ["iam:admin", "iam:read", "iam:use"]

# Combined verbs for validation
ALL_VERBS = OCI_VERBS + ID_VERBS

# OCI policy condition variable patterns
OCI_CONDITION_VARIABLES = {
    "request": [
        "principal.type", "principal.name", "principal.id", 
        "operation", "region.name", "region.home",
        "date", "time",
        "clientip", "user.id", "user.name", "user.groups",
        "networkSource.vcnId", "networkSource.vceId",
        "resource.id", "resource.compartment.id",
        "resource.compartment.name", "resource.type",
        "resource.parent.id", "resource.parent.compartment.id",
        "resource.parent.compartment.name",
        "object.name", "object.id", "object.type",
        "object.fetch.max", "secure", "ipAddress"
    ],
    "target": {
        "compute": ["instance.id", "instance.compartment.id", "volume.id", "image.id"],
        "object-storage": ["bucket.name", "object.name", "namespace"],
        "identity": ["user.id", "group.id", "compartment.id", "policy.id", "tag.id", "tag.value"],
        "vcn": ["vcn.id", "subnet.id", "security-list.id", "route-table.id", "network-security-group.id"],
        "database": ["db-system.id", "database.id", "backup.id"],
        "functions": ["function.id", "application.id"],
        "vault": ["key.id", "secret.id", "vault.id"]
    }
}

def validate_policy(policy):
    """
    Validates the syntax of an OCI policy.
    
    Args:
        policy (str): OCI policy statements as a string
        
    Returns:
        list: List of error messages, empty if policy is valid
    """
    if not policy:
        return ["Empty policy generated."]
    
    errors = []
    
    for line_num, line in enumerate(policy.split("\n"), 1):
        line = line.strip()
        
        if not line:
            continue
            
        # Check if this is a standard OCI policy or Identity Domains policy
        is_id_domains = False
        if re.match(ID_POLICY_PATTERN, line, re.IGNORECASE):
            is_id_domains = True
        
        # Validate basic policy syntax
        if not re.match(POLICY_PATTERN, line, re.IGNORECASE):
            errors.append(f"Syntax Error at line {line_num}: {line}")
            continue
            
        # Extract and validate group name
        if is_id_domains:
            match = re.search(r"group\s+([\w\s-]+)\s+(iam:admin|iam:read|iam:use)", line)
        else:
            match = re.search(r"group\s+([\w\s-]+)\s+to", line)
            
        if match:
            group_name = match.group(1).strip()
            if not re.match(GROUP_NAME_PATTERN, group_name):
                errors.append(f"Invalid group name at line {line_num}: {group_name}")
        
        # Validate verb
        if is_id_domains:
            match = re.search(r"group\s+[\w\s-]+\s+(iam:admin|iam:read|iam:use)", line, re.IGNORECASE)
            if not match:
                errors.append(f"Invalid verb at line {line_num}: Use one of 'iam:admin', 'iam:read', or 'iam:use' for Identity Domains policies")
            else:
                verb = match.group(1).lower()
                if verb not in ID_VERBS:
                    errors.append(f"Invalid Identity Domains verb at line {line_num}: '{verb}'. Valid verbs are: {', '.join(ID_VERBS)}")
        else:
            match = re.search(r"to\s+(inspect|read|use|manage)\s+", line, re.IGNORECASE)
            if not match:
                errors.append(f"Invalid verb at line {line_num}: Use one of 'inspect', 'read', 'use', or 'manage'")
            else:
                verb = match.group(1).lower()
                if verb not in OCI_VERBS:
                    errors.append(f"Invalid verb at line {line_num}: '{verb}'. Valid verbs are: {', '.join(OCI_VERBS)}")
        
        # Validate resource
        if is_id_domains:
            match = re.search(r"(iam:admin|iam:read|iam:use)\s+resource-type\.([\w-]+)", line, re.IGNORECASE)
            if match:
                resource_str = match.group(2).strip()
                # For Identity Domains, resource types are service names
                if not resource_str in SERVICE_MAPPINGS.values() and not resource_str in OCI_RESOURCE_TYPES.keys():
                    errors.append(f"Invalid resource type at line {line_num}: '{resource_str}'. Not a valid OCI service.")
        else:
            match = re.search(r"(inspect|read|use|manage)\s+([\w\s-]+)\s+in", line, re.IGNORECASE)
            if match:
                resource_str = match.group(2).strip()
                if not validate_oci_resource(resource_str):
                    errors.append(f"Invalid resource at line {line_num}: '{resource_str}'. Not a valid OCI resource.")
                
        # Validate conditions if present
        if "where" in line:
            match = re.search(r"where\s+(.+)$", line)
            if match:
                condition = match.group(1).strip()
                condition_errors = validate_condition(condition)
                if condition_errors:
                    for error in condition_errors:
                        errors.append(f"Condition error at line {line_num}: {error}")
                    
    return errors

def validate_oci_resource(resource_str):
    """
    Validates if the resource string is a valid OCI resource.
    Uses the comprehensive resource validation from oci_resource_types module.
    
    Args:
        resource_str (str): Resource string to validate
        
    Returns:
        bool: True if resource is valid, False otherwise
    """
    # First, use the comprehensive resource validation from oci_resource_types
    if is_valid_oci_resource(resource_str):
        return True
    
    # Legacy validation logic for backward compatibility
    # Check for service-level resources
    if resource_str in OCI_RESOURCE_TYPES.keys():
        return True
    
    # Check for special AWS services that map to OCI services
    special_services = [
        "container-registry",      # ECR
        "notification-service",    # SNS/notifications
        "streaming"                # SQS/queue
    ]
    
    if resource_str in special_services:
        return True
    
    # Check for service-specific resources (e.g., "object-storage bucket")
    parts = resource_str.split()
    if len(parts) == 2:
        service, resource_type = parts
        # Check legacy resource types
        if service in OCI_RESOURCE_TYPES and resource_type in OCI_RESOURCE_TYPES.get(service, []):
            return True
        
        # Legacy special combinations
        special_combinations = {
            "container-registry": ["repository", "image"],
            "notification-service": ["topic", "subscription"],
            "streaming": ["stream", "stream-pool", "connect-harness", "message"]
        }
        
        if service in special_combinations and resource_type in special_combinations[service]:
            return True
    
    # If we got here, the resource is invalid, so log it for future improvements
    parts = resource_str.split() if " " in resource_str else [resource_str]
    if len(parts) == 2:
        service, resource_type = parts
        log_invalid_resource(resource_str, service=service, additional_info={"resource_type": resource_type})
    else:
        log_invalid_resource(resource_str)
        
    return False

def validate_condition(condition):
    """
    Validates an OCI policy condition.
    
    Args:
        condition (str): Condition string
        
    Returns:
        list: List of error messages, empty if condition is valid
    """
    errors = []
    
    # Basic syntax validation
    if not re.match(CONDITION_PATTERN, condition):
        errors.append("Invalid condition syntax")
        return errors
        
    # Check for balanced parentheses
    if condition.count("(") != condition.count(")"):
        errors.append("Unbalanced parentheses in condition")
        return errors
        
    # Extract individual condition clauses
    clauses = []
    if "and" in condition:
        clauses = [c.strip() for c in condition.split("and")]
    elif "or" in condition:
        clauses = [c.strip() for c in condition.split("or")]
    else:
        clauses = [condition]
    
    # Validate each clause
    for clause in clauses:
        # Remove parentheses for validation
        clause = clause.strip().strip('(').strip(')')
        
        # Check if clause contains common OCI condition variables
        valid_variable = False
        
        # Check request variables
        for var in OCI_CONDITION_VARIABLES["request"]:
            if clause.startswith(f"request.{var}"):
                valid_variable = True
                break
                
        # Check target variables for each service
        if not valid_variable:
            for service, vars in OCI_CONDITION_VARIABLES["target"].items():
                for var in vars:
                    if clause.startswith(f"target.{var}"):
                        valid_variable = True
                        break
                if valid_variable:
                    break
        
        # Check for OCIDs in conditions (should follow ocid1.* pattern)
        if "ocid1." not in clause and "'ocid1." not in clause and "\"ocid1." not in clause:
            if "=" in clause and any(x in clause for x in ["id", ".id", "OCID"]):
                errors.append(f"Condition references an ID that may not be in OCID format: {clause}")
        
        # Check for valid operators
        operators = ["=", "!=", "<", ">", "<=", ">=", ".startsWith", ".endsWith", ".contains"]
        has_operator = False
        
        for op in operators:
            if op in clause:
                has_operator = True
                break
                
        if not has_operator:
            errors.append(f"No valid operator found in condition clause: {clause}")
    
    return errors

def validate_oci_mappings(aws_service, oci_service):
    """
    Validates that an AWS to OCI service mapping is correct.
    
    Args:
        aws_service (str): AWS service name
        oci_service (str): OCI service name
        
    Returns:
        bool: True if mapping is valid, False otherwise
    """
    if aws_service not in SERVICE_MAPPINGS:
        return False
        
    correct_oci_service = SERVICE_MAPPINGS.get(aws_service)
    return oci_service == correct_oci_service

def validate_resource_ocid(ocid):
    """
    Validates if a string is a valid OCI OCID.
    
    Args:
        ocid (str): OCID to validate
        
    Returns:
        bool: True if OCID is valid, False otherwise
    """
    # OCIDs follow the pattern: ocid1.<resource-type>.<realm>.[region][.future-extensibility].
    # <unique-id-specific-to-resource-type>
    ocid_pattern = r'^ocid1\.[a-z0-9-]+\.[a-z0-9-]+(\.[a-z0-9-]+)?(\.[a-z0-9-]+)?\.[a-z0-9-]+$'
    return bool(re.match(ocid_pattern, ocid))

def validate_group_exists(group_name):
    """
    Validates that an OCI group exists.
    This is a placeholder for integration with actual OCI API.
    
    Args:
        group_name (str): OCI group name
        
    Returns:
        bool: True if group exists, False otherwise
    """
    # In a real implementation, this would call the OCI API
    # to verify the group exists
    return True

def validate_compartment_exists(compartment_id):
    """
    Validates that an OCI compartment exists.
    This is a placeholder for integration with actual OCI API.
    
    Args:
        compartment_id (str): OCI compartment OCID
        
    Returns:
        bool: True if compartment exists, False otherwise
    """
    # In a real implementation, this would call the OCI API
    # to verify the compartment exists
    if not validate_resource_ocid(compartment_id):
        return False
    return True
