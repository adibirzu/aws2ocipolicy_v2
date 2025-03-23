"""
OCI resource types based on Oracle's Core Policy Reference documentation.
https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/corepolicyreference.htm
"""

# Resource families recognized in OCI policies
OCI_RESOURCE_FAMILIES = [
    "instance-family",
    "volume-family", 
    "boot-volume-family",
    "virtual-network-family", 
    "database-family",
    "autonomous-database-family",
    "cluster-family",
    "file-family",
    "object-family",
    "key-family",
    "secret-family",
    "certificate-family",
    "vault-family",
    "backup-family",
    "bastion-family",
    "logging-family",
    "cloud-guard-family",
    "devops-family",      # DevOps service resources
    "functions-family",   # Functions service resources
    "all-resources"
]

# Specific resource types by service
OCI_SERVICE_RESOURCES = {
    # Compute resources
    "compute": [
        "instances",
        "instance-configurations", 
        "instance-pools",
        "cluster-networks",
        "dedicated-vm-hosts",
        "images",
        "boot-volumes",
        "boot-volume-backups",
        "shapes",
        "capacity-reservations"
    ],
    
    # Block Volume
    "block-volume": [
        "volumes",
        "volume-backups",
        "volume-groups",
        "volume-group-backups"
    ],
    
    # Networking
    "vcn": [
        "virtual-networks",
        "subnets",
        "network-security-groups",
        "security-lists",
        "route-tables",
        "dhcp-options",
        "internet-gateways",
        "nat-gateways",
        "service-gateways",
        "local-peering-gateways",
        "drgs",
        "drg-attachments",
        "public-ips"
    ],
    
    # Load Balancer
    "load-balancer": [
        "load-balancers",
        "backend-sets"
    ],
    
    # Object Storage
    "object-storage": [
        "buckets",
        "objects",
        "preauthenticated-requests",
        "namespaces",
        "replication-policies"
    ],
    
    # File Storage
    "file-storage": [
        "file-systems",
        "mount-targets",
        "exports",
        "snapshots"
    ],
    
    # Database
    "database": [
        "databases",
        "db-systems",
        "db-homes",
        "backups"
    ],
    
    # Autonomous Database
    "autonomous-database": [
        "autonomous-databases",
        "autonomous-container-databases",
        "autonomous-exadata-infrastructures"
    ],
    
    # Identity resources
    "identity": [
        "users",
        "groups",
        "dynamic-groups",
        "compartments",
        "policies",
        "tag-namespaces",
        "tag-definitions"
    ],
    
    # Functions
    "functions": [
        "functions",
        "applications"
    ],
    
    # Vault (Key Management)
    "vault": [
        "vaults",
        "keys",
        "secrets",
        "key-versions",
        "secret-versions",
        "managed-keys"
    ],
    
    # Certificate Management
    "certificates": [
        "certificate-authorities",
        "ca-bundles",
        "certificates",
        "certificate-versions"
    ],
    
    # Certificate Authority
    "acm-pca": [
        "certificate-authorities",
        "ca-bundles",
        "ca-issuers"
    ],
    
    # Key Management
    "kms": [
        "keys",
        "key-versions",
        "vaults",
        "hsm-clusters"
    ],
    
    # Resource Manager
    "resource-manager": [
        "stacks",
        "configuration-source-providers",
        "jobs"
    ],
    
    # Notifications
    "ons": [
        "notification-topics",
        "subscriptions"
    ],
    
    # Events
    "events": [
        "rules"
    ],
    
    # Cloud Guard
    "cloud-guard": [
        "problems",
        "detectors"
    ],
    
    # Container Engine for Kubernetes
    "container-engine": [
        "clusters",
        "node-pools",
        "work-requests"
    ]
}

# Standalone resources that aren't tied to a specific service
STANDALONE_RESOURCES = [
    "tenancies",
    "regions",
    "compartments",
    "availability-domains",
    "fault-domains",
    "audit-events",
    "console-histories",
    "acm-pca",            # Certificate Authority Service
    "vault",              # Key and Vault Management 
    "certificates",       # Certificate Management
    "dns",                # DNS Service
    "instance-images",    # Compute Images
    "identity-domain",    # Identity Domain Service
    "identity-provider",  # Identity Provider Service
    "authentication-policies", # Authentication Policies
    "network-sources",    # Network Sources for Authentication
    
    # Budget resources
    "budgets",
    "usage-budgets",
    "usage-reports",
    
    # DevOps resources
    "repos",
    "container-instances",
    "artifacts"
]

def is_valid_oci_resource(resource_str):
    """
    Checks if a string is a valid OCI resource type based on the Core Policy Reference.
    
    Args:
        resource_str (str): The resource string to validate
        
    Returns:
        bool: True if the resource is valid, False otherwise
    """
    # Check if it's a resource family
    if resource_str in OCI_RESOURCE_FAMILIES:
        return True
    
    # Check if it's a standalone resource
    if resource_str in STANDALONE_RESOURCES:
        return True
    
    # Check if it's a service-specific resource
    parts = resource_str.split()
    if len(parts) == 2:
        service, resource = parts
        if service in OCI_SERVICE_RESOURCES and resource in OCI_SERVICE_RESOURCES[service]:
            return True
        
    # Check if it's a direct resource in any service
    for service, resources in OCI_SERVICE_RESOURCES.items():
        if resource_str in resources:
            return True
    
    return False
