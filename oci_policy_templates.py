"""
OCI Policy Templates Builder
Based on official Oracle documentation:
- https://docs.public.oneportal.content.oci.oraclecloud.com/en-us/iaas/Content/Identity/policiescommon/commonpolicies.htm
- https://docs.public.oneportal.content.oci.oraclecloud.com/en-us/iaas/Content/Identity/policyreference/iampolicyreference.htm
"""

# Template policy structure for common permission levels
class OCIPolicyTemplates:
    """
    Provides templates for common OCI policies across different services.
    
    Use this class to build Oracle recommended policies using standard
    templates from their documentation.
    """
    
    @staticmethod
    def network_admin_policies(group_name, scope="tenancy"):
        """
        Network administrator policies - for users who need to manage virtual cloud networks
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage virtual-network-family in {scope}",
            f"Allow group {group_name} to manage load-balancers in {scope}",
            f"Allow group {group_name} to manage dns in {scope}",
            f"Allow group {group_name} to manage certificates in {scope}",
            f"Allow group {group_name} to inspect instances in {scope}",
        ]
    
    @staticmethod
    def security_admin_policies(group_name, scope="tenancy"):
        """
        Security administrator policies - for users who need to manage security policies
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage security-lists in {scope}",
            f"Allow group {group_name} to manage network-security-groups in {scope}",
            f"Allow group {group_name} to manage key-family in {scope}",
            f"Allow group {group_name} to manage secret-family in {scope}",
            f"Allow group {group_name} to manage vault-family in {scope}",
            f"Allow group {group_name} to manage certificate-family in {scope}",
            f"Allow group {group_name} to manage bastion-family in {scope}",
            f"Allow group {group_name} to manage logging-family in {scope}",
            f"Allow group {group_name} to manage cloud-guard-family in {scope}",
        ]

    @staticmethod
    def compute_admin_policies(group_name, scope="tenancy"):
        """
        Compute administrator policies - for users who manage compute resources
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage instance-family in {scope}",
            f"Allow group {group_name} to manage cluster-family in {scope}",
            f"Allow group {group_name} to manage volume-family in {scope}",
            f"Allow group {group_name} to manage virtual-network-family in {scope}",
            f"Allow group {group_name} to manage load-balancers in {scope}",
            f"Allow group {group_name} to manage instance-images in {scope}",
            f"Allow group {group_name} to manage instance-configurations in {scope}",
            f"Allow group {group_name} to manage keys in {scope}",
            f"Allow group {group_name} to use secrets in {scope}",
            f"Allow group {group_name} to read certificate-family in {scope}",
        ]

    @staticmethod
    def storage_admin_policies(group_name, scope="tenancy"):
        """
        Storage administrator policies - for users who manage storage resources
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage buckets in {scope}",
            f"Allow group {group_name} to manage objects in {scope}",
            f"Allow group {group_name} to manage file-family in {scope}",
            f"Allow group {group_name} to manage volume-family in {scope}",
            f"Allow group {group_name} to manage backup-family in {scope}",
        ]

    @staticmethod
    def database_admin_policies(group_name, scope="tenancy"):
        """
        Database administrator policies - for users who manage database resources
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage database-family in {scope}",
            f"Allow group {group_name} to manage autonomous-database-family in {scope}",
            f"Allow group {group_name} to manage virtual-network-family in {scope}",
            f"Allow group {group_name} to manage volume-family in {scope}",
            f"Allow group {group_name} to use keys in {scope}",
            f"Allow group {group_name} to use secrets in {scope}",
        ]

    @staticmethod
    def identity_admin_policies(group_name, scope="tenancy"):
        """
        Identity Domain administrator policies
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage identity-domain in {scope}",
            f"Allow group {group_name} to manage identity-provider in {scope}",
            f"Allow group {group_name} to manage users in {scope}",
            f"Allow group {group_name} to manage groups in {scope}",
            f"Allow group {group_name} to manage policies in {scope}",
            f"Allow group {group_name} to manage dynamic-groups in {scope}",
            f"Allow group {group_name} to manage authentication-policies in {scope}",
            f"Allow group {group_name} to manage network-sources in {scope}",
        ]

    @staticmethod
    def budget_admin_policies(group_name, scope="tenancy"):
        """
        Budget administrator policies
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage budgets in {scope}",
            f"Allow group {group_name} to manage usage-budgets in {scope}",
            f"Allow group {group_name} to manage usage-reports in {scope}",
            f"Allow group {group_name} to read all-resources in {scope}",
        ]

    @staticmethod
    def read_only_policies(group_name, scope="tenancy"):
        """
        Read-only policies for users who can view but not modify resources
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to read all-resources in {scope}",
        ]

    @staticmethod
    def compute_read_only_policies(group_name, scope="tenancy"):
        """
        Compute read-only policies
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to read instance-family in {scope}",
            f"Allow group {group_name} to read cluster-family in {scope}",
            f"Allow group {group_name} to read volume-family in {scope}",
            f"Allow group {group_name} to read virtual-network-family in {scope}",
            f"Allow group {group_name} to read load-balancers in {scope}",
        ]

    @staticmethod
    def devops_policies(group_name, scope="tenancy"):
        """
        DevOps policies for CI/CD and build automation
        
        Args:
            group_name (str): OCI group name
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        return [
            f"Allow group {group_name} to manage devops-family in {scope}",
            f"Allow group {group_name} to manage repos in {scope}",
            f"Allow group {group_name} to manage functions-family in {scope}",
            f"Allow group {group_name} to manage container-instances in {scope}",
            f"Allow group {group_name} to manage cluster-family in {scope}",
            f"Allow group {group_name} to manage artifacts in {scope}",
            f"Allow group {group_name} to manage keys in {scope}",
            f"Allow group {group_name} to use secrets in {scope}",
        ]
        
    @staticmethod
    def custom_template(group_name, verbs, resources, scope="tenancy"):
        """
        Create custom policies for specific verbs and resources
        
        Args:
            group_name (str): OCI group name
            verbs (list): List of OCI verbs (e.g., "manage", "read", "use", "inspect")
            resources (list): List of OCI resources (e.g., "instances", "buckets")
            scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
        
        Returns:
            list: List of OCI policy statements
        """
        policies = []
        for verb in verbs:
            for resource in resources:
                policies.append(f"Allow group {group_name} to {verb} {resource} in {scope}")
        return policies


# Map AWS service areas to appropriate OCI template methods
AWS_TO_OCI_TEMPLATE_MAP = {
    "ec2": "compute_admin_policies",
    "eks": "compute_admin_policies",
    "ecs": "compute_admin_policies",
    "lambda": "compute_admin_policies",
    "vpc": "network_admin_policies",
    "s3": "storage_admin_policies",
    "rds": "database_admin_policies",
    "dynamodb": "database_admin_policies",
    "iam": "identity_admin_policies",
    "organizations": "identity_admin_policies",
    "kms": "security_admin_policies",
    "cloudwatch": "compute_admin_policies",
    "cloudtrail": "security_admin_policies",
    "budgets": "budget_admin_policies",
    "codebuild": "devops_policies",
    "codecommit": "devops_policies",
    "codepipeline": "devops_policies",
    "acm": "security_admin_policies",
    "acm-pca": "security_admin_policies",
    "secrets-manager": "security_admin_policies",
    "waf": "security_admin_policies",
    "shield": "security_admin_policies",
}


def get_template_for_aws_service(aws_service, group_name, scope="tenancy"):
    """
    Get the appropriate OCI policy template for an AWS service.
    
    Args:
        aws_service (str): AWS service name
        group_name (str): OCI group name
        scope (str): Scope for the policy (e.g., "tenancy", "compartment abc")
    
    Returns:
        list: List of OCI policy statements
    """
    if aws_service in AWS_TO_OCI_TEMPLATE_MAP:
        template_method = getattr(OCIPolicyTemplates, AWS_TO_OCI_TEMPLATE_MAP[aws_service])
        return template_method(group_name, scope)
    else:
        # Default to read-only policies if no specific template is available
        return OCIPolicyTemplates.read_only_policies(group_name, scope)
