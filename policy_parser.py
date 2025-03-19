import os
import json
import logging
import requests
from bs4 import BeautifulSoup
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Base URL for OCI policy reference documentation
BASE_URL = "https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/"

# List of policy reference pages to parse
POLICY_REFERENCE_PAGES = [
    {"url": "corepolicyreference.htm", "category": "Core Services", "name": "Core Services"},
    {"url": "objectstoragepolicyreference.htm", "category": "Storage", "name": "Object Storage"},
    {"url": "blockvolumepolicyreference.htm", "category": "Storage", "name": "Block Volume"},
    {"url": "databasepolicyreference.htm", "category": "Database", "name": "Database"},
    {"url": "vcnpolicyreference.htm", "category": "Networking", "name": "Virtual Cloud Network"},
    {"url": "identitypolicyreference.htm", "category": "Security", "name": "Identity"}
]

# Path to save the parsed policy data
DATA_FILE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "data")
os.makedirs(DATA_FILE_PATH, exist_ok=True)

class OCIPolicyParser:
    def __init__(self):
        self.policy_data = {
            "services": []
        }
    
    def run_parser(self):
        """Run the parser to extract OCI policy reference information"""
        try:
            # Process each policy reference page
            for page_info in POLICY_REFERENCE_PAGES:
                page_url = f"{BASE_URL}{page_info['url']}"
                logger.info(f"Parsing policy reference page: {page_url}")
                
                # Fetch the page content
                response = requests.get(page_url)
                if response.status_code != 200:
                    logger.error(f"Failed to fetch page: {page_url}, status: {response.status_code}")
                    continue
                
                # Parse the HTML content
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract service information
                service_data = self._extract_service_data(soup, page_info)
                if service_data:
                    self.policy_data["services"].append(service_data)
            
            # Save the parsed data
            self._save_data()
            
            return {
                "success": True,
                "message": f"Successfully parsed {len(self.policy_data['services'])} OCI policy reference pages."
            }
        
        except Exception as e:
            logger.exception(f"Error parsing OCI policy reference: {str(e)}")
            return {
                "success": False,
                "error": f"Error parsing OCI policy reference: {str(e)}"
            }
    
    def _extract_service_data(self, soup, page_info):
        """Extract service data from a policy reference page"""
        service_data = {
            "name": page_info["name"],
            "category": page_info["category"],
            "url": f"{BASE_URL}{page_info['url']}",
            "resource_types": self._extract_resource_types(soup),
            "aggregate_resources": self._extract_aggregate_resources(soup),
            "variables": self._extract_variables(soup),
            "verb_combinations": self._extract_verb_combinations(soup),
        }
        
        return service_data
    
    def _extract_resource_types(self, soup):
        """Extract resource types from the page"""
        resource_types = []
        
        # Look for the resource types section
        resource_section = self._find_section(soup, ["Resource Types", "Resource Type"])
        
        if resource_section:
            # Find the table in this section
            tables = resource_section.find_all("table")
            if tables:
                for table in tables:
                    rows = table.find_all("tr")
                    # Skip header row
                    for row in rows[1:]:
                        cells = row.find_all("td")
                        if len(cells) >= 2:
                            resource_type = {
                                "name": self._get_text(cells[0]),
                                "description": self._get_text(cells[1])
                            }
                            resource_types.append(resource_type)
        
        return resource_types
    
    def _extract_aggregate_resources(self, soup):
        """Extract aggregate resource types from the page"""
        aggregate_resources = []
        
        # Look for the aggregate resource types section
        aggregate_section = self._find_section(soup, ["Aggregate Resource Types", "Aggregate Resource Type"])
        
        if aggregate_section:
            # Find tables in this section
            tables = aggregate_section.find_all("table")
            for table in tables:
                rows = table.find_all("tr")
                # Skip header row
                for row in rows[1:]:
                    cells = row.find_all("td")
                    if len(cells) >= 2:
                        # The second cell might contain a list of resource types
                        included_resources = []
                        lists = cells[1].find_all("li")
                        if lists:
                            for item in lists:
                                included_resources.append(self._get_text(item))
                        else:
                            # If no list, just get the text
                            included_resources = [self._get_text(cells[1])]
                        
                        aggregate_resource = {
                            "name": self._get_text(cells[0]),
                            "included_resources": included_resources
                        }
                        aggregate_resources.append(aggregate_resource)
        
        return aggregate_resources
    
    def _extract_variables(self, soup):
        """Extract policy variables from the page"""
        variables = []
        
        # Look for the variables section
        variables_section = self._find_section(soup, ["Variables", "Supported Variables", "Policy Variables"])
        
        if variables_section:
            # Find tables in this section
            tables = variables_section.find_all("table")
            for table in tables:
                rows = table.find_all("tr")
                # Skip header row
                for row in rows[1:]:
                    cells = row.find_all("td")
                    if len(cells) >= 3:
                        variable = {
                            "name": self._get_text(cells[0]),
                            "applies_to": self._get_text(cells[1]),
                            "description": self._get_text(cells[2])
                        }
                        variables.append(variable)
        
        return variables
    
    def _extract_verb_combinations(self, soup):
        """Extract verb and resource type combinations from the page"""
        verb_combinations = []
        
        # Look for the verb combinations section
        verb_section = self._find_section(soup, [
            "Verb and Resource Type Combinations", 
            "Details for Each API Operation",
            "Details for API Operations"
        ])
        
        if verb_section:
            # Find tables in this section
            tables = verb_section.find_all("table")
            for table in tables:
                rows = table.find_all("tr")
                # Skip header row
                for row in rows[1:]:
                    cells = row.find_all("td")
                    if len(cells) >= 3:
                        # The third cell might contain a list of API operations
                        api_operations = []
                        lists = cells[2].find_all("li")
                        if lists:
                            for item in lists:
                                api_operations.append(self._get_text(item))
                        else:
                            # If no list, just get the text
                            api_operations = [self._get_text(cells[2])]
                        
                        verb_combination = {
                            "verb": self._get_text(cells[0]),
                            "resource_type": self._get_text(cells[1]),
                            "api_operations": api_operations
                        }
                        verb_combinations.append(verb_combination)
        
        return verb_combinations
    
    def _find_section(self, soup, possible_titles):
        """Find a section in the page by its title"""
        for title in possible_titles:
            # Look for h2 or h3 with the title
            for tag in ["h2", "h3", "h4"]:
                headers = soup.find_all(tag)
                for header in headers:
                    if title.lower() in header.get_text().lower():
                        # Once we found the header, get all content until the next header
                        section_content = []
                        current = header.next_sibling
                        while current and not current.name in ["h2", "h3", "h4"]:
                            if hasattr(current, 'name'):
                                section_content.append(current)
                            current = current.next_sibling
                        
                        # Create a new soup with just this section
                        section_html = "".join(str(content) for content in section_content)
                        return BeautifulSoup(section_html, 'html.parser')
        
        return None
    
    def _get_text(self, element):
        """Get clean text from an element"""
        if not element:
            return ""
        
        # Convert to string and remove excessive whitespace
        text = element.get_text().strip()
        text = re.sub(r'\s+', ' ', text)
        return text
    
    def _save_data(self):
        """Save the parsed policy data to a JSON file"""
        policy_file = os.path.join(DATA_FILE_PATH, "oci_policy_reference.json")
        os.makedirs(os.path.dirname(policy_file), exist_ok=True)
        
        with open(policy_file, 'w') as f:
            json.dump(self.policy_data, f, indent=2)
        
        logger.info(f"Saved policy reference data to {policy_file}")

# Function to run the parser
def run_policy_parser():
    parser = OCIPolicyParser()
    return parser.run_parser()

if __name__ == "__main__":
    # If run directly, execute the parser
    result = run_policy_parser()
    print(result)
