import logging
import os
import json
from datetime import datetime

# Create a dedicated logger for resource validation errors
resource_logger = logging.getLogger('resource_validation')
resource_logger.setLevel(logging.INFO)

# Set up file handler for the resource validation log
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'resource_validation.log')

file_handler = logging.FileHandler(log_file)
file_handler.setLevel(logging.INFO)

# Create a formatter that includes timestamp and detailed information
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handlers to the logger
resource_logger.addHandler(file_handler)

def log_invalid_resource(resource, service=None, additional_info=None):
    """
    Log invalid resources that failed validation to a separate log file.
    These can be reviewed later to update the reference lists.
    
    Args:
        resource (str): The invalid resource that failed validation
        service (str, optional): The service this resource belongs to
        additional_info (dict, optional): Any additional information about the context
    """
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'invalid_resource': resource,
        'service': service,
        'additional_info': additional_info or {}
    }
    
    # Log as both structured JSON and a readable message
    resource_logger.info(f"Invalid resource detected: '{resource}'" + 
                         (f" for service '{service}'" if service else ""))
    resource_logger.info(f"STRUCTURED_DATA: {json.dumps(log_entry)}")
