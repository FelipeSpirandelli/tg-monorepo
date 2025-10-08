import json
import re
from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors.pipeline_processor import PipelineStep


class IoCExtractorStep(PipelineStep):
    """
    IoC Extractor Engine - First step of Rule-to-Text pipeline
    
    Identifies potential Indicators of Compromise from alert data and logs
    using LLM analysis with fallback to pattern matching.
    """

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client

    @property
    def required_inputs(self) -> list[str]:
        return ["processed_alert"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["extracted_iocs", "enriched_alert"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Extract IoCs from the alert data using LLM analysis"""
        processed_alert = data["processed_alert"]
        
        logger.info("Starting IoC extraction process with LLM analysis")
        
        # Use LLM to extract IoCs
        iocs = await self._extract_iocs_with_llm(processed_alert)
        
        # Fallback to pattern matching if LLM fails
        if not iocs or sum(len(v) for v in iocs.values()) == 0:
            logger.warning("LLM extraction failed, falling back to pattern matching")
            iocs = await self._extract_iocs_fallback(processed_alert)
        
        # Create enriched alert with IoC information
        enriched_alert = processed_alert.copy()
        enriched_alert["extracted_iocs"] = iocs
        enriched_alert["ioc_summary"] = self._create_ioc_summary(iocs)
        
        logger.info(f"Extracted IoCs: {iocs}")
        
        return {
            "extracted_iocs": iocs,
            "enriched_alert": enriched_alert
        }

    async def _extract_iocs_with_llm(self, alert_data: dict[str, Any]) -> dict[str, list]:
        """Use LLM to extract IoCs from alert data"""
        try:
            # Create prompt for IoC extraction
            prompt = self._create_ioc_extraction_prompt(alert_data)
            
            # Process with LLM
            response = await self.mcp_client.process_query(
                prompt,
                model="claude-3-7-sonnet-20250219",  # Using working model
                max_tokens=2000,
                temperature=0.1  # Low temperature for precise extraction
            )
            
            # Parse LLM response to extract structured IoCs
            iocs = self._parse_llm_ioc_response(response)
            
            logger.info("Successfully extracted IoCs using LLM")
            return iocs
            
        except Exception as e:
            logger.error(f"Error in LLM IoC extraction: {str(e)}")
            return self._get_empty_iocs_dict()

    def _create_ioc_extraction_prompt(self, alert_data: dict[str, Any]) -> str:
        """Create a prompt for LLM to extract IoCs"""
        
        # Convert alert data to a formatted string
        alert_json = json.dumps(alert_data, indent=2, default=str)
        
        prompt = f"""You are a cybersecurity analyst specialized in extracting Indicators of Compromise (IoCs) from security alerts.

Analyze the following security alert data and extract all potential IoCs. Look for:
- IP addresses (both IPv4 and IPv6)
- Domain names and URLs
- File hashes (MD5, SHA1, SHA256)
- File paths and names
- Process names and executables
- User accounts
- Registry keys
- Network ports
- Email addresses
- Any other security-relevant indicators

ALERT DATA:
{alert_json}

Please respond with ONLY a JSON object in the following format:
{{
    "ip_addresses": ["list", "of", "ip_addresses"],
    "domains": ["list", "of", "domains"],
    "file_hashes": ["list", "of", "hashes"],
    "file_paths": ["list", "of", "file_paths"],
    "processes": ["list", "of", "process_names"],
    "urls": ["list", "of", "urls"],
    "user_accounts": ["list", "of", "user_accounts"],
    "registry_keys": ["list", "of", "registry_keys"],
    "ports": [list, of, port_numbers],
    "email_addresses": ["list", "of", "emails"],
    "mitre_techniques": ["list", "of", "mitre_technique_ids"]
}}

Extract IoCs from ALL fields including nested objects, query strings, rule descriptions, and any text content. Be thorough but avoid false positives from common system files or legitimate domains unless they appear suspicious in context.

Respond with ONLY the JSON object, no additional text or formatting."""

        return prompt

    def _parse_llm_ioc_response(self, response: str) -> dict[str, list]:
        """Parse LLM response to extract structured IoCs"""
        try:
            # Try to find JSON in the response
            json_start = response.find('{')
            json_end = response.rfind('}')
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end + 1]
                iocs = json.loads(json_str)
                
                # Ensure all expected keys exist
                expected_keys = [
                    "ip_addresses", "domains", "file_hashes", "file_paths", 
                    "processes", "urls", "user_accounts", "registry_keys", 
                    "ports", "email_addresses", "mitre_techniques"
                ]
                
                for key in expected_keys:
                    if key not in iocs:
                        iocs[key] = []
                    elif not isinstance(iocs[key], list):
                        iocs[key] = []
                
                # Clean and validate the data
                iocs = self._clean_and_validate_iocs(iocs)
                
                return iocs
            else:
                logger.warning("No JSON found in LLM response")
                return self._get_empty_iocs_dict()
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON response: {str(e)}")
            return self._get_empty_iocs_dict()
        except Exception as e:
            logger.error(f"Error parsing LLM response: {str(e)}")
            return self._get_empty_iocs_dict()

    def _clean_and_validate_iocs(self, iocs: dict[str, list]) -> dict[str, list]:
        """Clean and validate extracted IoCs"""
        cleaned_iocs = {}
        
        for ioc_type, values in iocs.items():
            cleaned_values = []
            
            for value in values:
                if isinstance(value, str):
                    cleaned_value = value.strip()
                    
                    # Basic validation based on IoC type
                    if self._validate_ioc(ioc_type, cleaned_value):
                        cleaned_values.append(cleaned_value)
                elif isinstance(value, (int, float)) and ioc_type == "ports":
                    if 0 <= int(value) <= 65535:
                        cleaned_values.append(int(value))
            
            # Remove duplicates while preserving order
            cleaned_iocs[ioc_type] = list(dict.fromkeys(cleaned_values))
        
        return cleaned_iocs

    def _validate_ioc(self, ioc_type: str, value: str) -> bool:
        """Basic validation for IoC values"""
        if not value or len(value) < 2:
            return False
        
        if ioc_type == "ip_addresses":
            # Basic IP validation
            parts = value.split('.')
            if len(parts) == 4:
                try:
                    return all(0 <= int(part) <= 255 for part in parts)
                except ValueError:
                    return False
        elif ioc_type == "domains":
            # Basic domain validation
            return '.' in value and not value.startswith('.') and not value.endswith('.')
        elif ioc_type == "file_hashes":
            # Basic hash validation
            return len(value) in [32, 40, 64] and all(c in '0123456789abcdefABCDEF' for c in value)
        elif ioc_type == "urls":
            # Basic URL validation
            return value.startswith(('http://', 'https://', 'ftp://'))
        
        return True  # Default to valid for other types

    async def _extract_iocs_fallback(self, alert_data: dict[str, Any]) -> dict[str, list]:
        """Fallback pattern-based IoC extraction"""
        logger.info("Using fallback pattern-based IoC extraction")
        
        iocs = self._get_empty_iocs_dict()
        
        # Extract IoCs using pattern matching
        self._extract_basic_iocs(alert_data, iocs)
        
        # Extract IoCs from structured alert fields
        self._extract_structured_iocs(alert_data, iocs)
        
        return iocs

    def _get_empty_iocs_dict(self) -> dict[str, list]:
        """Get empty IoCs dictionary with all expected keys"""
        return {
            "ip_addresses": [],
            "domains": [],
            "file_hashes": [],
            "file_paths": [],
            "processes": [],
            "urls": [],
            "user_accounts": [],
            "registry_keys": [],
            "ports": [],
            "email_addresses": [],
            "mitre_techniques": []
        }
    
    def _extract_basic_iocs(self, alert_data: dict[str, Any], iocs: dict[str, list]) -> None:
        """Extract IoCs using regex patterns from all text fields"""
        
        # Convert alert data to searchable text
        searchable_text = self._flatten_alert_to_text(alert_data)
        
        # IP address pattern (IPv4)
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ip_matches = re.findall(ip_pattern, searchable_text)
        iocs["ip_addresses"].extend(list(set(ip_matches)))
        
        # Domain pattern
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        domain_matches = re.findall(domain_pattern, searchable_text)
        # Filter out common false positives
        filtered_domains = [d for d in domain_matches if not d.endswith(('.exe', '.dll', '.sys', '.log'))]
        iocs["domains"].extend(list(set(filtered_domains)))
        
        # Hash patterns (MD5, SHA1, SHA256)
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
        ]
        for pattern in hash_patterns:
            hash_matches = re.findall(pattern, searchable_text)
            iocs["file_hashes"].extend(list(set(hash_matches)))
        
        # File path patterns
        file_path_patterns = [
            r'[C-Z]:\\[^<>:"|?*\n\r]+',  # Windows paths
            r'/[a-zA-Z0-9_\-./]+',       # Unix paths
        ]
        for pattern in file_path_patterns:
            path_matches = re.findall(pattern, searchable_text)
            iocs["file_paths"].extend(list(set(path_matches)))
        
        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;!?]'
        url_matches = re.findall(url_pattern, searchable_text)
        iocs["urls"].extend(list(set(url_matches)))
        
        # Port pattern
        port_pattern = r':(\d{1,5})\b'
        port_matches = re.findall(port_pattern, searchable_text)
        # Filter valid port numbers
        valid_ports = [int(p) for p in port_matches if 0 <= int(p) <= 65535]
        iocs["ports"].extend(list(set(valid_ports)))
    
    def _extract_structured_iocs(self, alert_data: dict[str, Any], iocs: dict[str, list]) -> None:
        """Extract IoCs from structured fields in the alert"""
        
        # Extract from common structured fields
        structured_fields = {
            "source_ip": "ip_addresses",
            "destination_ip": "ip_addresses", 
            "remote_addr": "ip_addresses",
            "host_name": "domains",
            "user_name": "user_accounts",
            "process_name": "processes",
            "file_name": "file_paths",
            "registry_path": "registry_keys",
            "url": "urls",
        }
        
        for field, ioc_type in structured_fields.items():
            if field in alert_data and alert_data[field]:
                value = str(alert_data[field]).strip()
                if value and value not in iocs[ioc_type]:
                    iocs[ioc_type].append(value)
        
        # Extract from MITRE ATT&CK techniques and tactics
        if "mitre_techniques" in alert_data:
            for technique in alert_data["mitre_techniques"]:
                if technique.get("id"):
                    # Store MITRE technique IDs as a special IoC type
                    if "mitre_techniques" not in iocs:
                        iocs["mitre_techniques"] = []
                    iocs["mitre_techniques"].append(technique["id"])
        
        # Extract query information
        if "query" in alert_data and alert_data["query"]:
            # Parse query for additional IoCs
            query_text = str(alert_data["query"])
            # This could be enhanced to parse specific SIEM query languages
            # For now, we'll extract basic patterns from the query
            temp_iocs = {
                "ip_addresses": [],
                "domains": [],
                "file_hashes": [],
                "file_paths": [],
                "processes": [],
                "urls": [],
                "user_accounts": [],
                "registry_keys": [],
                "ports": [],
                "protocols": []
            }
            self._extract_basic_iocs({"query": query_text}, temp_iocs)
            
            # Merge with main IoCs
            for ioc_type, values in temp_iocs.items():
                if values:
                    iocs[ioc_type].extend(values)
                    iocs[ioc_type] = list(set(iocs[ioc_type]))  # Remove duplicates
    
    def _flatten_alert_to_text(self, data: dict | list | str, depth: int = 0) -> str:
        """Recursively flatten nested data structures to searchable text"""
        if depth > 10:  # Prevent infinite recursion
            return ""
        
        if isinstance(data, dict):
            texts = []
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    texts.append(self._flatten_alert_to_text(value, depth + 1))
                else:
                    texts.append(str(value))
            return " ".join(texts)
        elif isinstance(data, list):
            texts = []
            for item in data:
                texts.append(self._flatten_alert_to_text(item, depth + 1))
            return " ".join(texts)
        else:
            return str(data)
    
    def _create_ioc_summary(self, iocs: dict[str, list]) -> dict[str, Any]:
        """Create a summary of extracted IoCs"""
        summary = {
            "total_iocs": 0,
            "ioc_counts": {},
            "high_value_iocs": []
        }
        
        for ioc_type, values in iocs.items():
            count = len(values)
            summary["ioc_counts"][ioc_type] = count
            summary["total_iocs"] += count
            
            # Identify high-value IoCs (file hashes, specific IPs, etc.)
            if ioc_type in ["file_hashes", "ip_addresses"] and values:
                for value in values[:3]:  # Limit to first 3 for brevity
                    summary["high_value_iocs"].append({
                        "type": ioc_type,
                        "value": value
                    })
        
        return summary
