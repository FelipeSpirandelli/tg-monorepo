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

        return {"extracted_iocs": iocs, "enriched_alert": enriched_alert}

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
                temperature=0.1,  # Low temperature for precise extraction
            )

            # Parse LLM response to extract structured IoCs
            iocs = self._parse_llm_ioc_response(response)

            # Check if parsing was successful by verifying we got valid IoCs
            if iocs and not self._is_empty_iocs(iocs):
                logger.info("Successfully extracted IoCs using LLM")
                return iocs
            else:
                logger.warning("LLM returned empty or invalid IoCs")
                return self._get_empty_iocs_dict()

        except Exception as e:
            logger.error(f"Error in LLM IoC extraction: {str(e)}")
            return self._get_empty_iocs_dict()

    def _create_ioc_extraction_prompt(self, alert_data: dict[str, Any]) -> str:
        """Create a prompt for LLM to extract IoCs"""

        # Convert alert data to a formatted string
        alert_json = json.dumps(alert_data, indent=2, default=str)

        prompt = f"""You are a professional cybersecurity analyst whose *only* job is to extract syntactically valid Indicators of Compromise (IoCs) from raw alert data.

TASK
- Extract ONLY syntactically valid IoCs from the ALERT DATA below.
- Do not guess, infer, or invent values.
- If a token resembles an IoC but **fails strict validation**, place it in "ambiguous_tokens" (see rules).
- Do NOT include internal instance IDs, request IDs, or cloud resource IDs (e.g., AWS instance ids like "i-0123...") as IPs — those belong in ambiguous_tokens if present.

ALERT DATA:
{alert_json}

OUTPUT FORMAT (MUST BE EXACT)
Respond with ONLY a single JSON object and nothing else. Keys must exist and values must be arrays (unique values only):

{{
  "ip_addresses": [],         # valid IPv4 or IPv6 (e.g. "1.2.3.4" or "2001:db8::1")
  "domains": [],              # hostnames/domains only, lowercase, no scheme or path (e.g. "example.com")
  "urls": [],                 # full URLs with scheme and host (e.g. "https://example.com/path")
  "file_hashes": [],          # MD5/SHA1/SHA256 hex only (32/40/64 hex characters)
  "file_paths": [],           # OS file paths (must contain "/" or "\\" for Windows paths)
  "processes": [],            # executable or process basenames (e.g. "rundll32.exe", "ssh")
  "user_accounts": [],        # usernames or account identifiers (no spaces)
  "registry_keys": [],        # Windows registry key paths (start with HK... or HKEY_...)
  "ports": [],                # integers 0-65535 (no ranges, single numbers only)
  "email_addresses": [],      # valid email addresses (syntactic)
  "mitre_techniques": [],     # ATT&CK IDs (e.g. "T1110", "TA0006", "T1110.001")
  "ambiguous_tokens": []      # tokens that LOOK like IoCs but fail strict syntactic validation
}}

VALIDATION RULES (APPLY THESE)
- ip_addresses: must parse with standard IPv4/IPv6 rules; reject hostnames (e.g., "host.example.com" is NOT an IP). Do NOT accept values with embedded colons if they are hostname:port forms.
- domains: must be lowercase, contain at least one dot, follow hostname label rules (each label 1-63 chars, total <=253), TLD >=2 letters; do NOT include "http://" or any path.
- urls: must include scheme (http/https/ftp) and a valid host (domain or IP). Accept URLs with ports; do not place host:port into ip_addresses or domains.
- file_hashes: exact hex lengths only (32/40/64). Case-insensitive; no surrounding punctuation.
- file_paths: must contain "/" or "\\", not be just filenames.
- processes: prefer basenames (strip directories). Exclude extremely short or generic shells (see note below) into ambiguous_tokens.
- ports: integers only; 0 <= port <= 65535.
- email_addresses: syntactically valid (single @, domain-like RHS).
- mitre_techniques: uppercase "T" or "TA" prefix followed by digits, optionally sub-technique ".###".
- ambiguous_tokens: collect tokens that resemble IoCs but fail the above checks (do not drop them).

NORMALIZATION & DEDUPING
- Domains must be returned lowercase and deduplicated.
- URLs must be returned normalized (no trailing spaces).
- Return only unique values per key (no duplicates).

HANDLING NOISE / SPECIAL CASES
- AWS/GCP/Azure resource IDs (e.g., "i-...", "vm-...", request IDs) -> ambiguous_tokens (they are not IPs).
- Internal console links (kibana, splunk) that contain long session or dashboard paths: include in "urls" only if they contain a host; otherwise move to ambiguous_tokens if they look like ephemeral IDs.
- If a value contains both host and port (e.g., "1.2.3.4:8080"), place the full text in "urls" only if it is a valid URL with scheme; otherwise place host in ip_addresses only if it passes IP validation and put the port in "ports".
  - **Do NOT** put "host:port" into `ip_addresses`.

EXAMPLES
- Valid ip_addresses: "8.8.8.8"
- Invalid ip_addresses (put to ambiguous_tokens instead): "i-0a4647b91f8bffcfc.elasticlabs.training" (this is a hostname/instance-id, not an IP)
- Valid domain: "attack.mitre.org"
- Valid url: "https://attack.mitre.org/techniques/T1110/"
- Valid hash: "d41d8cd98f00b204e9800998ecf8427e" (MD5)
- Valid port: 443

OTHER REQUIREMENTS
- If nothing valid exists for a key, return an empty array.
- Output must be pure JSON only (no markdown, no explanations, no extra keys).
- Do not return duplicate values.
- Keep responses compact — list only the values, no annotations.

If a token is suspicious but syntactically invalid, include it in "ambiguous_tokens" so human analysts can triage.
"""

        return prompt

    def _parse_llm_ioc_response(self, response: str) -> dict[str, list]:
        """Parse LLM response to extract structured IoCs"""
        try:
            # Log the raw response for debugging
            logger.debug(f"Raw LLM response: {response[:500]}...")

            # Try to find JSON in the response
            json_start = response.find("{")
            json_end = response.rfind("}")

            if json_start == -1 or json_end == -1:
                logger.warning("No JSON brackets found in LLM response")
                return self._get_empty_iocs_dict()

            if json_end <= json_start:
                logger.warning("Invalid JSON bracket positions in LLM response")
                return self._get_empty_iocs_dict()

            json_str = response[json_start : json_end + 1].strip()

            # Log the extracted JSON string for debugging
            logger.debug(f"Extracted JSON string: {json_str}")

            # Try multiple approaches to parse the JSON
            iocs = self._try_parse_json_multiple_ways(json_str)

            if not iocs:
                logger.warning("All JSON parsing attempts failed")
                return self._get_empty_iocs_dict()

            # Ensure all expected keys exist
            expected_keys = [
                "ip_addresses",
                "domains",
                "file_hashes",
                "file_paths",
                "processes",
                "urls",
                "user_accounts",
                "registry_keys",
                "ports",
                "email_addresses",
                "mitre_techniques",
            ]

            for key in expected_keys:
                if key not in iocs:
                    iocs[key] = []
                elif not isinstance(iocs[key], list):
                    iocs[key] = []

            # Clean and validate the data
            iocs = self._clean_and_validate_iocs(iocs)

            total_iocs = sum(len(v) for v in iocs.values())
            logger.info(f"Successfully parsed IoCs from LLM response: {total_iocs} total IoCs")
            return iocs

        except Exception as e:
            logger.error(f"Error parsing LLM response: {str(e)}")
            return self._get_empty_iocs_dict()

    def _try_parse_json_multiple_ways(self, json_str: str) -> dict[str, list] | None:
        """Try multiple approaches to parse potentially malformed JSON"""

        # Method 1: Direct JSON parsing
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            logger.debug(f"Direct JSON parsing failed: {str(e)}")

        # Method 2: Try to fix common JSON issues
        try:
            # Fix single quotes to double quotes
            fixed_json = json_str.replace("'", '"')
            return json.loads(fixed_json)
        except json.JSONDecodeError as e:
            logger.debug(f"Fixed quotes JSON parsing failed: {str(e)}")

        # Method 3: Try to extract and parse line by line (for partial JSON)
        try:
            # Look for patterns like "key": [values] or "key": []
            import ast

            # If it's a Python-style dict, try ast.literal_eval
            if json_str.strip().startswith("{") and ":" in json_str:
                try:
                    result = ast.literal_eval(json_str)
                    if isinstance(result, dict):
                        return result
                except (ValueError, SyntaxError):
                    pass

        except Exception as e:
            logger.debug(f"Alternative parsing failed: {str(e)}")

        # Method 4: Try to manually parse key-value pairs
        try:
            return self._manual_json_parse(json_str)
        except Exception as e:
            logger.debug(f"Manual JSON parsing failed: {str(e)}")

        return None

    def _manual_json_parse(self, json_str: str) -> dict[str, list] | None:
        """Manually parse JSON-like structure when standard parsing fails"""
        try:
            # Initialize empty result
            result = self._get_empty_iocs_dict()

            # Look for patterns like "key": [...] or 'key': [...]
            import re

            # Find all key-value pairs
            pattern = r'["\'](\w+)["\']\s*:\s*\[(.*?)\]'
            matches = re.findall(pattern, json_str, re.DOTALL)

            for key, value_str in matches:
                if key in result:
                    # Parse the array values
                    if value_str.strip():
                        # Split by comma and clean up values
                        values = []
                        for item in value_str.split(","):
                            item = item.strip().strip("\"'")
                            if item:
                                values.append(item)
                        result[key] = values
                    else:
                        result[key] = []

            return result

        except Exception:
            return None

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
                elif isinstance(value, int | float) and ioc_type == "ports":
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
            parts = value.split(".")
            if len(parts) == 4:
                try:
                    return all(0 <= int(part) <= 255 for part in parts)
                except ValueError:
                    return False
        elif ioc_type == "domains":
            # Basic domain validation
            return "." in value and not value.startswith(".") and not value.endswith(".")
        elif ioc_type == "file_hashes":
            # Basic hash validation
            return len(value) in [32, 40, 64] and all(c in "0123456789abcdefABCDEF" for c in value)
        elif ioc_type == "urls":
            # Basic URL validation
            return value.startswith(("http://", "https://", "ftp://"))

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
            "mitre_techniques": [],
        }

    def _is_empty_iocs(self, iocs: dict[str, list]) -> bool:
        """Check if IoCs dictionary contains any actual IoCs"""
        if not iocs:
            return True

        # Check if all lists are empty
        for ioc_list in iocs.values():
            if ioc_list and len(ioc_list) > 0:
                return False

        return True

    def _extract_basic_iocs(self, alert_data: dict[str, Any], iocs: dict[str, list]) -> None:
        """Extract IoCs using regex patterns from all text fields"""

        # Convert alert data to searchable text
        searchable_text = self._flatten_alert_to_text(alert_data)

        # IP address pattern (IPv4)
        ip_pattern = (
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        )
        ip_matches = re.findall(ip_pattern, searchable_text)
        iocs["ip_addresses"].extend(list(set(ip_matches)))

        # Domain pattern
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
        domain_matches = re.findall(domain_pattern, searchable_text)
        # Filter out common false positives
        filtered_domains = [d for d in domain_matches if not d.endswith((".exe", ".dll", ".sys", ".log"))]
        iocs["domains"].extend(list(set(filtered_domains)))

        # Hash patterns (MD5, SHA1, SHA256)
        hash_patterns = [
            r"\b[a-fA-F0-9]{32}\b",  # MD5
            r"\b[a-fA-F0-9]{40}\b",  # SHA1
            r"\b[a-fA-F0-9]{64}\b",  # SHA256
        ]
        for pattern in hash_patterns:
            hash_matches = re.findall(pattern, searchable_text)
            iocs["file_hashes"].extend(list(set(hash_matches)))

        # File path patterns
        file_path_patterns = [
            r'[C-Z]:\\[^<>:"|?*\n\r]+',  # Windows paths
            r"/[a-zA-Z0-9_\-./]+",  # Unix paths
        ]
        for pattern in file_path_patterns:
            path_matches = re.findall(pattern, searchable_text)
            iocs["file_paths"].extend(list(set(path_matches)))

        # URL pattern
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;!?]'
        url_matches = re.findall(url_pattern, searchable_text)
        iocs["urls"].extend(list(set(url_matches)))

        # Port pattern
        port_pattern = r":(\d{1,5})\b"
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
                "protocols": [],
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
            for _key, value in data.items():
                if isinstance(value, dict | list):
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
        summary = {"total_iocs": 0, "ioc_counts": {}, "high_value_iocs": []}

        for ioc_type, values in iocs.items():
            count = len(values)
            summary["ioc_counts"][ioc_type] = count
            summary["total_iocs"] += count

            # Identify high-value IoCs (file hashes, specific IPs, etc.)
            if ioc_type in ["file_hashes", "ip_addresses"] and values:
                for value in values[:3]:  # Limit to first 3 for brevity
                    summary["high_value_iocs"].append({"type": ioc_type, "value": value})

        return summary
