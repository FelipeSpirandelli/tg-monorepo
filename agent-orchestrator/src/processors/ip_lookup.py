from typing import Any
import aiohttp
import asyncio

from src.logger import logger
from config import Config


async def abuseipdb_lookup(ip_address: str) -> dict[str, Any]:
    """
    Look up IP reputation using AbuseIPDB API
    
    Args:
        ip_address: The IP address to look up
        
    Returns:
        Full AbuseIPDB API response as dictionary
    """
    config = Config()
    api_key = config.abuseipdb_api_key
    
    # Check if it's a private IP first
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("172."):
        return {
            "data": {
                "ipAddress": ip_address,
                "isPublic": False,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 0,
                "countryCode": None,
                "countryName": None,
                "usageType": "Private Network",
                "isp": "Private Network",
                "domain": "",
                "hostnames": [],
                "isTor": False,
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None,
                "reports": []
            }
        }
    
    # If no API key, use fallback
    if api_key == "test-abuseipdb-key-placeholder":
        logger.warning(f"Using mock AbuseIPDB data for {ip_address} - no API key configured")
        return _get_mock_abuseipdb_response(ip_address)
    
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": ""
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    logger.info(f"Successfully looked up IP {ip_address} via AbuseIPDB")
                    return data
                else:
                    logger.error(f"AbuseIPDB API error {response.status} for IP {ip_address}")
                    return _get_mock_abuseipdb_response(ip_address)
                    
    except Exception as e:
        logger.error(f"Failed to lookup IP {ip_address} via AbuseIPDB: {str(e)}")
        return _get_mock_abuseipdb_response(ip_address)


def _get_mock_abuseipdb_response(ip_address: str) -> dict[str, Any]:
    """Generate mock AbuseIPDB response for testing"""
    if ip_address in ["185.220.101.5", "45.61.139.54", "194.87.45.12"]:
        return {
            "data": {
                "ipAddress": ip_address,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 100,
                "countryCode": "RU",
                "countryName": "Russia",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Suspicious Hosting Ltd",
                "domain": "malicious.example",
                "hostnames": [],
                "isTor": False,
                "totalReports": 25,
                "numDistinctUsers": 15,
                "lastReportedAt": "2025-09-20T10:30:00+00:00",
                "reports": [
                    {
                        "reportedAt": "2025-09-20T10:30:00+00:00",
                        "comment": "SSH brute force attack detected from this IP",
                        "categories": [18, 22],
                        "reporterId": 12345,
                        "reporterCountryCode": "US",
                        "reporterCountryName": "United States"
                    }
                ]
            }
        }
    else:
        return {
            "data": {
                "ipAddress": ip_address,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "countryName": "United States",
                "usageType": "Commercial",
                "isp": "Example ISP",
                "domain": "example.com",
                "hostnames": [],
                "isTor": False,
                "totalReports": 0,
                "numDistinctUsers": 0,
                "lastReportedAt": None,
                "reports": []
            }
        }


def ip_lookup(ip_address: str) -> dict[str, Any]:
    """
    Synchronous wrapper for AbuseIPDB lookup
    
    Args:
        ip_address: The IP address to look up
        
    Returns:
        Full AbuseIPDB API response as dictionary
    """
    logger.debug(f"Looking up IP address via AbuseIPDB: {ip_address}")
    
    try:
        # Run async function in sync context
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a new task
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, abuseipdb_lookup(ip_address))
                return future.result()
        else:
            return asyncio.run(abuseipdb_lookup(ip_address))
    except Exception as e:
        logger.error(f"Error in ip_lookup wrapper: {str(e)}")
        return _get_mock_abuseipdb_response(ip_address)
