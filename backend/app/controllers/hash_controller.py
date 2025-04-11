import requests
from typing import Dict, Any
from dotenv import load_dotenv
load_dotenv()

import os

# Your API keys
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

if not MALWAREBAZAAR_API_KEY or not VT_API_KEY:
    raise EnvironmentError("Missing API keys! Please set MALWAREBAZAAR_API_KEY and VT_API_KEY in your environment.")


def query_malwarebazaar(hash_str: str) -> Dict[str, Any]:
    """
    Query MalwareBazaar with a given file hash.
    Returns a dictionary with relevant fields or an error message.
    """
    url = "https://mb-api.abuse.ch/api/v1/"
    headers = {"Auth-Key": MALWAREBAZAAR_API_KEY}
    data = {
        "query": "get_info",
        "hash": hash_str
    }

    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        status = result.get("query_status")
        if status == "ok" and result.get("data"):
            entry = result["data"][0]
            return {
                "signature": entry.get("signature"),
                "file_name": entry.get("file_name"),
                "file_type": entry.get("file_type"),
                "first_seen": entry.get("first_seen"),
                "origin_country": entry.get("origin_country"),
                "tags": entry.get("tags", [])
            }
        else:
            return {"error": "No result found in MalwareBazaar."}
    else:
        return {"error": f"MalwareBazaar API error. Status code: {response.status_code}"}

def query_virustotal(hash_str: str) -> Dict[str, Any]:
    """
    Query VirusTotal with a given file hash.
    Returns a dictionary with relevant fields or an error message.
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_str}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        attr = data["data"]["attributes"]
        stats = attr["last_analysis_stats"]
        return {
            "analysis_stats": {
                "malicious": stats['malicious'],
                "suspicious": stats['suspicious'],
                "harmless": stats.get('harmless', 0),
                "undetected": stats['undetected']
            },
            "threat_name": attr.get('popular_threat_name'),
            "type_description": attr.get('type_description'),
            "first_submission_date": attr.get('first_submission_date')
        }
    else:
        return {"error": f"VirusTotal API error. Status code: {response.status_code}"}

def check_hash(hash_str: str) -> Dict[str, Any]:
    """
    High-level function to query both services and return combined results as a single dictionary.
    """
    mb_result = query_malwarebazaar(hash_str)
    vt_result = query_virustotal(hash_str)
    return {
        "malwarebazaar": mb_result,
        "virustotal": vt_result
    }
