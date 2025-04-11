# import requests

# # Replace with your API keys
# MALWAREBAZAAR_API_KEY =
# VT_API_KEY =
# file_hash =

# def query_malwarebazaar(hash):
#     print("\n🔍 MalwareBazaar Results:")
#     url = "https://mb-api.abuse.ch/api/v1/"
#     headers = {
#         "Auth-Key": MALWAREBAZAAR_API_KEY
#     }
#     data = {
#         "query": "get_info",
#         "hash": hash
#     }

#     response = requests.post(url, headers=headers, data=data)
    
#     if response.status_code == 200:
#         result = response.json()
#         status = result.get("query_status")
#         if status == "ok" and result.get("data"):
#             entry = result["data"][0]
#             print(f"  🧠 Signature: {entry.get('signature')}")
#             print(f"  📎 File Name: {entry.get('file_name')}")
#             print(f"  📂 File Type: {entry.get('file_type')}")
#             print(f"  📅 First Seen: {entry.get('first_seen')}")
#             print(f"  🌍 Country: {entry.get('origin_country')}")
#             print(f"  🏷️ Tags: {', '.join(entry.get('tags', []))}")
#         else:
#             print("  ❌ No result found in MalwareBazaar.")
#     else:
#         print("  ❌ MalwareBazaar API error:", response.status_code)

# def query_virustotal(hash):
#     print("\n🔍 VirusTotal Results:")
#     url = f"https://www.virustotal.com/api/v3/files/{hash}"
#     headers = {
#         "x-apikey": VT_API_KEY
#     }

#     response = requests.get(url, headers=headers)

#     if response.status_code == 200:
#         data = response.json()
#         attr = data["data"]["attributes"]
#         stats = attr["last_analysis_stats"]
#         print(f"  🧪 Detection Engines:")
#         print(f"    Malicious:  {stats['malicious']}")
#         print(f"    Suspicious: {stats['suspicious']}")
#         print(f"    Harmless:   {stats['harmless']}")
#         print(f"    Undetected: {stats['undetected']}")
#         print(f"  🧬 Threat Name: {attr.get('popular_threat_name')}")
#         print(f"  🗂️ Type: {attr.get('type_description')}")
#         print(f"  ⏱️ First Submitted: {attr.get('first_submission_date')}")
#     else:
#         print("  ❌ VirusTotal API error:", response.status_code)

# # Run both lookups
# query_malwarebazaar(file_hash)
# query_virustotal(file_hash)
