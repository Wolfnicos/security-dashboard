"""IP geolocation using ip-api.com batch endpoint (free, no key required)."""

import requests

BATCH_URL = "http://ip-api.com/batch"
SINGLE_URL = "http://ip-api.com/json/{ip}"
FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,query"


def geolocate_ips(ip_list):
    """Geolocate a list of IPs using ip-api.com batch endpoint.

    Free tier: 15 requests/minute for single, 100 IPs per batch.
    Returns a dict mapping IP -> geo info.
    """
    if not ip_list:
        return {}

    unique_ips = list(set(ip_list))[:100]

    try:
        resp = requests.post(
            BATCH_URL,
            json=[{"query": ip, "fields": FIELDS} for ip in unique_ips],
            timeout=10,
        )
        resp.raise_for_status()
        results = resp.json()
    except (requests.RequestException, ValueError):
        return {}

    geo_map = {}
    for item in results:
        if item.get("status") == "success":
            geo_map[item["query"]] = {
                "country": item.get("country", "Unknown"),
                "country_code": item.get("countryCode", ""),
                "region": item.get("regionName", ""),
                "city": item.get("city", ""),
                "lat": item.get("lat", 0),
                "lon": item.get("lon", 0),
                "isp": item.get("isp", ""),
            }
        else:
            geo_map[item.get("query", "")] = {
                "country": "Private/Reserved",
                "country_code": "",
                "region": "",
                "city": "",
                "lat": 0,
                "lon": 0,
                "isp": "N/A",
            }

    return geo_map
