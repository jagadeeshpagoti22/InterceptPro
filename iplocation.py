import requests
import ipaddress


def is_public_ip(ip_str: str) -> bool:
    """
    Check if the given IP is a valid public (global) IP address.
    Returns True if it is public, False if private/reserved/loopback/etc.
    Raises ValueError if the string is not a valid IP at all.
    """
    ip_obj = ipaddress.ip_address(ip_str)
    return ip_obj.is_global


def get_ip_location(ip_address: str) -> dict:
    """
    Get approximate location information for a given PUBLIC IP address
    using the ip-api.com free API.

    NOTE:
    - Location is approximate (city/region/lat/lon), NOT exact house GPS.
    """
    url = (
        "http://ip-api.com/json/"
        f"{ip_address}"
        "?fields=status,message,query,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname"
    )

    response = requests.get(url, timeout=5)
    response.raise_for_status()
    data = response.json()

    if data.get("status") != "success":
        msg = data.get("message", "Unknown error from API")
        raise ValueError(f"API error: {msg}")

    # Build result dict
    details = {
        "ip": data.get("query"),
        "country": data.get("country"),
        "regionName": data.get("regionName"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "org": data.get("org"),
        "as": data.get("as"),
        "asname": data.get("asname"),
    }

    return details


def print_location(details: dict) -> None:
    """
    Print IP location details and Google Maps URL.
    """
    ip = details["ip"]
    lat = details["latitude"]
    lon = details["longitude"]

    print("\n===== IP LOCATION DETAILS =====")
    print(f"IP Address   : {ip}")
    print(f"Country      : {details['country']}")
    print(f"Region/State : {details['regionName']}")
    print(f"City         : {details['city']}")
    print(f"ZIP Code     : {details['zip']}")
    print(f"Timezone     : {details['timezone']}")
    print()
    print("--- Coordinates (from IP database) ---")
    print(f"Latitude     : {lat}")
    print(f"Longitude    : {lon}")
    print("--------------------------------------")
    print()
    print(f"ISP          : {details['isp']}")
    print(f"Organization : {details['org']}")
    print(f"AS / ASN     : {details['as']}")
    print(f"AS Name      : {details['asname']}")
    print()
    maps_url = f"https://www.google.com/maps?q={lat},{lon}"
    print("Open this URL in your browser to see it on Google Maps:")
    print(maps_url)
    print("======================================\n")


if __name__ == "__main__":
    print("=== IP Exact Location Tracker (Approx via IP) ===")
    ip_input = input("Enter an IP address (e.g., 8.8.8.8): ").strip()

    if not ip_input:
        print("No IP entered. Exiting.")
    else:
        try:
            # 1) Check if IP is valid
            if not is_public_ip(ip_input):
                print("\nThis IP is NOT a public internet IP.")
                print("It is probably PRIVATE (like 192.168.x.x / 10.x.x.x) or RESERVED.")
                print("Such IPs do NOT have public geolocation records.\n")
            else:
                # 2) Get geo location of the IP
                details = get_ip_location(ip_input)
                # 3) Print nicely + Google Maps link
                print_location(details)

        except ValueError as ve:
            print(f"Error: {ve}")
        except requests.exceptions.RequestException as re:
            print(f"Network error: {re}")
        except Exception as e:
            print(f"Unexpected error: {e}")
