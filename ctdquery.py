#!/usr/bin/env python3
import argparse
import requests
import getpass
import sys
import os
import json

CONFIG_DIR = os.path.expanduser("~/.ctdquery")
TOKEN_FILE = os.path.join(CONFIG_DIR, "token")

SEARCHABLE_FIELDS = ["name", "ipv4", "hostname"]  # Easily expand this list

def asset_matches_search(asset, search_term):
    """Return True if asset matches the search term in any searchable field."""
    for field in SEARCHABLE_FIELDS:
        value = asset.get(field, "")
        if isinstance(value, list):
            # For fields like ipv4, which may be a list
            if any(search_term.lower() in str(v).lower() for v in value):
                return True
        elif search_term.lower() in str(value).lower():
            return True
    return False

def search_assets(assets_json, search_term):
    """Return filtered assets matching the search term."""
    objects = assets_json.get("objects") or []
    filtered = [a for a in objects if asset_matches_search(a, search_term)]
    return {"objects": filtered}


def save_token(token: str):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(TOKEN_FILE, "w") as f:
        f.write(token)


def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    return None


def login_and_get_token(host: str, username: str, password: str) -> str:
    url = f"https://{host}/auth/authenticate"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    data = {"username": username, "password": password}

    try:
        resp = requests.post(url, json=data, headers=headers, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Error during login: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        token = resp.json().get("token")
    except ValueError:
        print("Invalid JSON response from server", file=sys.stderr)
        sys.exit(1)

    if not token:
        print("No token in response", file=sys.stderr)
        sys.exit(1)

    save_token(token)
    return token


def get_token(host: str, provided_token: str = None) -> str:
    if provided_token:
        save_token(provided_token)
        return provided_token

    token = load_token()
    if token:
        return token

    # Ask for credentials
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return login_and_get_token(host, username, password)


def get_assets(host: str, token: str, site_id: str = None, per_page: int = 100):
    """Fetch all assets, with pagination"""
    headers = {"Accept": "application/json", "Authorization": token}
    # fields = {"id,name,hostname,ipv4,site_name,risk_score,asset_type__"}
    fields = {"resource_id,;$hostname,;$name,;$id,;$site_id,;$name,;$mac,;$ipv4,;$vendor,;$network_id,;$site_name,;$network,;$risk_score"}    
    page = 1
    all_objects = []

    print("Querying assets", end="")
    while True:
        params = {"page": page, "per_page": per_page, "fields": fields}
        if site_id:
            params["site_id__exact"] = site_id

        url = f"https://{host}/ranger/v2/assets"
        try:
            print(".", end="", flush=True)
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching assets: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            data = resp.json()
        except ValueError:
            print("Invalid JSON response when fetching assets", file=sys.stderr)
            sys.exit(1)

        objects = data.get("objects", [])
        if not objects:
            break

        all_objects.extend(objects)

        # stop if we got fewer results than per_page (last page)
        if len(objects) < per_page:
            break

        page += 1
    print(".")

    return {"objects": all_objects}


def get_sites(host: str, token: str):
    url = f"https://{host}/ranger/sites"
    headers = {"Accept": "application/json", "Authorization": token}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"Error fetching sites: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        return resp.json()
    except ValueError:
        print("Invalid JSON response when fetching sites", file=sys.stderr)
        sys.exit(1)


def get_alerts(host: str, token: str, site_id: str = None, per_page: int = 100):
    """Fetch all alerts, with pagination and optional site filter"""
    headers = {"Accept": "application/json", "Authorization": token}
    page = 1
    all_objects = []
    fields = {"id,;$site_id,;$severity,;$timestamp,;$description,;$assigned_to,;$type"}

    print("Querying alerts", end="")
    while True:
        # params = {"page": page, "per_page": per_page}
        params = {"fields": fields}
        if site_id:
            params["site_id__exact"] = site_id

        url = f"https://{host}/ranger/v2/alerts"
        try:
            print(".", end="", flush=True)
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching alerts: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            data = resp.json()
        except ValueError:
            print("Invalid JSON response when fetching alerts", file=sys.stderr)
            sys.exit(1)

        objects = data.get("objects", [])
        if not objects:
            break

        all_objects.extend(objects)

        if len(objects) < per_page:
            break

        page += 1
    print(".")

    return {"objects": all_objects}


def get_events(host: str, token: str, site_id: str = None, per_page: int = 100):
    """Fetch all events, with pagination and optional site filter"""
    headers = {"Accept": "application/json", "Authorization": token}
    page = 1
    all_objects = []
    # Add alert_id, site_id, description to fields
    fields = {"resource_id,;$status,;$id,;$type,;$timestamp,;$alert_id,;$site_id,;$description"}

    print("Querying events", end="")
    while True:
        params = {"fields": fields}
        if site_id:
            params["site_id__exact"] = site_id

        url = f"https://{host}/ranger/v2/events"
        try:
            print(".", end="", flush=True)
            resp = requests.get(url, headers=headers, params=params, timeout=20)
            resp.raise_for_status()
        except requests.RequestException as e:
            print(f"Error fetching events: {e}", file=sys.stderr)
            sys.exit(1)
        try:
            data = resp.json()
        except ValueError:
            print("Invalid JSON response when fetching events", file=sys.stderr)
            sys.exit(1)

        objects = data.get("objects", [])
        if not objects:
            break

        all_objects.extend(objects)

        if len(objects) < per_page:
            break

        page += 1
    print(".")

    return {"objects": all_objects}


def print_assets_pretty(assets_json):
    objects = assets_json.get("objects") or []
    if not objects:
        print("No assets found.")
        return

    header = f"{'ID':<6} {'Name':<30} {'Hostname':<20} {'IP':<15} {'Site':<10} {'Risk':<6} {'Type':<15} {"Network name":<15}"
    print(header)
    print("-" * len(header))

    for a in objects:
        asset_id = a.get("id", "")
        name = a.get("name", "")
        hostname = a.get("hostname", "")
        ipv4 = ""
        if isinstance(a.get("ipv4"), list) and a["ipv4"]:
            ipv4 = a["ipv4"][0]
        site = a.get("site_name", "")
        risk = a.get("risk_score", "")
        asset_type = a.get("asset_type__", "")
        network_name = ""
        if isinstance(a.get("network"), dict):
            network_name = a["network"].get("name", "")

        print(f"{asset_id:<6} {name:<30} {hostname:<20} {ipv4:<15} {site:<10} {risk:<6} {asset_type:<15} {network_name:<15}")


def print_sites_pretty(sites_json):
    objects = sites_json.get("objects") or []
    if not objects:
        print("No sites found.")
        return

    header = f"{'ID':<6} {'Name':<30}"
    print(header)
    print("-" * len(header))

    for s in objects:
        site_id = s.get("id", "")
        name = s.get("name", "")
        print(f"{site_id:<6} {name:<30}")

def print_alerts_pretty(alerts_json):
    objects = alerts_json.get("objects") or []
    if not objects:
        print("No alerts found.")
        return

    header = f"{'ID':<8} {'Type':<20} {'Severity':<10} {'Site':<10} {'Time':<20} {'Assigned to':<35} {'Description':<40}"
    print(header)
    print("-" * len(header))

    for a in objects:
        alert_id = a.get("id", "")
        alert_type = a.get("type", "")
        severity = a.get("severity__", "")
        site = a.get("site_id", "")
        time = a.get("timestamp", "")
        assigned_to = a.get("assigned_to", "")
        # Only show "username" from assigned_to
        assigned_to_str = ""
        if isinstance(assigned_to, dict) and "username" in assigned_to:
            assigned_to_str = str(assigned_to["username"])
        elif isinstance(assigned_to, list):
            assigned_to_str = ", ".join(
                str(x.get("username", "")) if isinstance(x, dict) else str(x)
                for x in assigned_to
            )
        elif assigned_to is not None:
            assigned_to_str = str(assigned_to)
        description = a.get("description", "")
        print(f"{alert_id:<8} {alert_type:<20} {severity:<10} {site:<10} {time:<20} {assigned_to_str:<35} {description:<40}")


def print_events_pretty(events_json):
    objects = events_json.get("objects") or []
    if not objects:
        print("No events found.")
        return

    header = f"{'ID':<8} {'Resource ID':<20} {'Type':<15} {'Status':<10} {'Timestamp':<20} {'Alert ID':<12} {'Site ID':<10} {'Description':<40}"
    print(header)
    print("-" * len(header))

    for e in objects:
        event_id = e.get("id", "")
        resource_id = e.get("resource_id", "")
        event_type = e.get("type", "")
        status = e.get("status", "")
        timestamp = e.get("timestamp", "")
        alert_id = e.get("alert_id", "")
        site_id = e.get("site_id", "")
        description = e.get("description", "")
        print(f"{event_id:<8} {resource_id:<20} {event_type:<15} {status:<10} {timestamp:<20} {alert_id:<12} {site_id:<10} {description:<40}")


def get_events_for_all_sites(host: str, token: str, per_page: int = 100):
    """Fetch events for all sites"""
    sites_json = get_sites(host, token)
    sites = sites_json.get("objects", [])
    all_events = []
    for site in sites:
        site_id = site.get("id")
        print(f"\nSite: {site.get('name', '')} (ID: {site_id})")
        events = get_events(host, token, site_id, per_page)
        for event in events.get("objects", []):
            event["site_id"] = site_id  # Ensure site_id is set
            all_events.append(event)
        print_events_pretty(events)
    return {"objects": all_events}

def get_alerts_for_all_sites(host: str, token: str, per_page: int = 100):
    """Fetch alerts for all sites"""
    sites_json = get_sites(host, token)
    sites = sites_json.get("objects", [])
    all_alerts = []
    for site in sites:
        site_id = site.get("id")
        print(f"\nSite: {site.get('name', '')} (ID: {site_id})")
        alerts = get_alerts(host, token, site_id, per_page)
        for alert in alerts.get("objects", []):
            alert["site_id"] = site_id  # Ensure site_id is set
            all_alerts.append(alert)
        print_alerts_pretty(alerts)
    return {"objects": all_alerts}


def main():
    parser = argparse.ArgumentParser(description="CTD Query CLI Tool")
    parser.add_argument("host", help="Target host (e.g. api.example.com)", nargs="?")
    parser.add_argument("--token", help="Provide an existing token (otherwise credentials will be asked)", default=None)
    parser.add_argument("--assets", action="store_true", help="Fetch and print all assets")
    parser.add_argument("--sites", action="store_true", help="Fetch and print all sites")
    parser.add_argument("--alerts", action="store_true", help="Fetch and print all alerts")  # <-- Add this line
    parser.add_argument("--events", action="store_true", help="Fetch and print all events")
    parser.add_argument("--site", help="Limit assets to a specific site ID")
    parser.add_argument("--pretty", action="store_true", help="Pretty print output")
    parser.add_argument("--search", help="Search assets by name, ipv4, hostname", default=None)  # <-- Add this line

    args = parser.parse_args()

    # Require at least one argument
    if not args.host:
        parser.print_help()
        sys.exit(1)

    # If only host is provided, always obtain a new token with username/password
    if (
        args.host
        and not args.assets
        and not args.sites
        and not args.alerts
        and not args.search
        and not args.site
        and not args.token
        and not args.pretty
    ):
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        token = login_and_get_token(args.host, username, password)
        print(token)
        return

    token = get_token(args.host, args.token)

    if args.sites:
        sites = get_sites(args.host, token)
        if args.pretty:
            print_sites_pretty(sites)
        else:
            print(json.dumps(sites, indent=2))
        return

    if args.assets:
        assets = get_assets(args.host, token, args.site)
        if args.search:
            assets = search_assets(assets, args.search)
        if args.pretty:
            print_assets_pretty(assets)
        else:
            print(json.dumps(assets, indent=2))
        return

    if args.alerts:
        if args.site:
            alerts = get_alerts(args.host, token, args.site)
            if args.pretty:
                print_alerts_pretty(alerts)
            else:
                print(json.dumps(alerts, indent=2))
        else:
            # Query all sites
            alerts = get_alerts_for_all_sites(args.host, token)
            if not args.pretty:
                print(json.dumps(alerts, indent=2))
        return

    if args.events:
        if args.site:
            events = get_events(args.host, token, args.site)
            if args.pretty:
                print_events_pretty(events)
            else:
                print(json.dumps(events, indent=2))
        else:
            # Query all sites
            events = get_events_for_all_sites(args.host, token)
            if not args.pretty:
                print(json.dumps(events, indent=2))
        return

    # Default: just print token
    print(token)

if __name__ == "__main__":
    main()
