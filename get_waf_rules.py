import json
import requests

E_MAIL=""
AUTH_KEY=""

def list_waf_rule(zone_id: str, zone_name: str):
    
    
    API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}

    resp = requests.get(url=API, headers=headers)
    data = resp.json()['result']
    for item in data:
        if item['filter']['expression'] != "(ip.src in $blocked_ips)":
            print(f"zone id: {zone_id} , zone name: {zone_name}")
            print(item['filter'])
            print("================================================")


if __name__ == "__main__":
    # 讀取所有站點的zone資訊
    with open("./data/all_zones.json") as f:
        zones = json.load(f)

    # 讀配置
    with open("config/config.json", "r") as file:
        # Load JSON file
        config = json.load(file)

        # 讀取欄位
        E_MAIL = config.get("E_MAIL", None)
        AUTH_KEY = config.get("AUTH_KEY", None)

    for zone in zones:
        zone_id = zone['zone_id']
        zone_name = zone['zone_name']
        list_waf_rule(zone_id=zone_id, zone_name=zone_name)