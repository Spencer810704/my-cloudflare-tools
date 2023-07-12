import json
import requests

E_MAIL=""
AUTH_KEY=""

def get_waf_rule_id(zone_id: str) -> list:
    API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}

    resp = requests.get(url=API, headers=headers)
    waf_rules = resp.json()['result']
    return [rule['id'] for rule in waf_rules]
        
def get_filter_id(zone_id: str) -> list:
    API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/filters"
    headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}

    resp = requests.get(url=API, headers=headers)
    filters = resp.json()['result']
    return [filter['id'] for filter in filters]
        
def del_all_waf_rules(zone_id: str):
    filter_id_list = get_filter_id(zone_id=zone['zone_id'])
    waf_rule_id_list = get_waf_rule_id(zone_id=zone['zone_id'])
    print("ready to delete waf rules")
    for waf_rule_id in waf_rule_id_list:
            
        API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules/{waf_rule_id}"
        headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}
        resp = requests.delete(url=API, headers=headers)
        data = resp.json()
        print(data)

    print("ready to delete filter object")
    for filter_id in filter_id_list:
        API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/filters/{filter_id}"
        headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}
        resp = requests.delete(url=API, headers=headers)
        data = resp.json()
        print(data)

def get_customer_country(wl_code: str):
    if len(wl_code.split(" ")) == 2:
        # 取首字母判別國家
        first_word = wl_code.split(" ")[0][0]
        
        if first_word.lower() == "h" or first_word.lower() == "c":
            return '{"CN" "HK"}'
        else:
            return '{"VN" "TH" "IN" "PH" "MY" "ID" "KH" "BD"}'

        # # 泰國
        # if first_word.lower() == "t" or first_word.lower() == "o" or first_word.lower() == "f":
        #     return '{"TH"}'

        # # 越南
        # elif first_word.lower() == "v" or first_word.lower() == "z":
        #     return '{"VN" "PH" "KH"}'

        # # 印度
        # elif first_word.lower() == "r" or first_word.lower() == "n":
        #     return '{"IN"}'

        # # 菲律賓
        # elif first_word.lower() == "p" or first_word.lower() == "y":
        #     return '{"PH"}'
        
        # # 馬來西亞
        # elif first_word.lower() == "m":
        #     return '{"MY"}'

        # # 香港、中國
        # elif first_word.lower() == "h" or first_word.lower() == "c":
        #     return '{"CN" "HK"}'
        
        # # 印尼
        # elif first_word.lower() == "i":
        #     return '{"ID"}'
        
        # # 香港、中國開頭
        # elif first_word.lower() == "u":
        #     return '{"US"}'

        # # 柬埔寨、孟加拉
        # elif first_word.lower() == "s" or first_word.lower() == "e":
        #     return '{"KH" "BD"}'
        
        # else:
        #     return '{"VN" "TH" "IN" "PH" "MY" "HK" "ID" "US" "CN" "KH" "BD"}'
        
def add_waf_rule(zone_id: str, zone_name: str, wl_code: str):
    
    API = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/rules"
    headers = {"X-Auth-Key": f"{AUTH_KEY}", "X-Auth-Email": f"{E_MAIL}", "Content-Type": "application/json"}

    payload = [
        # 允許已知Bot
        {"paused": False, "description": "allow_known_bots", "action": "allow","filter": {"expression": "(cf.client.bot)", "paused": False}},
        # 阻擋已知惡意IP列表
        {"paused": False, "description": "blocked_malicious_ip", "action": "block", "filter": {"expression": "(ip.src in $blocked_ips)", "paused": False}},
        # 阻擋國家
        {"paused": True, "description": "block_other_country", "action": "block", "filter": {"expression": f"(not ip.geoip.country in {get_customer_country(wl_code)})", "paused": False}}
    ]
    print(payload)
    resp = requests.post(url=API, headers=headers, json=payload)
    if resp.status_code == 200:
        print("新增成功")
    else:
        print("新增失敗")
    # data = resp.json()['result']
    # print(data)


if __name__ == "__main__":
    # 讀取所有站點的zone資訊
    with open("./data/all_whitelabel_zones.json") as f:
        zones = json.load(f)
    
    # # 測試資料
    # zones = [{
    #     "zone_id": "d3352d5629f354380cd03d099d9fc9a9",
    #     "zone_name": "ottotest.com",
    #     "wl_code": "t01 test"
    # }]
    
    # 讀配置
    with open("config/config.json", "r") as file:
        # Load JSON file
        config = json.load(file)

        # 讀取欄位
        E_MAIL = config.get("E_MAIL", None)
        AUTH_KEY = config.get("AUTH_KEY", None)

        # E_MAIL="spencer810704@gmail.com"
        # AUTH_KEY="4d2f1db255038ba44f921204f7de90f56f791"

    # 刪除所有zone的Waf rule (需要刪除 filter & rule )
    # print("delete all waf rules")
    # for zone in zones:   
        
        # print(f"準備刪除{zone['zone_name']} WAF rules")
        # del_all_waf_rules(zone_id=zone['zone_id'])

    print("add waf rules")
    for zone in zones:   
        if zone.get("wl_code", None) is None:
            continue
        # 初始化
        print(f"準備新增{zone['zone_name']} WAF rules")
        add_waf_rule(zone_id=zone['zone_id'], zone_name=zone['zone_name'], wl_code=zone['wl_code'])