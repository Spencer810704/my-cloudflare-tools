import json

if __name__ == "__main__":
    
    with open("data/whitelable_info.json", "r") as file:
        # Load JSON file
        whitelabel_info_list = json.load(file)

    with open("data/all_zones.json", "r") as file:
        # Load JSON file
        cloudflare_zones = json.load(file)

    for zone in cloudflare_zones:
        for whitelabel in whitelabel_info_list:
            
            if zone['zone_name'] in whitelabel['domain'].encode().decode('idna'):
                zone.update({"wl_code": whitelabel['wl_code']})
                
    # 寫入
    with open("./data/all_whitelabel_zones.json", "w", encoding='utf8') as f:
        f.write(json.dumps(cloudflare_zones, indent=4,ensure_ascii=False))


    # for zone in cloudflare_zones:
    #     print(zone)