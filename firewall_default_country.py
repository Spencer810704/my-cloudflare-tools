#!/usr/bin/env python
# coding: UTF-8

import argparse
import json
import os
import sys
from time import sleep
import requests
import re
import CloudFlare



parser = argparse.ArgumentParser()
parser.add_argument("--domains", nargs = '+')
parser.add_argument("--API_TOKEN")
parser.add_argument("--paused")
parser.add_argument("--wl")
args = parser.parse_args()


class cloudflare(object):
    def __init__(self, domain):
        self.endpoint = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "X-Auth-Email": "encloudse@gmail.com",
            "X-Auth-Key": args.API_TOKEN,
            "Content-Type": "application/json"
        }
        self.domain = domain
        #zone id
        self.url = "%s/zones?name=%s" % (self.endpoint, self.domain)
        r = requests.get(self.url, headers=self.headers)
        self.zone_id = r.json()['result'][0]['id']


    def enterpise_detect(self):
        record_url = "%s/zones/%s/dns_records" % (self.endpoint, self.zone_id)
        r = requests.get(record_url, headers=self.headers)
        if "bzkyman.com" in r.text:
            print("此域名為企業版, 操作無效, 腳本自動退出")
            os._exit(0)


# 判斷規則是否存在, 不存在就創建規則(default)
    def get_rules(self, paused=True, wl="c"):
        firewall_url = "%s/zones/%s/firewall/rules" % (self.endpoint, self.zone_id)
        r = requests.get(firewall_url, headers=self.headers)
        if "default_country" in r.text:
            print("規則存在,執行切換")
            for r in r.json()['result']:
                if "geoip.country" in r['filter']['expression']:
                    r['paused'] = paused
                    r['filter']['paused'] = paused
                    # firewall_data = [{'paused': True, 'description': 'country', 'action': 'block', 'filter': {'expression': '(not ip.geoip.country in {"CN" "HK"})', 'paused': True}}]
                    sleep(1)
                    print(type(wl))
                    print(wl)
                    print(type(paused))
                    print(paused)
                    print(r)

                    result = requests.put(firewall_url + '/' + r['id'], headers=self.headers, data=json.dumps(r))
                    print(result.text)
        else:
            print("規則不存在, 執行添加並啟用防護")
            wl_dic = {
                'c' : {'expression': '(not ip.geoip.country in {"CN" "HK"})', 'paused': False},
                'v' : {'expression': '(not ip.geoip.country in {"VN"})', 'paused': False},
                't' : {'expression': '(not ip.geoip.country in {"TH"})', 'paused': False},
            }
            rules = [{'paused': True, 'description': 'default_country', 'action': 'block', 'filter': wl_dic[wl]}]
            cf = CloudFlare.CloudFlare(email = self.headers['X-Auth-Email'], token = self.headers['X-Auth-Key'], raw=True)
            settings_firewall_rules = cf.zones.firewall.rules.post(self.zone_id, data=rules)
            print(settings_firewall_rules)
        return 0



for i in args.domains:
    x = cloudflare(i)
    x.enterpise_detect()
    x.get_rules(wl=args.wl, paused=args.paused)