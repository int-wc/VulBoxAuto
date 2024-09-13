import requests
import csv
import json
import argparse
import time
import os
from termcolor import colored
from fuzzywuzzy import process

# 字符画
ascii_art = """
 _    __      ______             ___         __      
| |  / /_  __/ / __ )____  _  __/   | __  __/ /_____ 
| | / / / / / / __  / __ \\| |/_/ /| |/ / / / __/ __ \\
| |/ / /_/ / / /_/ / /_/ />  </ ___ / /_/ / /_/ /_/ /
|___/\\__,_/_/_____\\____/_/|_/_/  |\\__,_/\\__/\\____/ 
"""

print(ascii_art)
print("作者: weichai\n\n\n")

# 使用 argparse 获取命令行参数
parser = argparse.ArgumentParser(description="自动提交漏洞信息并查询地理位置")
parser.add_argument('--user-agent-file', required=True, help='User-Agent文件路径')
parser.add_argument('--cookie-file', required=True, help='Cookie文件路径')
parser.add_argument('--authorization-file', required=True, help='Authorization文件路径')
parser.add_argument('--geo-api-key', required=True, help='高德地图API密钥（是web服务密钥，而不是web端）')
args = parser.parse_args()

# 读取文件中的 User-Agent、Cookie、Authorization 信息
def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read().strip()

user_agent = read_file(args.user_agent_file)
cookie = read_file(args.cookie_file)
authorization = read_file(args.authorization_file)

# VulBox URL 和 headers
url = "https://user.vulbox.com/api/hacker/bugs/draft"
headers = {
    "Host": "user.vulbox.com",
    "User-Agent": user_agent,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json;charset=utf-8",
    "Authorization": authorization,
    "Cookie": cookie,
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=0"
}

# 高德地图API的基础URL
geo_api_url = "https://restapi.amap.com/v3/place/text"
geo_city_url = "https://restapi.amap.com/v3/config/district"

# 定义通过厂商信息获取地理位置的函数
def get_location_from_city_or_firm(keyword, api_key):
    params = {
        'keywords': keyword,
        'key': api_key
    }
    response = requests.get(geo_api_url, params=params)
    if response.status_code == 200:
        geo_data = response.json()
        if geo_data['status'] == '1' and geo_data['pois']:
            poi = geo_data['pois'][0]  # 使用第一个搜索结果
            province = poi.get('pname', '')
            city = poi.get('cityname', '')
            
            # 特例处理：重庆市、北京市、上海市
            if province in ['重庆市', '北京市', '上海市']:
                if province == '重庆市':
                    return ['重庆', '']  # 重庆市返回 ['重庆', '']
                elif province == '北京市':
                    return ['北京', '北京市']  # 北京市返回 ['北京', '北京市']
                elif province == '上海市':
                    return ['上海', '上海市']  # 上海市返回 ['上海', '上海市']

            # 默认情况返回省份和城市
            return [province, city if city else province]
        else:
            print(f"未找到相关地理位置: {keyword}")
            return ["未知", "未知"]
    else:
        print(f"地理位置查询失败: {response.status_code}")
        return ["未知", "未知"]

# 通过市级名称获取对应省份并去除省份中的“省”字
def get_province_from_city(city, api_key):
    params = {
        'keywords': city,
        'subdistrict': 1,
        'key': api_key
    }
    response = requests.get(geo_city_url, params=params)
    if response.status_code == 200:
        geo_data = response.json()
        if geo_data['status'] == '1' and geo_data['districts']:
            province = geo_data['districts'][0].get('province', '')
            province = province.replace('省', '')
            return province
        else:
            print(f"未找到与城市 '{city}' 对应的省份")
            return "未知"
    else:
        print(f"城市查询失败: {response.status_code}")
        return "未知"

# 从CSV文件中读取数据
csv_file = 'data.csv'
success_count = 0
failure_count = 0
failures = []

# 定义关键字字典
company_keywords_dict = {
    "基金": "基金/证券/期货/投资",
    "发展股份": "房地产开发/建筑/建材/工程",
    "科技": "计算机软件",
    "能源": "计算机软件",
    "信息": "计算机软件",
    "医院": "医疗/保健/美容/卫生服务",
    "网络": "计算机软件",
    "环境": "环保",
    "设计": "规划/设计/装潢",
    "云计算": "计算机软件",
    "科技发展": "计算机软件",
    "环境科技": "环保",
    "平面设计": "规划/设计/装潢"
}

# 根据厂商信息提取关键字并确定行业
def determine_industry(firm_name):
    keywords = list(company_keywords_dict.keys())
    best_match = process.extractOne(firm_name, keywords)
    if best_match and best_match[1] > 80:  # 设置一个阈值，确保匹配质量
        return company_keywords_dict[best_match[0]]
    return "未知"

with open(csv_file, mode='r', encoding='utf-8-sig') as file:
    reader = csv.DictReader(file)
    
    for row in reader:
        row = {key.strip(): value for key, value in row.items()}
        firm_name = row['厂商信息']
        print(f"正在查询厂商: {firm_name}")
    
        # 使用厂商信息来查询地理位置
        area = get_location_from_city_or_firm(firm_name, args.geo_api_key)
        if area[0]:
            area[0] = area[0].replace('省','')
        # 如果省份缺失，根据市级信息获取省份
        if not area[0] and area[1]:
            area[0] = get_province_from_city(area[1], args.geo_api_key)
            print("省份缺失，正在查询省份")
        
        print(f"厂商: {firm_name}, 地理位置: {area}")

        # 确定行业
        industry = determine_industry(firm_name)
        print(f"厂商: {firm_name}, 行业: {industry}")
        
        # 模拟提交数据
        data = {
            "task_id": 72,
            "bug_title": row['漏洞标题'],
            "protocol": True,
            "area": area,
            "industry": industry,
            "bug_display": False,
            "bug_category": 1,
            "bug_star": 0,
            "bug_firm_name": firm_name,
            "domain": row['所属域名'],
            "bug_type": [1, 12],
            "bug_level": 2,
            "bug_url": row['漏洞url/位置'],
            "bug_paper": row['漏洞简述'],
            "repetition_step": row['复现步骤'],  # 将更新后的复现步骤加入到data中
            "fix_plan": row['修复方案'],
            "draft_id": None
        }
        
        response = requests.post(url, headers=headers, data=json.dumps(data))
        
        if response.status_code == 200 and "success" in response.text:
            success_count += 1
            print(colored(f"提交成功: {firm_name}", "green"))
        else:
            failure_count += 1
            failures.append(firm_name)
            print(colored(f"提交失败: {firm_name}, 响应: {response.text}", "red"))
        
        time.sleep(5)  # 每次请求间隔5秒

# 打印结果统计
print(colored(f"\n提交成功数量: {success_count}", "green"))
print(colored(f"提交失败数量: {failure_count}", "red"))

if failures:
    print(colored("提交失败的厂商:", "red"))
    for firm in failures:
        print(firm)
