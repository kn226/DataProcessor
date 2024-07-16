'''
Module for translating text using the LibreTranslate API.
'''
import json

import requests

translate_cache = {}

# 提取翻译结果的正则表达式模式
pattern = r'["\']translatedText["\']: ["\']([^}]+)'


def load_cache():
    global translate_cache
    try:
        # 如果本地文件存在则尝试读取上次保存的翻译缓存
        with open('translate_cache.json', 'r', encoding='utf-8') as f:
            translate_cache = json.load(f)
    except Exception as e:
        print('读取翻译缓存失败...')


def save_cache():
    global translate_cache
    with open('translate_cache.json', 'w', encoding='utf-8') as f:
        json.dump(translate_cache, f, ensure_ascii=False, indent=4)


load_cache()
translate_count = 0


def send_push_notification(title, content, channel, token):
    """发送消息提醒"""
    url = "your webhook"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    data = {
        "title": title,
        "description": content,
        "content": content,
        "channel": channel,
        "token": token
    }
    response = requests.post(url, json=data, headers=headers)
    return response.status_code


def translate_text(text, retry=True):
    global translate_count
    global translate_cache
    # your translate method