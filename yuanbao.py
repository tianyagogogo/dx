
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
元宝派 - 免费 Bot 创建脚本【多线程并发版】
=============================================================================

【功能说明】
    自动抢元宝派每天 12:00 和 20:00 的免费 Bot 创建名额
    多线程并发请求，提前 5 分钟开始循环，直到抢到成功或整点后 2 分钟停止

【青龙定时规则】
    上午场: 55 11 * * *   （11:55 启动，抢 12:00 场）
    下午场: 55 19 * * *   （19:55 启动，抢 20:00 场）

【环境变量】
    变量名: YUANBAO_COOKIE
    变量值: 完整的 Cookie 字符串

=============================================================================
"""

import os
import requests
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, wait

# 青龙面板推送
try:
    from notify import send
    SEND_FLAG = True
except Exception:
    SEND_FLAG = False
    def send(title: str, content: str) -> None:
        print(f"[推送] {title}: {content[:100]}")

# ========== 配置参数（可按需修改）==========
ADVANCE_SECONDS = 20      # 提前多少秒开始循环抢（默认300秒=5分钟）
MAX_RETRY_SECONDS = 120    # 整点后最多继续抢多少秒（默认120秒=2分钟）
THREAD_COUNT = 20          # 并发线程数（建议 10~30，太高容易被风控）
REQUEST_INTERVAL = 0.05    # 单线程内请求间隔（秒）

# ========== 全局控制变量 ==========
success_flag = False       # 是否抢到成功
request_count = 0          # 总请求次数
count_lock = threading.Lock()  # 计数锁

# ========== 从环境变量获取 Cookie ==========
def get_cookie_value(cookie_str, key):
    match = re.search(rf'{key}=([^;]+)', cookie_str)
    return match.group(1) if match else None

COOKIE_STR = os.environ.get("YUANBAO_COOKIE", "")

if not COOKIE_STR:
    print("=" * 50)
    print("❌ 错误: 未设置环境变量 YUANBAO_COOKIE")
    print("=" * 50)
    exit(1)

# 验证 Cookie
HY_TOKEN = get_cookie_value(COOKIE_STR, "hy_token")
HY_USER = get_cookie_value(COOKIE_STR, "hy_user")

if not HY_TOKEN or not HY_USER:
    print("=" * 50)
    print("❌ 错误: Cookie 中未找到 hy_token 或 hy_user")
    print("=" * 50)
    exit(1)

print("=" * 50)
print("✅ 环境变量加载成功【多线程版】")
print(f"   hy_user: {HY_USER[:20]}...")
print(f"   并发线程数: {THREAD_COUNT}")
print(f"   提前抢时间: {ADVANCE_SECONDS} 秒（{ADVANCE_SECONDS//60}分钟）")
print(f"   整点后继续抢: {MAX_RETRY_SECONDS} 秒")
print("=" * 50)

# ========== 请求配置 ==========
HEADERS = {
    "Host": "yuanbao.tencent.com",
    "Origin": "https://yuanbao.tencent.com",
    "Referer": "https://yuanbao.tencent.com/e/claw/manage",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/148.0.0.0",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Cookie": COOKIE_STR,
}

PAYLOAD = {
    "type": 1,
    "create_type": 1,
}

def send_notify(title, content):
    """发送青龙推送"""
    if not SEND_FLAG:
        print("\n" + "="*50)
        print(f"【{title}】\n{content}")
        print("="*50)
        return
    try:
        send(title, content)
        print("✅ 青龙推送已发送")
    except Exception as e:
        print(f"❌ 青龙推送失败: {str(e)}")

# ========== 核心抢票函数 ==========
def grab_bot():
    """多线程执行的单次抢票任务"""
    global success_flag, request_count
    url = "https://yuanbao.tencent.com/api/v5/robotLogic/create"
    
    while not success_flag:
        try:
            # 计数
            with count_lock:
                request_count += 1
                current_count = request_count

            start = time.time()
            resp = requests.post(url, headers=HEADERS, json=PAYLOAD, timeout=8)
            cost = int((time.time() - start) * 1000)
            
            if resp.status_code == 200:
                data = resp.json()
                code = data.get("code", -1)
                msg = data.get("msg", "")
                
                if code == 0:
                    success_flag = True
                    print(f"\n[{time.strftime('%H:%M:%S')}] ✅ 抢 Bot 成功！耗时:{cost}ms | 总请求:{current_count}")
                    return True, msg
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] 第{current_count}次 | 失败 code={code}", end="\r")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] 第{current_count}次 | HTTP{resp.status_code}", end="\r")
                
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] 第{current_count}次 | 异常:{str(e)[:20]}", end="\r")
        
        # 单线程内间隔，防止过快
        time.sleep(REQUEST_INTERVAL)
    
    return False, "已抢到/超时停止"

# ========== 主循环逻辑 ==========
def loop_grab():
    """多线程并发抢购主逻辑"""
    now = time.localtime()
    current_hour = now.tm_hour
    current_min = now.tm_min
    
    # 判断目标场次
    if current_hour < 12 or (current_hour == 11 and current_min >= 55):
        target_hour, target_min = 12, 0
        target_desc = "12:00"
    elif current_hour < 20 or (current_hour == 19 and current_min >= 55):
        target_hour, target_min = 20, 0
        target_desc = "20:00"
    else:
        print(f"⚠️ 当前时间不在抢购时段")
        return False
    
    # 计算时间戳
    target_ts = time.mktime(time.struct_time((
        now.tm_year, now.tm_mon, now.tm_mday,
        target_hour, target_min, 0,
        now.tm_wday, now.tm_yday, now.tm_isdst
    )))
    start_ts = target_ts - ADVANCE_SECONDS
    end_ts = target_ts + MAX_RETRY_SECONDS
    current_ts = time.time()

    # 等待开始时间
    if current_ts < start_ts:
        wait = start_ts - current_ts
        print(f"⏰ 等待 {wait:.0f} 秒后开始并发抢购...")
        time.sleep(wait)
    elif current_ts > end_ts:
        print("⚠️ 已过抢购时间")
        return False

    # 开始并发
    print(f"\n🚀 多线程并发抢购启动！线程数：{THREAD_COUNT}")
    print(f"   目标场次：{target_desc}")
    print("-" * 60)

    # 线程池执行
    with ThreadPoolExecutor(max_workers=THREAD_COUNT) as executor:
        futures = [executor.submit(grab_bot) for _ in range(THREAD_COUNT)]
        
        # 等待成功 或 超时
        while not success_flag and time.time() < end_ts:
            time.sleep(0.1)
        
        # 强制停止所有线程
        executor.shutdown(wait=False, cancel_futures=True)

    # 结果
    if success_flag:
        push_title = "元宝派 Bot 抢购成功【多线程版】"
        push_content = f"✅ 抢购成功！\n场次：{target_desc}\n总请求：{request_count}\n并发线程：{THREAD_COUNT}"
        send_notify(push_title, push_content)
    else:
        print(f"\n⏰ 时间结束，未抢到名额，总请求：{request_count}")
    
    return success_flag

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("元宝派 Bot 抢购脚本【多线程并发版】启动")
    print("=" * 50 + "\n")
    loop_grab()
