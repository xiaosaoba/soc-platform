#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SOC自动化编排服务 - Wazuh告警 → AI智能研判 → TheHive工单创建
监听端口: 8181
接收Wazuh integration推送的JSON告警，调用AI大模型分析后自动创建TheHive工单
"""
from flask import Flask, request, json
import requests
import logging
import json as json_module
import time
import os
from datetime import datetime

# ==================== 配置区 ====================
# TheHive配置
THEHIVE_URL = os.environ.get('THEHIVE_URL', 'http://172.16.113.66:9000')
THEHIVE_API_KEY = os.environ.get('THEHIVE_API_KEY', '')
THEHIVE_ORG = "soc"  # 必须指定soc组织，admin组织无创建告警权限

# AI大模型配置（密钥从环境变量读取，不要硬编码到仓库）
LLM_API_URL = os.environ.get('LLM_API_URL', 'https://ai-codex.jupyte.com/v1/chat/completions')
LLM_API_KEY = os.environ.get('LLM_API_KEY', '')
LLM_MODEL = os.environ.get('LLM_MODEL', 'deepseek-v4-flash')

# 告警过滤配置
MIN_ALERT_LEVEL = 3  # 最低处理告警等级（Wazuh level 3以上）
MIN_AI_LEVEL = 10    # 最低AI研判等级（仅严重/高危 level>=10 才调用AI，节省token）

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/opt/soc-automate/soc_automate.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)


def call_llm_analysis(alert_data):
    """
    调用AI大模型进行安全告警研判
    返回: (成功状态, 研判结果文本)
    """
    if not LLM_API_URL or not LLM_MODEL:
        logger.info("AI大模型未配置，使用默认研判模板")
        return True, f"""【AI智能研判 - 待配置大模型后启用自动分析】

告警等级: {alert_data.get('rule', {}).get('level', '未知')}
告警描述: {alert_data.get('rule', {}).get('description', '未知')}
代理主机: {alert_data.get('agent', {}).get('name', '未知')}
源IP: {alert_data.get('data', {}).get('srcip', 'N/A')}

⚠️ 请配置LLM_API_URL和LLM_API_KEY以启用自动AI研判。"""

    try:
        # 精简版SOC研判Prompt（控制token消耗）
        system_prompt = """你是资深SOC安全分析师。对Wazuh告警做中文研判，结合具体数据，禁止泛泛而谈。直接输出结果，无客套话。"""

        # 只提取关键字段，减少输入token
        rule = alert_data.get('rule', {})
        agent = alert_data.get('agent', {})
        data = alert_data.get('data', {})
        brief_alert = {
            "level": rule.get('level'),
            "rule_id": rule.get('id'),
            "description": rule.get('description'),
            "agent": agent.get('name'),
            "agent_ip": agent.get('ip'),
            "srcip": data.get('srcip'),
            "dstuser": data.get('dstuser') or data.get('user'),
            "dstport": data.get('dstport'),
            "path": data.get('path'),
            "full_log": alert_data.get('full_log', '')[:300]
        }

        user_prompt = f"""告警数据：{json_module.dumps(brief_alert, ensure_ascii=False)}

按以下格式输出（控制在800字内）：
## 一、风险评估
风险等级/处置优先级/可信度/误报可能性

## 二、攻击分析
攻击行为/MITRE ATT&CK/潜在危害/关联分析

## 三、排查步骤
3条具体命令，标注目的

## 四、应急处置
2-3条立即措施

## 五、长效加固
2-3条建议"""

        # 判断是OpenAI兼容API还是Ollama
        if 'ollama' in LLM_API_URL or '11434' in LLM_API_URL:
            # Ollama格式
            payload = {
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": False
            }
            headers = {"Content-Type": "application/json"}
        else:
            # OpenAI兼容格式
            payload = {
                "model": LLM_MODEL,
                "temperature": 0.1,
                "max_tokens": 1500,  # 限制输出token，控制成本
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ]
            }
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {LLM_API_KEY}"
            }

        logger.info(f"调用AI大模型: {LLM_MODEL}")

        # 带重试机制的API调用（最多3次，超时60秒）
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(LLM_API_URL, headers=headers, json=payload, timeout=60)
                if resp.status_code == 200:
                    resp_json = resp.json()
                    # 兼容不同API返回格式
                    if 'choices' in resp_json:
                        ai_result = resp_json['choices'][0]['message']['content']
                    elif 'message' in resp_json:
                        ai_result = resp_json['message']['content']
                    else:
                        ai_result = json_module.dumps(resp_json, ensure_ascii=False, indent=2)
                    logger.info(f"AI大模型研判成功(第{attempt}次尝试)")
                    return True, ai_result
                else:
                    logger.warning(f"AI大模型返回非200(第{attempt}次): HTTP {resp.status_code} - {resp.text[:150]}")
                    if attempt < max_retries:
                        time.sleep(3)
                        continue
                    return False, f"AI大模型调用失败(HTTP {resp.status_code})，已重试{max_retries}次。\n原始告警已记录，可稍后人工分析。"
            except requests.exceptions.Timeout:
                logger.warning(f"AI大模型调用超时(第{attempt}次/{max_retries})，60秒无响应")
                if attempt < max_retries:
                    time.sleep(3)
                    continue
                return False, f"AI大模型调用超时，已重试{max_retries}次均失败。\n可能原因：API服务繁忙或网络不稳定。原始告警已记录，可稍后人工分析。"
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"AI大模型连接失败(第{attempt}次): {str(e)[:100]}")
                if attempt < max_retries:
                    time.sleep(3)
                    continue
                return False, f"AI大模型连接失败: {str(e)[:100]}\n原始告警已记录。"
            except Exception as e:
                logger.error(f"AI大模型调用异常(第{attempt}次): {str(e)}")
                if attempt < max_retries:
                    time.sleep(3)
                    continue
                return False, f"AI大模型调用异常: {str(e)[:150]}\n原始告警已记录。"

        return False, "AI大模型调用失败，已达最大重试次数。"

    except Exception as e:
        logger.error(f"AI大模型调用异常: {str(e)}")
        return False, f"AI大模型调用异常: {str(e)[:150]}\n原始告警已记录。"


def create_thehive_alert(alert_data, ai_result):
    """
    调用TheHive API创建安全告警工单
    返回: (成功状态, 结果信息)
    """
    rule_info = alert_data.get('rule', {})
    agent_info = alert_data.get('agent', {})
    data_info = alert_data.get('data', {})

    # 构造工单标题
    title = rule_info.get('description', 'Wazuh安全告警')
    if len(title) > 150:
        title = title[:147] + "..."

    # 构造severity (TheHive: 1-低, 2-中, 3-高)
    wazuh_level = rule_info.get('level', 2)
    if wazuh_level >= 12:
        severity = 3
    elif wazuh_level >= 7:
        severity = 2
    else:
        severity = 1

    # 构造告警时间（兼容字符串和时间戳两种格式）
    raw_timestamp = alert_data.get('timestamp', '')
    if isinstance(raw_timestamp, (int, float)):
        alert_time = datetime.fromtimestamp(raw_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    elif isinstance(raw_timestamp, str) and raw_timestamp:
        try:
            # Wazuh格式: 2026-09-11T13:29:18.552+0800
            alert_time = raw_timestamp.replace('T', ' ')[:19]
        except:
            alert_time = str(raw_timestamp)[:19]
    else:
        alert_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # 构造描述
    description = f"""# AI智能安全研判结果

{ai_result}

---

## 原始Wazuh告警详情

- **告警ID**: {alert_data.get('id', 'N/A')}
- **告警等级**: {wazuh_level}
- **规则ID**: {rule_info.get('id', 'N/A')}
- **规则描述**: {rule_info.get('description', 'N/A')}
- **代理主机**: {agent_info.get('name', 'N/A')} ({agent_info.get('ip', 'N/A')})
- **源IP**: {data_info.get('srcip', 'N/A')}
- **目标端口**: {data_info.get('dstport', 'N/A')}
- **用户名**: {data_info.get('user', 'N/A')}
- **告警时间**: {alert_time}

<details>
<summary>完整告警JSON</summary>

```json
{json_module.dumps(alert_data, ensure_ascii=False, indent=2)}
```
</details>
"""

    # 构造sourceRef（去重用）
    source_ref = f"wazuh-{alert_data.get('id', 'unknown')}"

    payload = {
        "title": title,
        "description": description,
        "type": "alert",
        "source": "Wazuh智能SOC平台",
        "sourceRef": source_ref,
        "severity": severity,
        "tags": [
            f"wazuh-level-{wazuh_level}",
            f"rule-{rule_info.get('id', 'unknown')}",
            agent_info.get('name', 'unknown-agent')
        ]
    }

    headers = {
        "Authorization": f"Bearer {THEHIVE_API_KEY}",
        "X-Organisation": THEHIVE_ORG,
        "Content-Type": "application/json"
    }

    try:
        logger.info(f"调用TheHive创建工单: {title[:50]}...")
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers=headers,
            json=payload,
            timeout=15
        )

        if resp.status_code in [200, 201]:
            result = resp.json()
            alert_id = result.get('_id', 'unknown')
            logger.info(f"TheHive工单创建成功! ID: {alert_id}")
            return True, f"工单创建成功, ID: {alert_id}"
        elif resp.status_code == 409:
            logger.info(f"告警已存在(去重): {source_ref}")
            return True, "告警已存在，跳过重复创建"
        else:
            logger.error(f"TheHive创建失败: HTTP {resp.status_code} - {resp.text[:300]}")
            return False, f"TheHive创建失败(HTTP {resp.status_code}): {resp.text[:200]}"

    except Exception as e:
        logger.error(f"TheHive请求异常: {str(e)}")
        return False, f"TheHive请求异常: {str(e)}"


@app.route('/wazuh-webhook', methods=['POST'])
def wazuh_webhook():
    """接收Wazuh告警的Webhook端点"""
    try:
        alert_data = request.get_json(force=True)
        if not alert_data:
            logger.warning("收到空告警数据")
            return app.response_class(
                response=json_module.dumps({"status": "error", "message": "空数据"}),
                status=400, mimetype='application/json'
            )

        # 兼容Wazuh shuffle.py集成格式：原始告警包装在all_fields字段中
        if 'all_fields' in alert_data and isinstance(alert_data['all_fields'], dict):
            logger.info("检测到shuffle.py格式(all_fields)，提取原始告警")
            alert_data = alert_data['all_fields']

        rule_level = alert_data.get('rule', {}).get('level', 0)
        rule_desc = alert_data.get('rule', {}).get('description', '未知')
        alert_id = alert_data.get('id', 'unknown')

        logger.info(f"收到Wazuh告警: ID={alert_id}, level={rule_level}, desc={rule_desc[:60]}")

        # 告警过滤
        if rule_level < MIN_ALERT_LEVEL:
            logger.info(f"告警等级{rule_level}低于阈值{MIN_ALERT_LEVEL}，跳过")
            return app.response_class(
                response=json_module.dumps({"status": "skipped", "reason": "level too low"}),
                status=200, mimetype='application/json'
            )

        # 1. AI大模型研判（仅严重/高危级别才调用，节省token）
        if rule_level >= MIN_AI_LEVEL:
            ai_success, ai_result = call_llm_analysis(alert_data)
        else:
            logger.info(f"告警等级{rule_level}低于AI研判阈值{MIN_AI_LEVEL}，跳过AI分析")
            ai_success = False
            ai_result = f"""【告警通知 - 低级别告警，未触发AI研判】

告警等级: {rule_level}
告警描述: {rule_desc}
代理主机: {alert_data.get('agent', {}).get('name', '未知')}
源IP: {alert_data.get('data', {}).get('srcip', 'N/A')}

仅记录原始告警，如需AI研判请调整MIN_AI_LEVEL配置。"""

        # 2. 创建TheHive工单
        th_success, th_result = create_thehive_alert(alert_data, ai_result)

        # 返回结果
        response_data = {
            "status": "processed",
            "alert_id": alert_id,
            "ai_analysis": ai_success,
            "thehive_created": th_success,
            "thehive_result": th_result
        }

        return app.response_class(
            response=json_module.dumps(response_data, ensure_ascii=False),
            status=200, mimetype='application/json'
        )

    except Exception as e:
        logger.error(f"处理告警异常: {str(e)}", exc_info=True)
        return app.response_class(
            response=json_module.dumps({"status": "error", "message": str(e)}),
            status=500, mimetype='application/json'
        )


@app.route('/health', methods=['GET'])
def health():
    """健康检查端点"""
    return app.response_class(
        response=json_module.dumps({
            "status": "ok",
            "service": "SOC Automate",
            "thehive_configured": bool(THEHIVE_API_KEY),
            "llm_configured": bool(LLM_API_URL and LLM_MODEL),
            "time": datetime.now().isoformat()
        }, ensure_ascii=False),
        status=200, mimetype='application/json'
    )


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("SOC自动化编排服务启动")
    logger.info(f"监听地址: 0.0.0.0:8181")
    logger.info(f"TheHive: {THEHIVE_URL} (org: {THEHIVE_ORG})")
    logger.info(f"AI大模型: {'已配置 - ' + LLM_MODEL if LLM_API_URL else '未配置(使用默认模板)'}")
    logger.info(f"最低告警等级: {MIN_ALERT_LEVEL}")
    logger.info(f"AI研判等级阈值: {MIN_AI_LEVEL} (仅level>={MIN_AI_LEVEL}调用AI)")
    logger.info("=" * 60)

    app.run(host="0.0.0.0", port=8181, debug=False)
