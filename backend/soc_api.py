#!/usr/bin/env python3
import base64, json, ssl, urllib.error, urllib.request, re, sqlite3, time, uuid, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime

CREDS = {}
with open('/data/soc/wazuh-credentials.txt', encoding='utf-8') as f:
    for line in f:
        if '=' in line:
            key, value = line.rstrip().split('=', 1); CREDS[key] = value
CTX = ssl._create_unverified_context()

# AI配置（密钥从环境变量读取，不要硬编码到仓库）
AI_API_URL = os.environ.get('AI_API_URL', 'https://ai-codex.jupyte.com/v1/chat/completions')
AI_API_KEY = os.environ.get('AI_API_KEY', '')
AI_MODEL = os.environ.get('AI_MODEL', 'glm-5.3-flash')

# 数据库初始化
DB_PATH = '/data/soc/soc_tickets.db'
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id TEXT PRIMARY KEY,
        title TEXT,
        description TEXT,
        status TEXT DEFAULT 'open',
        priority TEXT DEFAULT 'medium',
        severity INTEGER DEFAULT 0,
        source_alert TEXT,
        ai_analysis TEXT,
        assignee TEXT DEFAULT '未分配',
        tags TEXT,
        created_at TEXT,
        updated_at TEXT,
        comments TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS ai_analyses (
        alert_id TEXT PRIMARY KEY,
        result_json TEXT,
        created_at TEXT,
        updated_at TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_json(url, method='GET', data=None, user=None, password=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if user is not None:
        headers['Authorization'] = 'Basic ' + base64.b64encode(f'{user}:{password}'.encode()).decode()
    if token: headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None, headers=headers, method=method)
    with urllib.request.urlopen(req, context=CTX, timeout=15) as res:
        body = res.read().decode(); return json.loads(body) if body else {}

def token():
    req = urllib.request.Request('https://127.0.0.1:55000/security/user/authenticate?raw=true')
    raw = base64.b64encode(f"{CREDS['WAZUH_API_USER']}:{CREDS['WAZUH_API_PASSWORD']}".encode()).decode()
    req.add_header('Authorization', 'Basic ' + raw)
    with urllib.request.urlopen(req, context=CTX, timeout=15) as res: return res.read().decode().strip()

def get_time_range(range_str):
    if range_str == 'today': return 'now/d'
    elif range_str == '7d': return 'now-7d'
    elif range_str == '30d': return 'now-30d'
    else: return 'now-24h'

# 深信服日志严重级别 -> 平台级别(critical/high/medium/low) 与 Wazuh level 数值
FW_SEVERITY_ORDER = [
    ('critical', 12, ('致命', '紧急', 'critical', 'Critical')),
    ('high', 8, ('高危', '高', '严重', 'high', 'High')),
    ('medium', 5, ('中危', '中', '警告', 'medium', 'Medium')),
    ('low', 2, ('低危', '低', '提示', 'low', 'Low')),
    ('low', 1, ('信息', 'info', 'Info', 'INFO')),
]

def map_fw_severity(raw, rule_level=0):
    """按深信服原始'严重级别'中文映射平台级别；无原始级别时按 Wazuh rule.level 兜底。"""
    if raw:
        v = raw.strip().strip('-').strip()
        for bucket, level, words in FW_SEVERITY_ORDER:
            if v in words:
                return bucket, level
    lv = rule_level or 0
    if lv >= 12: return 'critical', 12
    if lv >= 8: return 'high', 8
    if lv >= 4: return 'medium', 5
    return 'low', lv if lv > 0 else 2

def level_to_bucket(level):
    """Wazuh rule.level 数值 -> 平台级别分档（主机告警用）。"""
    lv = level or 0
    if lv >= 12: return 'critical'
    if lv >= 8: return 'high'
    if lv >= 4: return 'medium'
    return 'low'

def _fw_field(pattern, text):
    m = re.search(pattern, text)
    return m.group(1).strip().strip('-').strip() if m else ''

def parse_fw_log(full_log):
    result = {}
    result['srcip'] = _fw_field(r'源IP[:：]\s*([0-9.]+)', full_log)
    result['dstip'] = _fw_field(r'(?:目的IP|目标IP)[:：]\s*([0-9.]+)', full_log)
    result['srcport'] = _fw_field(r'源端口[:：]\s*(\d+)', full_log)
    result['dstport'] = _fw_field(r'(?:目的端口|目标端口)[:：]\s*(\d+)', full_log)
    result['attack_type'] = _fw_field(r'(?:攻击类型|威胁类型)[:：]\s*([^,，]+)', full_log)
    result['action'] = _fw_field(r'(?:系统动作|动作)[:：]\s*([^,，\s-]+)', full_log)
    result['severity'] = _fw_field(r'(?:严重级别|严重等级)[:：]\s*([^,，\s-]+)', full_log)
    result['log_type'] = _fw_field(r'日志类型[:：]\s*([^,，\s-]+)', full_log)
    result['policy'] = _fw_field(r'(?:策略名称|匹配策略名|策略名)[:：]\s*([^,，-]+)', full_log)
    result['feature_id'] = _fw_field(r'(?:特征ID|漏洞ID|特征ID号)[:：]\s*([^,，\s-]+)', full_log)
    if result['feature_id'] in ('0', '-', ''):
        result.pop('feature_id')
    result['protocol'] = _fw_field(r'协议[:：]\s*([^,，\s-]+)', full_log)
    if result['protocol'].lower() in ('(null)', 'null', '-', ''):
        result.pop('protocol')
    for _p in ('srcport', 'dstport'):
        if result.get(_p) in ('0', ''):
            result.pop(_p)
    result['vuln_name'] = _fw_field(r'(?:漏洞名称|特征名称)[:：]\s*([^,，-]+)', full_log)
    result['description'] = _fw_field(r'描述[:：]\s*(.*)', full_log)
    result['solution'] = _fw_field(r'(?:解决方案|处置建议)[:：]\s*(.*)', full_log)
    result['url'] = _fw_field(r'(?:URL/目录|URL|目的URL|域名)[:：]\s*([^,，\s]+)', full_log)
    result['src_location'] = _fw_field(r'源IP归属地[:：]\s*([^,，-]+)', full_log)
    result['dst_location'] = _fw_field(r'目的IP归属地[:：]\s*([^,，-]+)', full_log)
    for k in list(result):
        if not result[k]:
            result.pop(k)
    return result

def fw_event_desc(parsed, rule_desc, full_log):
    """事件描述：只取原始日志中的'描述'原文；无描述则留空，不拼接字段、不用规则描述占位。"""
    if parsed.get('description'):
        return parsed['description'][:300]
    return ''

# 非威胁类防火墙日志：流量审计 / 应用控制 / 系统操作等正常访问与运维记录，平台只收威胁日志，直接丢弃
TRAFFIC_TAGS = ('流量审计', '系统操作', '应用控制')
TRAFFIC_FEATURES = ('应用类型', '上行流量', '下行流量', '操作对象', '操作类型')
def is_traffic_log(full_log):
    if not full_log:
        return False
    if any(tag in full_log for tag in TRAFFIC_TAGS):
        return True
    if any(feat in full_log for feat in TRAFFIC_FEATURES):
        return True
    return False

# ES 层排除非威胁类日志的 must_not 条件；match_phrase 对中文分词字段有效，query_string wildcard 对中文不生效
TRAFFIC_MUST_NOT = [
    {'match_phrase': {'full_log': '流量审计'}},
    {'match_phrase': {'full_log': '系统操作'}},
    {'match_phrase': {'full_log': '应用控制'}},
    {'match_phrase': {'full_log': '操作对象'}},
    {'match_phrase': {'full_log': '应用类型'}},
    {'match_phrase': {'full_log': '上行流量'}},
]
# 防火墙低危/信息级别排除：只收中危/高危/严重
LOW_SEV_MUST_NOT = [
    {'match_phrase': {'full_log': '严重级别:低'}},
    {'match_phrase': {'full_log': '严重级别:低危'}},
    {'match_phrase': {'full_log': '严重级别:信息'}},
    {'match_phrase': {'full_log': '严重级别:提示'}},
]
# Wazuh 自身日志量统计句子（groups=stats），无威胁语义，被误判为防火墙时一并排除
STATS_MUST_NOT = [
    {'term': {'rule.groups': 'stats'}},
]
FW_MUST_NOT = TRAFFIC_MUST_NOT + LOW_SEV_MUST_NOT + STATS_MUST_NOT

def ai_analyze_alert(alert_info):
    """调用AI大模型进行安全研判"""
    prompt = f"""你是一名资深网络安全分析师。请对以下安全告警进行专业研判，输出JSON格式结果。

告警信息：
- 标题: {alert_info.get('description', '')}
- 级别: {alert_info.get('level', 0)}
- 来源IP: {alert_info.get('srcip', '未知')}
- 目标IP: {alert_info.get('dstip', '未知')}
- 来源端口: {alert_info.get('srcport', '未知')}
- 目标端口: {alert_info.get('dstport', '未知')}
- 攻击类型: {alert_info.get('attack_type', '未知')}
- 系统动作: {alert_info.get('action', '未知')}
- Agent: {alert_info.get('agent', '未知')}
- 原始日志: {alert_info.get('fullLog', '')[:500]}

请按以下JSON格式输出研判结果：
{{
    "threat_type": "威胁类型（如：僵尸网络、暴力破解、漏洞利用等）",
    "threat_level": "威胁等级（critical/high/medium/low）",
    "attack_chain": "攻击链阶段（如：侦察、初始访问、执行、持久化、权限提升、防御规避、凭证访问、发现、横向移动、数据窃取、影响）",
    "impact_assessment": "影响评估（简要说明可能造成的影响）",
    "ioc_indicators": ["IOC指标列表（IP、域名、URL等）"],
    "recommended_actions": ["处置建议列表（具体可执行的步骤）"],
    "false_positive_probability": "误报概率（0-100）",
    "summary": "研判摘要（一句话总结）"
}}

只输出JSON，不要输出其他内容。"""
    
    try:
        data = {
            'model': AI_MODEL,
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': 4000,
            'temperature': 0.3
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {AI_API_KEY}'
        }
        req = urllib.request.Request(AI_API_URL, data=json.dumps(data).encode(), headers=headers, method='POST')
        with urllib.request.urlopen(req, context=CTX, timeout=120) as res:
            result = json.loads(res.read().decode())
            content = result['choices'][0]['message']['content']
            # 提取JSON
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                return json.loads(json_match.group())
            return {'summary': content, 'threat_type': '未知', 'threat_level': 'medium'}
    except Exception as e:
        return {'error': str(e), 'summary': 'AI研判失败', 'threat_type': '未知', 'threat_level': 'medium'}

def get_firewall_data(time_range='now-24h'):
    fw = {'connected': False, 'alerts24h': 0, 'blocked': 0, 'allowed': 0, 'attackTypes': [], 'topSrcIps': [], 'topDstIps': [], 'severity': {'critical':0,'high':0,'medium':0,'low':0}, 'trend': [], 'recentEvents': []}
    try:
        query = {
            'size': 500, 'track_total_hits': True,
            'query': {'bool': {
                'filter': [
                    {'range': {'timestamp': {'gte': time_range}}},
                    {'bool': {'should': [
                        {'term': {'decoder.name': 'sangfor-af'}},
                        {'term': {'decoder.name': 'sangfor-waf'}},
                        {'term': {'rule.groups': 'sangfor'}}
                    ]}}
                ],
                'must_not': FW_MUST_NOT
            }},
            'sort': [{'timestamp': {'order': 'desc'}}],
            'aggs': {
                'by_hour': {'date_histogram': {'field': 'timestamp', 'fixed_interval': '1h', 'min_doc_count': 0}}
            }}
        alerts = get_json('https://127.0.0.1:9200/wazuh-alerts-*/_search', 'POST', query,
                          CREDS['WAZUH_DASHBOARD_USER'], CREDS['WAZUH_DASHBOARD_PASSWORD'])
        aggs = alerts.get('aggregations', {})
        fw['trend'] = [[b.get('key_as_string', '')[11:16], b.get('doc_count', 0)] for b in aggs.get('by_hour', {}).get('buckets', [])]
        kept = 0

        attack_types = {}
        src_ips = {}
        dst_ips = {}
        for hit in alerts.get('hits', {}).get('hits', []):
            s = hit.get('_source', {}); rule = s.get('rule', {}); data = s.get('data', {})
            full_log = s.get('full_log', '')
            parsed = parse_fw_log(full_log)
            # 只保留带「日志类型」标签的防火墙威胁报文；流量审计/系统操作/统计句子等无结构记录直接丢弃
            if is_traffic_log(full_log) or not parsed.get('log_type'):
                continue
            srcip = parsed.get('srcip', data.get('srcip', ''))
            dstip = parsed.get('dstip', data.get('dstip', ''))
            attack_type = parsed.get('attack_type', '')
            if not attack_type:
                attack_type = parsed.get('log_type', '')
            if not attack_type:
                attack_type = '其他事件'
            action = parsed.get('action', '')
            severity_raw = parsed.get('severity', '')
            bucket, level = map_fw_severity(severity_raw, rule.get('level', 0))
            # 防火墙只收中危及以上，低危/信息直接丢弃
            if bucket == 'low':
                continue
            fw['severity'][bucket] += 1

            if srcip: src_ips[srcip] = src_ips.get(srcip, 0) + 1
            if dstip: dst_ips[dstip] = dst_ips.get(dstip, 0) + 1
            attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

            if action in ('阻断', '拒绝', '丢弃', '拒绝连接', '阻断连接'):
                fw['blocked'] += 1
            elif action in ('允许', '放行'):
                fw['allowed'] += 1
            elif '阻断' in full_log or '拒绝' in full_log or '丢弃' in full_log:
                fw['blocked'] += 1
            elif '允许' in full_log or '放行' in full_log:
                fw['allowed'] += 1

            fw['recentEvents'].append({
                'time': s.get('timestamp', ''), 'level': level,
                'severity': severity_raw, 'severityLabel': bucket,
                'source': 'firewall', 'agent': '深信服防火墙',
                'description': fw_event_desc(parsed, rule.get('description', '防火墙事件'), full_log),
                'log_type': parsed.get('log_type', ''), 'attack_type': attack_type,
                'action': action, 'policy': parsed.get('policy', ''),
                'feature_id': parsed.get('feature_id', ''), 'protocol': parsed.get('protocol', ''),
                'vuln_name': parsed.get('vuln_name', ''), 'solution': parsed.get('solution', ''),
                'url': parsed.get('url', ''),
                'srcip': srcip, 'dstip': dstip,
                'srcport': parsed.get('srcport', data.get('srcport', '')),
                'dstport': parsed.get('dstport', data.get('dstport', '')),
                'src_location': parsed.get('src_location', ''), 'dst_location': parsed.get('dst_location', ''),
                'fullLog': full_log[:500]
            })
            kept += 1
        fw['attackTypes'] = sorted([[k, v] for k, v in attack_types.items()], key=lambda x: -x[1])[:10]
        fw['topSrcIps'] = sorted([[k, v] for k, v in src_ips.items()], key=lambda x: -x[1])[:10]
        fw['topDstIps'] = sorted([[k, v] for k, v in dst_ips.items()], key=lambda x: -x[1])[:10]
        fw['alerts24h'] = kept
        if fw['alerts24h'] == 0:
            fw['connected'] = False
        else:
            fw['connected'] = True
    except Exception as e:
        fw['error'] = str(e)
    return fw

def metrics(time_range='now-24h'):
    result = {'live':True,'agentsTotal':0,'agentsActive':0,'agents':[],'alerts24h':0,'highAlerts24h':0,'riskScore':100,'topIps':[],'riskAssets':[],'recentEvents':[],'hostEvents':[],'fwEvents':[],'trend':[],'severity':{'critical':0,'high':0,'medium':0,'low':0},'hostSeverity':{'critical':0,'high':0,'medium':0,'low':0},'hostAlerts24h':0,'hostHighAlerts24h':0,'vulnerabilities':{'total':0,'items':[],'severity':{}}}
    agents = get_json('https://127.0.0.1:55000/agents?limit=500', token=token()).get('data',{}).get('affected_items',[])
    result['agentsTotal'] = len(agents); result['agentsActive'] = sum(a.get('status') == 'active' for a in agents)
    result['agents']=[{'id':a.get('id'),'name':a.get('name'),'ip':a.get('ip'),'status':a.get('status'),'version':a.get('version'),'os':(a.get('os') or {}).get('name','-'),'lastKeepAlive':a.get('lastKeepAlive','')} for a in agents]
    query = {
        'size': 500, 'track_total_hits': True,
        'query': {'bool': {
            'filter': [{'range': {'timestamp': {'gte': time_range}}}],
            'must_not': FW_MUST_NOT
        }},
        'sort': [{'timestamp': {'order': 'desc'}}],
        'aggs': {
            'critical': {'filter': {'range': {'rule.level': {'gte': 12}}}},
            'high': {'filter': {'range': {'rule.level': {'gte': 8, 'lt': 12}}}},
            'medium': {'filter': {'range': {'rule.level': {'gte': 4, 'lt': 8}}}},
            'low': {'filter': {'range': {'rule.level': {'lt': 4}}}},
            'top_ips': {'terms': {'field': 'data.srcip', 'size': 5}},
            'top_agents': {'terms': {'field': 'agent.name', 'size': 5}},
            'by_hour': {'date_histogram': {'field': 'timestamp', 'fixed_interval': '1h', 'min_doc_count': 0}}
        }}
    try:
        alerts=get_json('https://127.0.0.1:9200/wazuh-alerts-*/_search','POST',query,CREDS['WAZUH_DASHBOARD_USER'],CREDS['WAZUH_DASHBOARD_PASSWORD'])
        total=alerts.get('hits',{}).get('total',0); result['alerts24h']=total.get('value',0) if isinstance(total,dict) else total
        aggs=alerts.get('aggregations',{})
        result['severity']={'critical':0,'high':0,'medium':0,'low':0}
        coverage=(result['agentsActive']/result['agentsTotal']) if result['agentsTotal'] else 0
        result['riskAssets']=[[b['key'],b['doc_count']] for b in aggs.get('top_agents',{}).get('buckets',[])]
        result['trend']=[[b.get('key_as_string','')[11:16],b.get('doc_count',0)] for b in aggs.get('by_hour',{}).get('buckets',[])]
        
        fw_src_ips = {}
        all_src_ips = {}
        for hit in alerts.get('hits',{}).get('hits',[]):
            s=hit.get('_source',{}); rule=s.get('rule',{}); data=s.get('data',{}); agent=s.get('agent',{}); decoder=s.get('decoder',{})
            full_log = s.get('full_log','')
            srcip = data.get('srcip','')
            is_fw = decoder.get('name') in ('sangfor-af','sangfor-waf') or 'sangfor' in str(rule.get('groups',[]))
            parsed = parse_fw_log(full_log) if is_fw else {}
            fw_bucket = ''
            if is_fw:
                severity_raw = parsed.get('severity','')
                fw_bucket, fw_level = map_fw_severity(severity_raw, rule.get('level', 0))
                # 防火墙只保留带「日志类型」标签的中危及以上威胁报文；流量审计/系统操作/统计句子/低危信息丢弃
                if is_traffic_log(full_log) or not parsed.get('log_type') or fw_bucket == 'low':
                    continue
            if is_fw:
                if parsed.get('srcip'):
                    fw_src_ips[parsed['srcip']] = fw_src_ips.get(parsed['srcip'], 0) + 1
            elif srcip:
                all_src_ips[srcip] = all_src_ips.get(srcip, 0) + 1

            desc = rule.get('description','安全事件')
            if not is_fw:
                fw_level = rule.get('level', 0)
            severity_raw = ''
            severity_label = ''
            fw_extra = {}
            if is_fw:
                attack_type = parsed.get('attack_type') or parsed.get('log_type') or '其他事件'
                if parsed.get('srcip'):
                    srcip = parsed['srcip']
                if parsed.get('dstip'):
                    data['dstip'] = parsed['dstip']
                severity_raw = parsed.get('severity','')
                severity_label = fw_bucket
                fw_level = {'critical':12,'high':8,'medium':5,'low':2}.get(fw_bucket, 5)
                desc = fw_event_desc(parsed, rule.get('description','防火墙事件'), full_log)
                fw_extra = {
                    'log_type': parsed.get('log_type',''), 'attack_type': attack_type,
                    'policy': parsed.get('policy',''), 'feature_id': parsed.get('feature_id',''),
                    'protocol': parsed.get('protocol',''), 'vuln_name': parsed.get('vuln_name',''),
                    'solution': parsed.get('solution',''), 'url': parsed.get('url',''),
                    'action': parsed.get('action',''),
                    'src_location': parsed.get('src_location',''), 'dst_location': parsed.get('dst_location',''),
                    'srcport': parsed.get('srcport', data.get('srcport','')),
                    'dstport': parsed.get('dstport', data.get('dstport',''))
                }
            event_agent = '深信服防火墙' if is_fw else agent.get('name','-')
            event = {'id':hit.get('_id',''),'index':hit.get('_index',''),'time':s.get('timestamp',''),'level':fw_level,'severity':severity_raw,'severityLabel':severity_label,'ruleId':rule.get('id',''),'description':desc,'groups':rule.get('groups',[]),'source':'firewall' if is_fw else 'host','agent':event_agent,'agentId':agent.get('id',''),'srcip':srcip,'dstip':data.get('dstip',''),'srcport':data.get('srcport',''),'dstport':data.get('dstport',''),'user':data.get('srcuser') or data.get('dstuser') or data.get('user',''),'process':data.get('process') or data.get('program_name',''),'file':data.get('path') or data.get('file',''),'decoder':decoder.get('name',''),'location':s.get('location',''),'fullLog':full_log,'data':data}
            event.update(fw_extra)
            result['recentEvents'].append(event)
            (result['fwEvents'] if is_fw else result['hostEvents']).append(event)
            bucket = severity_label if is_fw and severity_label else level_to_bucket(fw_level)
            result['severity'][bucket] += 1
            if not is_fw:
                result['hostSeverity'][bucket] += 1
        
        fw_top = sorted([[k, v] for k, v in fw_src_ips.items()], key=lambda x: -x[1])[:5]
        other_top = sorted([[k, v] for k, v in all_src_ips.items()], key=lambda x: -x[1])[:5]
        result['topIps'] = fw_top + other_top[:5-len(fw_top)]
        result['topFwIps'] = fw_top
        result['highAlerts24h']=result['severity']['critical']+result['severity']['high']
        result['hostAlerts24h']=len(result['hostEvents'])
        result['hostHighAlerts24h']=result['hostSeverity']['critical']+result['hostSeverity']['high']
        result['riskScore']=max(0,round(100*coverage-result['severity']['critical']*8-result['severity']['high']*2))

        # 额外查询高危告警
        try:
            high_query = {
                'size': 20,
                'query': {'bool': {
                    'filter': [{'range': {'rule.level': {'gte': 8}}}, {'range': {'timestamp': {'gte': time_range}}}],
                    'must_not': FW_MUST_NOT
                }},
                'sort': [{'timestamp': {'order': 'desc'}}]
            }
            high_alerts=get_json('https://127.0.0.1:9200/wazuh-alerts-*/_search','POST',high_query,CREDS['WAZUH_DASHBOARD_USER'],CREDS['WAZUH_DASHBOARD_PASSWORD'])
            existing_ids = {e['id'] for e in result['recentEvents']}
            for hit in high_alerts.get('hits',{}).get('hits',[]):
                if hit.get('_id') not in existing_ids:
                    s=hit.get('_source',{}); rule=s.get('rule',{}); data=s.get('data',{}); agent=s.get('agent',{}); decoder=s.get('decoder',{})
                    full_log=s.get('full_log','')
                    fw_flag=decoder.get('name') in ('sangfor-af','sangfor-waf') or 'sangfor' in str(rule.get('groups',[]))
                    parsed=parse_fw_log(full_log) if fw_flag else {}
                    severity_raw=parsed.get('severity','') if fw_flag else ''
                    severity_label,hlevel=(map_fw_severity(severity_raw,rule.get('level',0)) if fw_flag else ('',rule.get('level',0)))
                    bkt=severity_label if fw_flag and severity_label else level_to_bucket(hlevel)
                    desc=fw_event_desc(parsed,rule.get('description','防火墙事件'),full_log) if fw_flag else rule.get('description','安全事件')
                    ev={'id':hit.get('_id',''),'index':hit.get('_index',''),'time':s.get('timestamp',''),'level':hlevel,'severity':severity_raw,'severityLabel':severity_label,'ruleId':rule.get('id',''),'description':desc,'groups':rule.get('groups',[]),'source':'firewall' if fw_flag else 'host','agent':'深信服防火墙' if fw_flag else agent.get('name','-'),'agentId':agent.get('id',''),'srcip':data.get('srcip',''),'dstip':data.get('dstip',''),'srcport':data.get('srcport',''),'dstport':data.get('dstport',''),'user':data.get('srcuser') or data.get('dstuser') or data.get('user',''),'process':data.get('process') or data.get('program_name',''),'file':data.get('path') or data.get('file',''),'decoder':decoder.get('name',''),'location':s.get('location',''),'fullLog':full_log,'data':data}
                    if fw_flag:
                        ev.update({'log_type':parsed.get('log_type',''),'attack_type':parsed.get('attack_type') or parsed.get('log_type') or '其他事件','policy':parsed.get('policy',''),'feature_id':parsed.get('feature_id',''),'protocol':parsed.get('protocol',''),'vuln_name':parsed.get('vuln_name',''),'solution':parsed.get('solution',''),'url':parsed.get('url',''),'action':parsed.get('action',''),'src_location':parsed.get('src_location',''),'dst_location':parsed.get('dst_location',''),'srcport':parsed.get('srcport',data.get('srcport','')),'dstport':parsed.get('dstport',data.get('dstport',''))})
                    result['recentEvents'].append(ev)
                    (result['fwEvents'] if fw_flag else result['hostEvents']).append(ev)
                    result['severity'][bkt] += 1
                    if not fw_flag:
                        result['hostSeverity'][bkt] += 1
            result['highAlerts24h']=result['severity']['critical']+result['severity']['high']
            result['hostHighAlerts24h']=result['hostSeverity']['critical']+result['hostSeverity']['high']
            result['hostAlerts24h']=len(result['hostEvents'])
            result['riskScore']=max(0,round(100*coverage-result['severity']['critical']*8-result['severity']['high']*2))
            result['recentEvents'].sort(key=lambda x: x.get('time',''), reverse=True)
            result['hostEvents'].sort(key=lambda x: x.get('time',''), reverse=True)
            result['fwEvents'].sort(key=lambda x: x.get('time',''), reverse=True)
        except Exception as e:
            pass
    except urllib.error.HTTPError as e:
        if e.code not in (400,404): raise
    try:
        vq={'size':30,'track_total_hits':True,'sort':[{'vulnerability.severity':{'order':'desc','unmapped_type':'keyword'}}],'query':{'match_all':{}},'_source':['agent.name','host.os.full','vulnerability.id','vulnerability.title','vulnerability.severity','vulnerability.description','vulnerability.detected_at','vulnerability.published_at','vulnerability.reference','vulnerability.score.base','package.name','package.version','package.description','vulnerability.status']}
        vulns=get_json('https://127.0.0.1:9200/wazuh-states-vulnerabilities-*/_search','POST',vq,CREDS['WAZUH_DASHBOARD_USER'],CREDS['WAZUH_DASHBOARD_PASSWORD'])
        total=vulns.get('hits',{}).get('total',0); result['vulnerabilities']['total']=total.get('value',0) if isinstance(total,dict) else total
        sev={}
        for hit in vulns.get('hits',{}).get('hits',[]):
            s=hit.get('_source',{}); v=s.get('vulnerability',{}); p=s.get('package',{}); a=s.get('agent',{})
            level=v.get('severity','Unknown'); sev[level]=sev.get(level,0)+1
            result['vulnerabilities']['items'].append({'id':v.get('id','-'),'title':v.get('title','-'),'severity':level,'agent':a.get('name','-'),'os':(s.get('host') or {}).get('os',{}).get('full','-'),'package':p.get('name','-'),'version':p.get('version','-'),'package_desc':p.get('description','-'),'description':v.get('description','-'),'detected_at':v.get('detected_at','-'),'published_at':v.get('published_at','-'),'reference':v.get('reference','-'),'score':(v.get('score') or {}).get('base','-'),'status':v.get('status','Active')})
        result['vulnerabilities']['severity']=sev
    except urllib.error.HTTPError as e:
        if e.code not in (400,404): raise
    result['firewall'] = get_firewall_data(time_range)
    result['timeRange'] = time_range
    return result

# 工单管理函数
def get_vulnerabilities(page=1, page_size=30, severity=None):
    from_ = (page - 1) * page_size
    query = {
        'size': page_size,
        'from': from_,
        'track_total_hits': True,
        'sort': [{'vulnerability.severity': {'order': 'desc', 'unmapped_type': 'keyword'}}],
        '_source': ['agent.name', 'host.os.full', 'vulnerability.id', 'vulnerability.title',
                    'vulnerability.severity', 'vulnerability.description', 'vulnerability.detected_at',
                    'vulnerability.published_at', 'vulnerability.reference', 'vulnerability.score.base',
                    'package.name', 'package.version', 'package.description', 'vulnerability.status']
    }
    if severity:
        query['query'] = {'term': {'vulnerability.severity': severity}}
    else:
        query['query'] = {'match_all': {}}
    try:
        vulns = get_json('https://127.0.0.1:9200/wazuh-states-vulnerabilities-*/_search', 'POST', query,
                        CREDS['WAZUH_DASHBOARD_USER'], CREDS['WAZUH_DASHBOARD_PASSWORD'])
        total = vulns.get('hits', {}).get('total', 0)
        total_value = total.get('value', 0) if isinstance(total, dict) else total
        items = []
        for hit in vulns.get('hits', {}).get('hits', []):
            s = hit.get('_source', {})
            v = s.get('vulnerability', {})
            p = s.get('package', {})
            a = s.get('agent', {})
            level = v.get('severity', 'Unknown')
            items.append({
                'id': v.get('id', '-'),
                'title': v.get('title', '-'),
                'severity': level,
                'agent': a.get('name', '-'),
                'os': (s.get('host') or {}).get('os', {}).get('full', '-'),
                'package': p.get('name', '-'),
                'version': p.get('version', '-'),
                'package_desc': p.get('description', '-'),
                'description': v.get('description', '-'),
                'detected_at': v.get('detected_at', '-'),
                'published_at': v.get('published_at', '-'),
                'reference': v.get('reference', '-'),
                'score': (v.get('score') or {}).get('base', '-'),
                'status': v.get('status', 'Active')
            })
        return {'total': total_value, 'page': page, 'page_size': page_size,
                'total_pages': (total_value + page_size - 1) // page_size, 'items': items}
    except Exception as e:
        return {'total': 0, 'page': page, 'page_size': page_size, 'total_pages': 0, 'items': [], 'error': str(e)}

def get_ai_analysis(alert_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT result_json FROM ai_analyses WHERE alert_id = ?', (alert_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return json.loads(row['result_json'])
    return None

def save_ai_analysis(alert_id, result):
    conn = get_db()
    c = conn.cursor()
    now = datetime.now().isoformat()
    result_json = json.dumps(result, ensure_ascii=False)
    c.execute('SELECT id FROM ai_analyses WHERE alert_id = ?', (alert_id,))
    if c.fetchone():
        c.execute('UPDATE ai_analyses SET result_json = ?, updated_at = ? WHERE alert_id = ?',
                  (result_json, now, alert_id))
    else:
        c.execute('INSERT INTO ai_analyses (alert_id, result_json, created_at, updated_at) VALUES (?, ?, ?, ?)',
                  (alert_id, result_json, now, now))
    conn.commit()
    conn.close()
    return True

def list_tickets(status=None, priority=None):
    conn = get_db()
    c = conn.cursor()
    query = 'SELECT * FROM tickets'
    params = []
    conditions = []
    if status:
        conditions.append('status = ?')
        params.append(status)
    if priority:
        conditions.append('priority = ?')
        params.append(priority)
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    query += ' ORDER BY created_at DESC'
    rows = c.execute(query, params).fetchall()
    conn.close()
    tickets = []
    for row in rows:
        t = dict(row)
        t['source_alert'] = json.loads(t['source_alert']) if t['source_alert'] else None
        t['ai_analysis'] = json.loads(t['ai_analysis']) if t['ai_analysis'] else None
        t['tags'] = json.loads(t['tags']) if t['tags'] else []
        t['comments'] = json.loads(t['comments']) if t['comments'] else []
        tickets.append(t)
    return tickets

def get_ticket(ticket_id):
    conn = get_db()
    c = conn.cursor()
    row = c.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    conn.close()
    if row:
        t = dict(row)
        t['source_alert'] = json.loads(t['source_alert']) if t['source_alert'] else None
        t['ai_analysis'] = json.loads(t['ai_analysis']) if t['ai_analysis'] else None
        t['tags'] = json.loads(t['tags']) if t['tags'] else []
        t['comments'] = json.loads(t['comments']) if t['comments'] else []
        return t
    return None

def create_ticket(data):
    ticket_id = str(uuid.uuid4())[:8]
    now = datetime.now().isoformat()
    conn = get_db()
    c = conn.cursor()
    c.execute('''INSERT INTO tickets (id, title, description, status, priority, severity, source_alert, ai_analysis, assignee, tags, created_at, updated_at, comments)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (ticket_id, data.get('title', '未命名工单'), data.get('description', ''),
               data.get('status', 'open'), data.get('priority', 'medium'),
               data.get('severity', 0),
               json.dumps(data.get('source_alert'), ensure_ascii=False) if data.get('source_alert') else None,
               json.dumps(data.get('ai_analysis'), ensure_ascii=False) if data.get('ai_analysis') else None,
               data.get('assignee', '未分配'),
               json.dumps(data.get('tags', []), ensure_ascii=False),
               now, now, json.dumps([], ensure_ascii=False)))
    conn.commit()
    conn.close()
    return get_ticket(ticket_id)

def update_ticket(ticket_id, data):
    conn = get_db()
    c = conn.cursor()
    updates = []
    params = []
    for key in ['title', 'description', 'status', 'priority', 'severity', 'assignee']:
        if key in data:
            updates.append(f'{key} = ?')
            params.append(data[key])
    if 'source_alert' in data:
        updates.append('source_alert = ?')
        params.append(json.dumps(data['source_alert'], ensure_ascii=False))
    if 'ai_analysis' in data:
        updates.append('ai_analysis = ?')
        params.append(json.dumps(data['ai_analysis'], ensure_ascii=False))
    if 'tags' in data:
        updates.append('tags = ?')
        params.append(json.dumps(data['tags'], ensure_ascii=False))
    if 'comments' in data:
        updates.append('comments = ?')
        params.append(json.dumps(data['comments'], ensure_ascii=False))
    updates.append('updated_at = ?')
    params.append(datetime.now().isoformat())
    params.append(ticket_id)
    c.execute(f'UPDATE tickets SET {", ".join(updates)} WHERE id = ?', params)
    conn.commit()
    conn.close()
    return get_ticket(ticket_id)

def delete_ticket(ticket_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM tickets WHERE id = ?', (ticket_id,))
    conn.commit()
    conn.close()
    return True

def add_comment(ticket_id, comment):
    ticket = get_ticket(ticket_id)
    if not ticket:
        return None
    comments = ticket.get('comments', [])
    comments.append({
        'id': str(uuid.uuid4())[:8],
        'content': comment.get('content', ''),
        'author': comment.get('author', '系统'),
        'created_at': datetime.now().isoformat()
    })
    return update_ticket(ticket_id, {'comments': comments})

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == '/api/health':
                data={'ok':True}; code=200
            elif path == '/api/metrics':
                params = parse_qs(parsed.query)
                range_param = params.get('range', ['24h'])[0]
                time_range = get_time_range(range_param)
                data=metrics(time_range); code=200
            elif path == '/api/tickets':
                params = parse_qs(parsed.query)
                status = params.get('status', [None])[0]
                priority = params.get('priority', [None])[0]
                data = list_tickets(status, priority); code=200
            elif path.startswith('/api/tickets/'):
                ticket_id = path.split('/')[-1]
                ticket = get_ticket(ticket_id)
                if ticket:
                    data = ticket; code=200
                else:
                    data = {'error': '工单不存在'}; code=404
            elif path == '/api/vulnerabilities':
                params = parse_qs(parsed.query)
                page = int(params.get('page', ['1'])[0])
                page_size = int(params.get('page_size', ['30'])[0])
                severity = params.get('severity', [None])[0]
                data = get_vulnerabilities(page, page_size, severity); code=200
            elif path.startswith('/api/ai/analysis/'):
                alert_id = path.split('/')[-1]
                result = get_ai_analysis(alert_id)
                if result:
                    data = {'ai_analysis': result, 'cached': True}; code=200
                else:
                    data = {'ai_analysis': None, 'cached': False}; code=200
            elif path == '/api/ai/analyses':
                # 获取所有有AI研判结果的工单
                tickets = list_tickets()
                analyses = [t for t in tickets if t.get('ai_analysis')]
                data = analyses; code=200
            else:
                self.send_error(404); return
        except Exception as e:
            data={'error':str(e)}; code=500
        body=json.dumps(data,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode() if content_length else '{}'
            data = json.loads(body) if body else {}
            
            if path == '/api/tickets':
                ticket = create_ticket(data)
                response = ticket; code=201
            elif path.startswith('/api/tickets/') and path.endswith('/comments'):
                ticket_id = path.split('/')[-2]
                ticket = add_comment(ticket_id, data)
                response = ticket if ticket else {'error': '工单不存在'}; code=200 if ticket else 404
            elif path == '/api/ai/analyze':
                # AI研判
                alert_info = data.get('alert', {})
                alert_id = alert_info.get('id') or (str(alert_info.get('ruleId','')) + '_' + str(alert_info.get('time','')))
                # 先查是否有已保存的结果
                cached = get_ai_analysis(alert_id)
                force = data.get('force', False)
                # 失败缓存(有error或summary=AI研判失败)自动重试,不直接返回
                is_failed = cached and (cached.get('error') or cached.get('summary') == 'AI研判失败')
                if cached and not force and not is_failed:
                    response = {"ai_analysis": cached, "cached": True}; code=200
                else:
                    analysis = ai_analyze_alert(alert_info)
                    # 自动保存AI研判结果
                    if analysis and alert_id:
                        save_ai_analysis(alert_id, analysis)
                    # 如果有ticket_id，自动保存到工单
                    ticket_id = data.get('ticket_id')
                    if ticket_id:
                        update_ticket(ticket_id, {'ai_analysis': analysis})
                    response = {"ai_analysis": analysis, "cached": False}; code=200
            else:
                self.send_error(404); return
        except Exception as e:
            response={'error':str(e)}; code=500
        body=json.dumps(response,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    
    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode() if content_length else '{}'
            data = json.loads(body) if body else {}
            
            if path.startswith('/api/tickets/'):
                ticket_id = path.split('/')[-1]
                ticket = update_ticket(ticket_id, data)
                if ticket:
                    response = ticket; code=200
                else:
                    response = {'error': '工单不存在'}; code=404
            else:
                self.send_error(404); return
        except Exception as e:
            response={'error':str(e)}; code=500
        body=json.dumps(response,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    
    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path.startswith('/api/tickets/'):
                ticket_id = path.split('/')[-1]
                delete_ticket(ticket_id)
                response = {'success': True}; code=200
            else:
                self.send_error(404); return
        except Exception as e:
            response={'error':str(e)}; code=500
        body=json.dumps(response,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    
    def log_message(self,*_): pass

ThreadingHTTPServer(('127.0.0.1',8090),Handler).serve_forever()
