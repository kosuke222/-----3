import json
import datetime
import os
from dotenv import load_dotenv
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from email.message import EmailMessage
import smtplib
from openai import OpenAI
import time
from datetime import datetime
import traceback
from cryptography.fernet import Fernet
from data_model import db, User, Report
from markupsafe import Markup
import markdown

# .envファイルから環境変数を読み込む
load_dotenv(dotenv_path='.env.flask')
load_dotenv(dotenv_path='../.env.db')

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

# .env.flaskからVIRUSTOTAL_API_KEYを読み込む
#VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_API_URL="https://www.virustotal.com/api/v3/files/"
#VIRUSTOTAL_BEHAVE_API_URL = os.getenv('VIRUSTOTAL_BEHAVE_API_URL')
# .env.flaskからOpenAI APIキーを読み込む
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
# .env.flaskからMalwareBazaarAPIキーを読み込む
#MALWAREBAZAAR_API_KEY = os.getenv('MALWAREBAZAAR_API_KEY')
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"
# .env.flaskからAPIキー暗号化キーを読み込む 
API_ENCRYPTION_KEY = os.getenv('API_ENCRYPTION_KEY')
fernet = Fernet(API_ENCRYPTION_KEY.encode())
if not API_ENCRYPTION_KEY:
    API_ENCRYPTION_KEY = Fernet.generate_key().decode()
    with open(".env.flask", "a") as f:
        f.write(f"\nAPI_ENCRYPTION_KEY={API_ENCRYPTION_KEY}")

# DBの読み込み
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql+psycopg2://{os.getenv('POSTGRES_USER')}:"
    f"{os.getenv('POSTGRES_PASSWORD')}@"
    f"{os.getenv('POSTGRES_HOST')}:"
    f"{os.getenv('POSTGRES_PORT')}/"
    f"{os.getenv('POSTGRES_DB')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ユーザデータ読み込み
@login_manager.user_loader
def load_user(user_id: str):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None

def _ts() -> URLSafeTimedSerializer:
    # salt は固定文字列（環境変数から）
    return URLSafeTimedSerializer(
        secret_key=app.config["SECRET_KEY"],
        salt=os.getenv("SECURITY_PASSWORD_SALT", "default_salt"),
    )

def generate_reset_token(user_id: int) -> str:
        return _ts().dumps({"uid": user_id})

def verify_reset_token(token: str, max_age: int) -> int | None:
    try:
        data = _ts().loads(token, max_age=max_age)
        return int(data.get("uid"))
    except (SignatureExpired, BadSignature):
        return None

def send_email(subject: str, to: str, html_body: str, text_body: str | None = None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("MAIL_DEFAULT_SENDER", os.getenv("MAIL_USERNAME"))
    msg["To"] = to
    if text_body:
        msg.set_content(text_body)
        msg.add_alternative(html_body, subtype="html")
    else:
        msg.set_content(html_body, subtype="html")

    server = os.getenv("MAIL_SERVER")
    port = int(os.getenv("MAIL_PORT", "587"))
    username = os.getenv("MAIL_USERNAME")
    password = os.getenv("MAIL_PASSWORD")
    use_tls = os.getenv("MAIL_USE_TLS", "1") == "1"

    with smtplib.SMTP(server, port) as s:
        if use_tls:
            s.starttls()
        if username:
            s.login(username, password)
        s.send_message(msg)

# VIRUSTOTALからの出力を保存するファイルパス
RESULTS_DIR = 'results'
os.makedirs(RESULTS_DIR, exist_ok=True)

# OpenAIクライアントの初期化
client = OpenAI(api_key=OPENAI_API_KEY)

# 安全に辞書から値を取得するヘルパー関数
# キーが存在しない場合はデフォルト値を返す
def safe_get(data, keys, default=None):
    for key in keys:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
    return data if data is not None else default

# リクエスト制限対策
def wait_until_utc_midnight():
    now = datetime.datetime.now(datetime.timezone.utc)
    tomorrow = now + datetime.timedelta(days=1)
    midnight = tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)
    wait_seconds = (midnight - now).total_seconds()
    print(f"UTC深夜0時まで {wait_seconds:0f} 秒待機します。")
    time.sleep(wait_seconds)

# Virustotalから基本情報を取得する
def get_virustotal_data(sha256_hash: str) -> tuple[dict | None, dict | None]:
    encrypted_virustotal_api_key = current_user.virustotal_api_key
    virustotal_api_key = fernet.decrypt(encrypted_virustotal_api_key.encode()).decode()
    headers = {
        'x-apikey': virustotal_api_key
    }
    files_url = f"{VIRUSTOTAL_FILE_API_URL}{sha256_hash}"
    behaviours_url = f"{files_url}/behaviours"
    files_data, behaviours_data = None, None
    try:
        time.sleep(15)
        files_response = requests.get(files_url, headers=headers, timeout=15)
        if files_response.status_code == 429:
            print(f"VirusTotal APIのリクエスト制限に達しました。")
            wait_until_utc_midnight()
            return get_virustotal_data(sha256_hash)
        
        files_response.raise_for_status()
        files_data = files_response.json()

        time.sleep(15)
        behaviours_response = requests.get(behaviours_url, headers=headers, timeout=15)
        if behaviours_response.status_code == 429:
            print(f"VirusTotal APIのリクエスト制限に達しました。")
            wait_until_utc_midnight()
            return get_virustotal_data(sha256_hash)

        if behaviours_response.ok:
            behaviours_data = behaviours_response.json()
    except requests.exceptions.RequestException as e:
        print(f"VirusTotal APIリクエストエラー ({sha256_hash}): {e}")
    except Exception as e:
        print(f"{e}")
    return files_data, behaviours_data

def extract_report_data(files_data, behaviours_data):
    """
    2つのAPIレスポンスからレポートに必要な情報を抽出し、整形する関数
    """
    report = {
        "mitre_attack_summary": {},
        "file_basic_info": {},
        "specimen_info": {},
        "communication_destination": {},
        "specimen_behavior": {},
        "popularity": {},
        "ioc": {}
    }

    # --- 1. /files APIからの情報抽出 ---
    f_attr = safe_get(files_data, ['data', 'attributes'], {})
    
    report["file_basic_info"] = {
        "file_name": safe_get(f_attr, ['meaningful_name']),
        "file_type_tags": safe_get(f_attr, ['type_tags'], []),
        "all_file_names": safe_get(f_attr, ['names'], []),
        "file_size": safe_get(f_attr, ['size']),
        "sha256_hash": safe_get(f_attr, ['sha256'])
    }
    
    classification = safe_get(f_attr, ['popular_threat_classification'], {})
    vendor_results = safe_get(f_attr, ['last_analysis_results'], {})
    report["specimen_info"] = {
        "suggested_malware_name": safe_get(classification, ['suggested_threat_label']),
        "signature_info": safe_get(f_attr, ['signature_info'], {}),
        "vendor_malware_names": {vendor: result.get('result') for vendor, result in vendor_results.items() if result.get('result')},
        "classification": [cat.get('value') for cat in safe_get(classification, ['popular_threat_category'], [])],
        "first_submitted_date": safe_get(f_attr, ['first_submission_date'])
    }
    
    report["popularity"] = {
        "times_submitted": safe_get(f_attr, ['times_submitted'])
    }

    report["ioc"]["sha256_hash"] = safe_get(f_attr, ['sha256'])

    # --- 2. /behaviours APIからの情報抽出と整形 ---
    resolved_ips_from_dns = set()
    all_urls = set()
    tls_fingerprints = set()
    mitre_techniques = {}
    
    # 検体の挙動に関する情報を集約するためのセット
    files_created = set()
    files_deleted = set()
    files_opened = set()
    files_written = set()
    registry_opened = set()
    registry_set = set()
    registry_deleted = set()
    process_trees = []
    payload_evidence = set()

    if behaviours_data and 'data' in behaviours_data:
        # 最初にDNS解決されたIPをすべて収集
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            for lookup in b_attr.get('dns_lookups', []):
                if lookup.get('resolved_ips'):
                    resolved_ips_from_dns.update(lookup.get('resolved_ips', []))

        # 各サンドボックスレポートを処理
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            
            # MITRE ATT&CK
            for tech in b_attr.get('mitre_attack_techniques', []):
                tech_id = tech.get('id')
                if tech_id and tech_id not in mitre_techniques:
                    mitre_techniques[tech_id] = tech.get('signature_description')
            
            # 通信先URLとTLSフィンガープリント
            for lookup in b_attr.get('dns_lookups', []):
                if lookup.get('hostname'): all_urls.add(lookup.get('hostname'))
            for convo in b_attr.get('http_conversations', []):
                if convo.get('url'): all_urls.add(convo.get('url'))
            for tls in b_attr.get('tls', []):
                if tls.get('ja3') or tls.get('ja3s'):
                    tls_fingerprints.add((tls.get('ja3'), tls.get('ja3s')))

            # 検体の挙動 (ファイル、レジストリ、プロセス)
            for f in b_attr.get('files_dropped', []): files_created.add(f.get('path'))
            for f in b_attr.get('files_written', []): files_written.add(f)
            for f in b_attr.get('files_opened', []): files_opened.add(f)
            for f in b_attr.get('files_deleted', []): files_deleted.add(f)
            
            for k in b_attr.get('registry_keys_opened', []): registry_opened.add(k)
            for k in b_attr.get('registry_keys_set', []): registry_set.add(f"{k.get('key')} = {k.get('value')}")
            for k in b_attr.get('registry_keys_deleted', []): registry_deleted.add(k)
            
            if b_attr.get('processes_tree'): process_trees.append(b_attr.get('processes_tree'))

            # 【改良】汎用的なペイロードの証拠を収集
            # ランサムウェアの証拠
            for f in b_attr.get('files_dropped', []):
                path = f.get('path', '').lower()
                if 'ransom' in path or 'decrypt' in path or 'readme.txt' in path:
                    payload_evidence.add(f"Ransom Note Dropped: {f.get('path')}")
            for cmd in b_attr.get('command_executions', []):
                if 'vssadmin' in cmd.lower() and 'delete shadows' in cmd.lower():
                    payload_evidence.add(f"Shadow Copy Deletion Attempted: {cmd}")
            
            # ダウンローダー/ドロッパーの証拠
            dropped_executables = {f.get('path').lower() for f in b_attr.get('files_dropped', []) if f.get('path') and f.get('path').lower().endswith(('.exe', '.dll', '.ps1', '.bat'))}
            if dropped_executables:
                for proc in b_attr.get('processes_created', []):
                    # コマンドライン全体を小文字にして比較
                    proc_lower = proc.lower()
                    for exe in dropped_executables:
                        if exe in proc_lower:
                            payload_evidence.add(f"Dropped File Executed: {proc}")
            
            # RAT/バックドアの証拠
            for sig in b_attr.get('signature_matches', []):
                if 'c2 communication' in sig.get('description', '').lower():
                    payload_evidence.add("C2 Communication Pattern Detected")
            
            # 情報窃取型マルウェアの証拠
            for sig in b_attr.get('signature_matches', []):
                if 'harvest and steal' in sig.get('description', '').lower():
                    payload_evidence.add(sig.get('description'))
            for key in b_attr.get('registry_keys_opened', []):
                if any(browser in key for browser in ['Chrome\\User Data\\Default\\Login Data', 'Firefox', 'IncrediMail']):
                    payload_evidence.add(f"Accessed Credential Storage: {key}")

    # --- 3. 抽出した情報をレポートにまとめる ---
    important_ips = set()
    if behaviours_data and 'data' in behaviours_data:
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            for traffic in b_attr.get('ip_traffic', []):
                dest_ip = traffic.get('destination_ip')
                if dest_ip in resolved_ips_from_dns:
                    important_ips.add(f"{dest_ip}:{traffic.get('destination_port')}")

    report["mitre_attack_summary"] = mitre_techniques
    report["communication_destination"] = {
        "important_ip_addresses": sorted(list(important_ips)),
        "urls": sorted([url for url in all_urls if url])
    }
    
    report["specimen_behavior"] = {
        "file_operations": {
            "created": sorted([f for f in files_created if f]),
            "deleted": sorted([f for f in files_deleted if f]),
            "opened": sorted([f for f in files_opened if f]),
            "written": sorted([f for f in files_written if f])
        },
        "registry_key_operations": {
            "opened": sorted([k for k in registry_opened if k]),
            "set": sorted([k for k in registry_set if k]),
            "deleted": sorted([k for k in registry_deleted if k])
        },
        "process_tree": process_trees,
        "payload_content_evidence": sorted(list(payload_evidence))
    }
    
    report["ioc"] = {
        **report["ioc"],
        "ip_addresses": sorted(list(important_ips)),
        "urls": sorted([url for url in all_urls if url]),
        "tls_fingerprints": [{"ja3": ja3, "ja3s": ja3s} for ja3, ja3s in sorted(list(tls_fingerprints))]
    }

    return report

#Malware_Bazaar 関連関数
def get_similar_hashes_from_malwarebazaar(family_name: str, limit: int = 3) -> list[str] | None:
    encrypted_malwarebazaar_api_key = current_user.malwarebazaar_api_key
    malwarebazaar_api_key = fernet.decrypt(encrypted_malwarebazaar_api_key.encode()).decode()
    if not malwarebazaar_api_key:
        print("MalwareBazaarのAPIキーが設定されていないため、類似検体検索をストップします。")
        return None
    print(f"[*] マルウェアファミリ '{family_name}' に類似する検体を検索中...")
    try:
        headers = {'Auth-Key': malwarebazaar_api_key}
        data = {'query': 'get_siginfo', 'signature': family_name, 'limit': limit}
        response = requests.post(MALWAREBAZAAR_API_URL, data=data, headers=headers, timeout=15)
        response.raise_for_status()
        response_json = response.json()
        query_status = response_json.get('query_status')
        if query_status == 'ok':
            samples = response_json.get('data', [])
            hashes = [s.get('sha256_hash') for s in samples if s.get('sha256_hash')]
            return hashes
        elif query_status in ['no_results', 'illegal_status']:
            print(f"'{family_name}'の結果: {query_status}")
            return []
        else:
            print(f"[!] APIエラー: {response_json.get('query_status')}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] リクエストエラーが発生しました: {e}")
        return None

#   反復検索
def search_similar_hashes_iteratively(original_family_name: str) -> list[str] | None:
    if not original_family_name:
        return None
    
    parts = original_family_name.replace('/', '.').split('.')

    search_terms = []
    if len(parts) > 1:
        search_terms.append(original_family_name.replace('/','.'))
    search_terms.extend(reversed(parts))

    unique_search_terms = list(dict.fromkeys(search_terms))

    for term in unique_search_terms:
        print(f"[*] MalwareBazaarでファミリ'{term}'を検索中...")
        hashes = get_similar_hashes_from_malwarebazaar(term)

        if hashes is None:
            print(f"[-] '{term}'検索中にAPIエラーが発生しました。")
            return None
        if len(hashes) > 0:
            print(f"[+] '{term}'で{len(hashes)}件のハッシュ値が見つかりました。")
            return hashes
        print(f"[-] '{term}' では結果が見つかりませんでした。より抽象的な名前で再検索します。")

    print("[-] 全ての試行で類似検体が見つかりませんでした。")
    return []
    

#OpenAI_APIのweb_searchを叩く関数
def web_search(malware_family_name: str) -> dict | None:
    """
    OpenAI APIを使用して、マルウェアファミリ名に基づく情報を検索する関数
    """
    if not malware_family_name:
        print("マルウェアファミリ名が空です。")
        return None
    # 当該マルウェアファミリの一般的な挙動についての検索
    messages= [
        {
            "role": "system",
            "content": """あなたはマルウェア解析の専門家です。提供されたマルウェアファミリ名に基づいて，以下のJSON形式で情報を調査し報告してください。各項目は具体的に記述してください。また、流行度について調査する際は、直近1年以内のセキュリティベンダーの脅威レポート、セキュリティ専門家のブログ、公的機関の注意喚起などを重点的に参照してください。\n
            形式:
            {
                "investigated_family_name": "提供されたマルウェアファミリ名",
                "general_behavior": {
                    "summary": "マルウェアの概要",
                    "initial_compromise": "初期侵入の方法",
                    "payload_behavior": "感染後のペイロードの挙動",
                    "c2_communication": "C2サーバーとの通信方式や特徴",
                    "other_features": "その他執筆すべき技術的な特徴"
                },
                "attack_cases": [
                    {
                        "case_title": "攻撃事例1のタイトル",
                        "case_summary": "攻撃事例1の概要(時期、標的、影響，ソースリンクなど)"
                    },
                    {
                        "case_title": "攻撃事例2のタイトル",
                        "case_summary": "攻撃事例2の概要(時期、標的、影響，ソースリンクなど)"
                    }
                ],
                "popularity_assessment": [
                    {
                        "activity_level": "観測データやレポートを基に、活動レベルを「非常に活発」「活発」「中程度」「低」のいずれかで評価してください。",
                        "trend": "直近の活動状況から、脅威の動向を「増加傾向」「横ばい」「減少傾向」のいずれかで評価してください。",
                        "recent_reports_summary": [
                            {
                                "source": "参照した情報の発行元や著者名 (例: Trend Micro, JPCERT/CC)",
                                "title": "参照したレポートやブログ記事のタイトル",
                                "published_data": "公開日, YYYY-MM-DD",
                                "summary": "その情報源から判断できる流行度に関する内容を具体的に要約してください。"
                            }
                        ],
                        "targeted_regions": ["攻撃が主に観測されている国や地域をリストアップしてください。"],
                        "targeted_sectors": ["主な標的となっている業種をリストアップしてください。"],
                        "overall_summary": "上記で得られた情報を総合的に分析し、なぜその活動レベルや傾向と判断したのか、理由を簡潔に記述してください。"
                    }
                ]
                ###指示###
                上記のJSON形式に厳密に従ってください。
                JSONオブジェクトのみを出力し、前後のテキスト、補足、挨拶、マークダウンのjsonなどは一切含めないでください。
            }"""
        },
        {
            "role": "user",
            "content": f"マルウェアファミリ名: {malware_family_name} の一般的な挙動と、関連するサイバー攻撃事案について調査してください。"
        }
    ]
    try:
        print(f"{malware_family_name}の情報を検索します...")
        response = client.responses.create(
        model="gpt-5-mini",
        tools=[{"type": "web_search_preview"}],
        input=messages
        )
        return response.to_dict() if hasattr(response, 'to_dict') else json.loads(response.json())

    except Exception as e:
        print(f"OpenAI APIの呼び出し中に予期せぬエラーが発生しました: {e}")
        return None

#レスポンスからデータ抽出
def extract_osint_json_from_response(api_response: dict | None) -> dict | None:
    """
    OpenAI APIのカスタムレスポンス構造から, 最終的なJSONコンテンツを安全に抽出する関数
    """
    if not api_response:
        print("APIからのレスポンスが空です。")
        return None, "No response from OpenAI API"
    
    raw_text = None
    parsed_json = None

    try:
        output_list = api_response.get("output", [])
        message_object = next((item for item in output_list if item.get("type") == "message"), None)
        if message_object:
            content_list = message_object.get("content",[])
            if content_list:
                raw_text = content_list[0].get("text")
    except (IndexError, TypeError, AttributeError):
        print("OSINTレスポンスの構造が予期しない形式です。")
        return None, "Unexpected response structure"
    
    if not raw_text:
        print("OSINTレスポンスからテキストコンテンツが見つかりませんでした。")
        return None, "Failed to retrieve text from OpenAI response"
    
    try:
        start_index = raw_text.find('{')
        end_index = raw_text.rfind('}')
        if start_index == -1 or end_index == -1 or start_index > end_index:
            raise json.JSONDecodeError("JSONオブジェクトが見つかりません。", raw_text, 0)
        json_str = raw_text[start_index:end_index+1]
        parsed_json = json.loads(json_str)
        if 'popularity_assessment' in parsed_json and isinstance(parsed_json['popularity_assessment'], list):
            parsed_json['popularity_assessment'] = parsed_json['popularity_assessment'][0] if parsed_json['popularity_assessment'] else {}
        print("OSINT情報のJSONパースに成功しました。")
        return parsed_json, None
    except json.JSONDecodeError as e:
        print(f"OSINT情報のパースに失敗しました: {e}。RAWテキストを保存します。")
        return None, raw_text

# --- 最終レポート生成関数
def generate_markdown_report(report_data: dict) -> str | None:
    """
    収集したJSONデータを基に、LLMを使用してMarkdown形式の解析レポートを生成する。
    """
    json_data_string = json.dumps(report_data, indent=2, ensure_ascii=False)
    system_prompt = """あなたは優秀なマルウェア解析官であり、セキュリティレポートの専門家です。
提供されたJSON形式の技術データを分析し、以下の厳格なフォーマットに従って、日本語のMarkdown形式で詳細な解析レポートを作成してください。

### レポート形式 ###

# マルウェア解析レポート

## 1. ファイル基本情報
| 項目 | 内容 |
| :--- | :--- |
| ファイル名 | (JSONの`file_basic_info.file_name`から記載) |
| ファイルサイズ | (JSONの`file_basic_info.file_size`から記載、単位をKBやMBに変換して分かりやすく) |
| SHA256ハッシュ値 | (JSONの`file_basic_info.sha256_hash`から記載) |

## 2. 検体情報
| 項目 | 内容 |
| :--- | :--- |
| マルウェア名 | (JSONの`specimen_info.suggested_malware_name`から記載) |
| 分類 | (JSONの`specimen_info.classification`をカンマ区切りで記載) |
| 初めて登録された日 | (JSONの`specimen_info.first_submitted_date`を日時に変換して記載) |

## 3. 通信先
| 項目 | 内容 |
| :--- | :--- |
| IPアドレス | (JSONの`communication_destination.important_ip_addresses`を列挙) |
| URL | (JSONの`communication_destination.urls`を列挙) |
| 通信パターン | (JSONの`osint_investigation.general_behavior.c2_communication`の要約を基に、どのような通信を行うか記述) |

## 4. 検体の挙動
`mitre_attack_summary`、`specimen_behavior`（特に`file_operations`, `registry_key_operations`, `process_tree`）を総合的に分析し、以下の項目に分類して、自然言語で分かりやすく解説してください。単なる情報の羅列ではなく、各挙動が攻撃の中でどのような意味を持つのかを説明することが重要です。

### プロセスツリー
(各プロセスが何を表すのかを簡単に解説)

### ファイル操作
(主要なファイル操作について簡単に解説)

### レジストリキー操作
(主要なレジストリ操作について簡単に解説)

### 環境認識
(システム情報、ユーザー情報、実行中プロセスなどを収集する挙動について解説)

### 防御回避
(サンドボックス検知、デバッガ検知、難読化、プロセスインジェクションなどの挙動について解説)

### ペイロードの内容
(情報窃取、キーロギング、スクリーンショット、ファイルの暗号化など、マルウェアの主目的となる活動について解説)

### 痕跡消去
(自身の削除、ログの消去などの挙動について解説)

## 5. 類似検体の挙動
`similar_samples_info`に含まれる各検体の情報を分析し、メイン検体との共通点や特徴的な違いを、以下の項目で要約・解説してください。

### 初期侵入
(類似検体がどのような手法で侵入する傾向があるか)

### 環境認識
(類似検体に共通する環境認識の手法)

### 防御回避
(類似検体に共通する防御回避の手法)

### ペイロードの内容
(類似検体がどのようなペイロードを持つ傾向があるか)

### 痕跡消去
(類似検体に共通する痕跡消去の手法)

## 6. 流行度
`osint_investigation.popularity_assessment`の情報を基に、以下の項目を記述してください。

- **直近の活動状況**: (`activity_level`と`trend`を基に自然言語で要約)
- **サイバー攻撃に使われた例**: (`attack_cases`の要約を基に、具体的な攻撃事例を1〜2件紹介)
- **総合的な評価**: (`overall_summary`を基に、なぜそのように評価されるのかを解説)

## 7. IoC (Indicators of Compromise)
| 種別 | 値 |
| :--- | :--- |
| SHA256ハッシュ値 | (JSONの`ioc.sha256_hash`から記載) |
| IPアドレス | (JSONの`ioc.ip_addresses`を列挙) |
| URL | (JSONの`ioc.urls`を列挙) |

---
### 指示 ###
- 必ず上記のMarkdownフォーマットで出力してください。
- 表の中身や解説文が空になる場合は、「該当する情報なし」と明記してください。
- 専門用語には適宜簡単な説明を加えてください。
- 全体を通して、プロフェッショナルかつ客観的なトーンで記述してください。"""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"以下のJSONデータを基に、指定されたフォーマットで詳細な解析レポートを作成してください。\n\n```json\n{json_data_string}```"}
    ]
    try:
        print("--- OpenAI APIにMarkdownレポート生成をリクエストしています... ---")
        response = client.chat.completions.create(
            model="gpt-5-mini",
            messages=messages
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"エラー: OpenAI APIでのレポート生成中にエラーが発生しました: {e}")
        traceback.print_exc()
        return None

# 作成レポートのDB保存関数
def save_report_to_db(user_id: int, sha256_hash: str, report_markdown: str, malware_family: str) -> bool:
    """
    生成されたレポートをデータベースに保存する関数
    """
    try:
        new_report = Report(
            user_id=user_id,
            hash_sha256=sha256_hash,
            report_markdown=report_markdown,
            malware_family=malware_family
        )
        db.session.add(new_report)
        db.session.commit()
        print(f"レポートがデータベースに保存されました。Report ID: {new_report.report_id}")
        return new_report.report_id
    except Exception as e:
        db.session.rollback()
        print(f"エラー: レポートのデータベース保存中にエラーが発生しました: {e}")
        return None

# --- レポート作成のための情報収集関数
def run_full_analysis(sha256_hash: str) -> dict | None:
    """
    指定されたハッシュ値のフル分析を実行し、Markdownレポート文字列を返す。
    """
    try:
        print(f"--- メイン検体 ({sha256_hash})の分析を開始 ---")
        main_files_data, main_behaviours_data = get_virustotal_data(sha256_hash)
        if not main_files_data or not main_behaviours_data:
            flash(f"VirusTotalからのデータ取得に失敗しました。")
            return None
        report_data = extract_report_data(main_files_data, main_behaviours_data)
        if not report_data:
            flash(f"VirusTotalのレスポンスから基本情報を抽出できませんでした。")
            return None
        
        malware_family_name = safe_get(report_data, ['specimen_info', 'suggested_malware_name'])

        if malware_family_name:
            api_response = web_search(malware_family_name)
            parsed_data, raw_text_on_fail = extract_osint_json_from_response(api_response)
            if parsed_data:
                report_data['osint_investigation'] = parsed_data
            else:
                report_data['openai_response'] = raw_text_on_fail
        else:
            print("マルウェアファミリ名が見つからず、OSINT調査をスキップします。")
        
        if malware_family_name:
            similar_hashes = search_similar_hashes_iteratively(malware_family_name)
            if similar_hashes:
                report_data['similar_samples_info'] = []
                hashes_to_check = [h for h in similar_hashes if h != sha256_hash][:3]
                for similar_hash in hashes_to_check:
                    print(f"--- 類似検体 ({similar_hash})の情報を取得 ---")
                    files_data, behaviours_data = get_virustotal_data(similar_hash)
                    if files_data and behaviours_data:
                        sample_info = extract_report_data(files_data, behaviours_data)
                        if sample_info:
                            report_data['similar_samples_info'].append(sample_info)
                print(f"類似検体情報の追加が完了しました。")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_name = f"report_{sha256_hash[:10]}_{timestamp}.json"
        file_path = os.path.join(RESULTS_DIR, file_name)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        print(f"--- 中間レポートが{file_path}に保存されました。 ---")

        markdown_report = generate_markdown_report(report_data)
        if markdown_report:
            md_file_name = f"final_report_{sha256_hash[:10]}_{timestamp}.md"
            md_file_path = os.path.join(RESULTS_DIR, md_file_name)
            with open(md_file_path, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            print(f"--- 分析完了 --- 最終レポートが {md_file_path} に保存されました。")

            return {
                "markdown": markdown_report,
                "family_name": malware_family_name if malware_family_name else "Unknown"
            }
        else:
            flash('エラー: Markdownレポートの生成に失敗しました。')
            return None
    except Exception as e:
        traceback.print_exc()
        flash(f"予期せぬサーバーエラーが発生しました。{e}")
        return None

                        
# --- Flask定義 ---
#[test]起動直後に/に行くとtest.htmlを表示するエンドポイント
@app.route('/')
def index():
    return render_template('test.html',page_title='API Test page')

#[test]APIを叩くエンドポイント
@app.route('/api/test', methods=['GET'])
def api_test():
    """load_dotenv(dotenv_path='.env.flask')
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    if not VIRUSTOTAL_API_KEY or not VIRUSTOTAL_FILE_API_URL:
        return jsonify({'error': 'VIRUSTOTAL_API_KEYが.env.flaskファイルに設定されていません。'}), 500
    
    sha256_hash = "09a4adef9a7374616851e5e2a7d9539e1b9808e153538af94ad1d6d73a3a1232"
    report_data = run_full_analysis(sha256_hash)
    report_result = report_data.get('markdown') if report_data else None
    if report_result:
        return jsonify(report_result), 200
    else:
        return jsonify({'error': '分析に失敗しました。'}), 500
    """
    return "閉鎖中", 200

#   G-001 ログイン画面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get("email", "").strip()  
    password = request.form.get("password", "")

    if not email or not password:
        flash("メールアドレスとパスワードを入力してください。", "danger")
        return redirect(url_for("login"))

    user = User.query.filter((User.email == email)).first()

    if user and check_password_hash(user.password, password):
        login_user(user, remember=False)
        flash("ログインしました。", "success")
        return redirect(url_for("home"))
    else:
        flash("認証に失敗しました。", "danger")
        return redirect(url_for("login"))

# G-002 新規登録画面
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form.get("user", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()

        if not user or not password or not email:
            flash("全てのフィールドを入力してください。", "danger")
            return redirect(url_for("signup"))
        
        # ユーザ名またはメールアドレスの重複チェック
        existing_user = User.query.filter(
            (User.username == user) | (User.email == email)
        ).first()

        if existing_user:
            flash("このユーザー名またはメールアドレスは既に登録されています。", "warning")
            return redirect(url_for("signup"))

        new_user = User(
            username=user,
            email=email,
            password=generate_password_hash(password)
        )

        db.session.add(new_user)
        db.session.commit()
        flash("アカウントが作成されました。ログインしてください。", "success")
        return redirect(url_for("login"))
    
    return render_template('signup.html')

    

# G-003 パスワード再設定メール送信先入力画面
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template("forgot_password.html")

    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("メールアドレスを入力してください。", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()

    #flash("パスワードリセット手順を送信しました（届かない場合はメールアドレスをご確認ください）。", "info")

    if not user:
        return redirect(url_for("password_reset_sent"))

    token = generate_reset_token(user.user_id)
    app_base = os.getenv("APP_BASE_URL", request.url_root.rstrip("/"))
    reset_link = f"{app_base}{url_for('reset_password', token=token)}"

    html = f"""
    <p>パスワード再設定のリンクです（有効期限あり）：</p>
    <p><a href="{reset_link}">{reset_link}</a></p>
    <p>このメールに心当たりがない場合は破棄してください。</p>
    """
    send_email("パスワード再設定のご案内", to=email, html_body=html)
    return redirect(url_for("password_reset_sent"))

# G-004 メール添付完了画面
@app.route('/password_reset_sent', methods=['GET','POST'])
def password_reset_sent():
    if request.method == "GET":
        return render_template('password_reset_sent.html')
    return redirect(url_for("login"))

# G-005 パスワード再設定画面
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    max_age = int(os.getenv("RESET_TOKEN_MAX_AGE", "3600"))  # 秒
    user_id = verify_reset_token(token, max_age=max_age)
    if not user_id:
        flash("トークンが無効または期限切れです。再度メールを請求してください。", "danger")
        return redirect(url_for("forgot_password"))

    pw1 = request.form.get("password", "")
    pw2 = request.form.get("password_confirm", "")
    if not pw1 or pw1 != pw2:
        flash("パスワードが未入力、または一致しません。", "danger")
        return redirect(url_for("reset_password", token=token))

    user = User.query.get(user_id)
    if not user:
        flash("ユーザーが見つかりません。", "danger")
        return redirect(url_for("forgot_password"))

    user.password = generate_password_hash(pw1, method="pbkdf2:sha256")
    db.session.commit()

    return redirect(url_for("reset_complete"))

# G-006 パスワード再設定完了画面
@app.route('/reset_complete', methods=['GET','POST'])
def reset_complete():
    if request.method == "GET":
        return render_template('reset_complete.html')
    return redirect(url_for("login"))

# G-007 ホーム画面
@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username, page_title='ホーム')

# G-008 APIキー入力画面
@app.route('/api_key', methods=['GET', 'POST'])
def api_key():
    if request.method == 'POST':
        # ここでVIRUSTOTAL_API_KEYを使用する処理などを実装できます
        virustotal_api_key = request.form.get("virustotal_api_key", "").strip()
        malwarebazaar_api_key = request.form.get("malwarebazaar_api_key", "").strip()

        if not virustotal_api_key or not malwarebazaar_api_key:
            flash("全てのフィールドを入力してください。", "danger")
            return redirect(url_for("api_key"))
        
        #暗号化処理
        #load_dotenv(dotenv_path='.env.flask')
        #API_ENCRYPTION_KEY = os.getenv("API_ENCRYPTION_KEY")

        fernet = Fernet(API_ENCRYPTION_KEY.encode())

        encrypted_virustotal = fernet.encrypt(virustotal_api_key.encode()).decode()
        encrypted_malwarebazaar = fernet.encrypt(malwarebazaar_api_key.encode()).decode()

        current_user.virustotal_api_key = encrypted_virustotal
        current_user.malwarebazaar_api_key = encrypted_malwarebazaar
        db.session.commit()

        flash("APIキーが保存されました。", "success")
        return redirect(url_for('api_key'))
    return render_template('api_key.html')

# G-009 レポート作成画面
@app.route('/create_report', methods=['GET', 'POST'])
@login_required
def create_report():
    if request.method == 'POST':
        sha256_hash = request.form.get('sha256_hash', '').strip()
        if not sha256_hash:
            flash('SHA256ハッシュ値を入力してください。', 'error')
        # 分析
        analysis_result = run_full_analysis(sha256_hash)
        if not analysis_result:
            return redirect(url_for('create_report'))
        # 分析結果を展開
        markdown_text = analysis_result.get('markdown')
        malware_family = analysis_result.get('family_name')

        # レポート保存
        report_id = save_report_to_db(
            user_id=current_user.user_id,
            sha256_hash=sha256_hash,
            report_markdown=markdown_text,
            malware_family=malware_family
            )

        if report_id:
            # レポートオブジェクトを取得
            report = Report.query.get(report_id)
            if not report:
                flash('レポートの取得に失敗しました。', 'error')
                return redirect(url_for('create_report'))
            # マークダウンに変換
            html_content = markdown.markdown(report.report_markdown, extensions=["tables"])
            html_content = html_content.replace('<table>', '<table class="table table-bordered table-dark table-striped">')
            html_content = html_content.replace('<th>', '<th scope="col" class="bg-dark">')
            return render_template(
                'report_result.html', 
                report=report,
                report_html_content=html_content)
        else:
            flash('レポートの保存に失敗しました。', 'error')
            return redirect(url_for('create_report'))
    elif request.method == 'GET':
        if not current_user.virustotal_api_key or not current_user.malwarebazaar_api_key:
            flash('レポート作成にはAPIキーの登録が必要です。APIキーを登録してください。', 'warning')
            return redirect(url_for('api_key'))
        else:
            return render_template('create_report.html')

# G-010 レポート一覧画面
@app.route('/report_list')
def report_list():
    # URLのクエリパラメータから検索クエリを取得
    query = request.args.get('query')

    base_query = Report.query.order_by(Report.created_at.desc())
    
    # 検索クエリが存在する場合、フィルタリングを適用
    if query:
        # 検索条件をフィルタリング
        # 例：マルウェア名またはハッシュ値に検索クエリが含まれるかを検索
        search_pattern = f"%{query}%"
        reports = base_query.filter(
            (Report.malware_family.ilike(search_pattern)) | 
            (Report.hash_sha256.ilike(search_pattern))
        ).all()
    else:
        # 検索クエリがない場合、すべてのレポートを取得
        reports = base_query.all()
        
    return render_template('report_list.html', reports=reports)

# レポート単体表示
@app.route('/report/<int:report_id>')
@login_required
def show_report(report_id):
    report = Report.query.get_or_404(report_id)
    html_content = markdown.markdown(report.report_markdown, extensions=["tables"])
    html_content = html_content.replace('<table>', '<table class="table table-bordered table-dark table-striped">')
    html_content = html_content.replace('<th>', '<th scope="col" class="bg-dark">')
    return render_template('report_detail.html', report=report, report_html_content=html_content)


@app.route('/logout')
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
