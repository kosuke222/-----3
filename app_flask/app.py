import json
import datetime
import os
from dotenv import load_dotenv
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from openai import OpenAI
import time

# .envファイルから環境変数を読み込む
load_dotenv(dotenv_path='.env.flask')

app = Flask(__name__)

# .env.flaskからVIRUSTOTAL_API_KEYを読み込む
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_API_URL="https://www.virustotal.com/api/v3/files/"
#VIRUSTOTAL_BEHAVE_API_URL = os.getenv('VIRUSTOTAL_BEHAVE_API_URL')
# .env.flaskからOpenAI APIキーを読み込む
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
# .env.flaskからMalwareBazaarAPIキーを読み込む
MALWAREBAZAAR_API_KEY = os.getenv('MALWAREBAZAAR_API_KEY')
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"

# VIRUSTOTALからの出力を保存するファイルパス
RESULTS_DIR = 'results'
os.makedirs(RESULTS_DIR, exist_ok=True)

# OpenAIのAPIを使用するための設定
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
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
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

#[test] Malware_Bazaar 関連関数
def get_similar_hashes_from_malwarebazaar(family_name: str, limit: int = 3) -> list[str] | None:
    if not MALWAREBAZAAR_API_KEY:
        print("MalwareBazaarのAPIキーが設定されていないため、類似検体検索をストップします。")
        return None
    print(f"[*] マルウェアファミリ '{family_name}' に類似する検体を検索中...")
    try:
        headers = {'Auth-Key': MALWAREBAZAAR_API_KEY}
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
    

#[test]OpenAI_APIのweb_searchを叩く関数
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

#[test] レスポンスからデータ抽出
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

#[test]起動直後に/に行くとtest.htmlを表示するエンドポイント
@app.route('/')
def index():
    return render_template('test.html',page_title='API Test page')

#[test]APIを叩くエンドポイント
@app.route('/api/test', methods=['GET'])
def api_test():
    if not VIRUSTOTAL_API_KEY or not VIRUSTOTAL_FILE_API_URL:
        return jsonify({'error': 'VIRUSTOTAL_API_KEYが.env.flaskファイルに設定されていません。'}), 500
    
    sha256_hash = "09a4adef9a7374616851e5e2a7d9539e1b9808e153538af94ad1d6d73a3a1232"
    try:
        print(f"--- メイン検体の分析開始 ---")
        main_files_data, main_behaviours_data = get_virustotal_data(sha256_hash)
        print(main_files_data)
        print(main_behaviours_data)
        if not main_files_data or not main_behaviours_data:
            return jsonify({'error': 'VirusTotalからのデータ取得に失敗しました。'}), 500
        # 2つのレスポンスから必要な情報を抽出する関数
        report_data = extract_report_data(main_files_data, main_behaviours_data)
        if not report_data:
            return jsonify({'error': 'VirusTotalのレスポンスから基本情報を抽出できませんでした。'}), 500
        # マルウェアファミリ名抽出
        malware_family_name = report_data.get('specimen_info', {}).get('suggested_malware_name')
        # OpenAI APIを叩く関数
        if malware_family_name:
            # OpenAI APIの呼び出し
            api_response = web_search(malware_family_name)
            #レスポンスから目的のJSONを抽出
            parsed_data, raw_text_on_fail = extract_osint_json_from_response(api_response)
            if parsed_data:
                report_data['osint_investigation'] = parsed_data
                print("OSINT情報の取得とレポートへの追加が完了しました。")
            else:
                report_data['openai_response'] = raw_text_on_fail
        else:
            print("マルウェアファミリ名を見つけられませんでした。OSINT調査をスキップします。")
        
        # TODO: malware buzzer APIの処理の実装
        if malware_family_name:
            similar_hashes = search_similar_hashes_iteratively(malware_family_name)
            if similar_hashes:
                report_data['similar_samples_info'] = []
                hashes_to_check = [h for h in similar_hashes if h != sha256_hash][:3]
                for similar_hash in hashes_to_check:
                    print(f"--- 類似検体の情報を取得 ---")
                    files_data, behaviours_data = get_virustotal_data(similar_hash)
                    sample_info = extract_report_data(files_data, behaviours_data)
                    if sample_info:
                        report_data['similar_samples_info'].append(sample_info)
                    print("類似検体情報の追加が完了しました。")
        # レポートを保存
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        file_name = f'MAOT_report_{sha256_hash}_{timestamp}.json'
        file_path = os.path.join(RESULTS_DIR, file_name)

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        return jsonify(report_data), 200
    except requests.exceptions.HTTPError as e:
        return jsonify({
            'error': f'APIリクエストエラー: {e.response.status_code}',
            'message': e.response.text
        }), e.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'APIリクエストエラー: {e}'}), 500
    except Exception as e:
        return jsonify({'error': f'予期せぬサーバーエラー: {e}'}), 500

# G-001 ログイン画面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('home'))
    return render_template('login.html')

# G-002 新規登録画面
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('signup.html')

# G-003 パスワード再設定メール送信先入力画面
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        return redirect(url_for('password_reset_sent'))
    return render_template('forgot_password.html')

# G-004 メール添付完了画面
@app.route('/password_reset_sent')
def password_reset_sent():
    return render_template('password_reset_sent.html')

# G-005 パスワード再設定画面
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if request.method == 'POST':
        return redirect(url_for('password_reset_complete'))
    return render_template('reset_password.html', token=token)

# G-006 パスワード再設定完了画面
@app.route('/password_reset_complete')
def password_reset_complete():
    return render_template('password_reset_complete.html')

# G-007 ホーム画面
@app.route('/home')
def home():
    return render_template('home.html')

# G-008 APIキー入力画面
@app.route('/api_key', methods=['GET', 'POST'])
def api_key():
    if request.method == 'POST':
        # ここでVIRUSTOTAL_API_KEYを使用する処理などを実装できます
        return redirect(url_for('home'))
    return render_template('api_key.html')

# G-009 レポート作成画面
@app.route('/create_report', methods=['GET', 'POST'])
def create_report():
    if request.method == 'POST':
        return redirect(url_for('report_list'))
    return render_template('create_report.html')

# G-010 レポート一覧画面
@app.route('/report_list')
def report_list():
    return render_template('report_list.html')

@app.route('/logout')
def logout():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)