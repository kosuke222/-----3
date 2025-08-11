import json
import datetime
import os
from dotenv import load_dotenv
import requests
from flask import Flask, render_template, request, redirect, url_for, jsonify

# .envファイルから環境変数を読み込む
load_dotenv()

app = Flask(__name__)

# .envからVIRUSTOTAL_API_KEYを読み込む
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_FILE_API_URL = os.getenv('VIRUSTOTAL_FILE_API_URL')
VIRUSTOTAL_BEHAVE_API_URL = os.getenv('VIRUSTOTAL_BEHAVE_API_URL')

# VIRUSTOTALからの出力を保存するファイルパス
RESULTS_DIR = 'results'
os.makedirs(RESULTS_DIR, exist_ok=True)

# 安全に辞書から値を取得するヘルパー関数
# キーが存在しない場合はデフォルト値を返す
def safe_get(data, keys, default=None):
    for key in keys:
        if not isinstance(data, dict):
            return default
        data = data.get(key, default)
    return data if data is not None else default
        
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
    file_ops = set()
    deleted_files = set()
    process_trees = []
    unique_sigma_titles = set()
    mitre_techniques = {}
    api_calls_recognition = set()
    defense_evasion = set()
    payload_evidence = set()
    tls_fingerprints = set()

    if behaviours_data and 'data' in behaviours_data:
        # 最初にDNS解決されたIPをすべて収集
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            for lookup in b_attr.get('dns_lookups', []):
                if lookup.get('resolved_ips'):
                    for ip in lookup.get('resolved_ips'):
                        resolved_ips_from_dns.add(ip)

        # 各サンドボックスレポートを処理
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            
            # MITRE ATT&CK
            for technique in b_attr.get('mitre_attack_techniques', []):
                technique_id = technique.get('id')
                if technique_id and technique_id not in mitre_techniques:
                    mitre_techniques[technique_id] = technique.get('signature_description')
            
            # 通信先URLとTLSフィンガープリント
            for lookup in b_attr.get('dns_lookups', []):
                if lookup.get('hostname'): all_urls.add(lookup.get('hostname'))
            for convo in b_attr.get('http_conversations', []):
                if convo.get('url'): all_urls.add(convo.get('url'))
            for tls in b_attr.get('tls', []):
                if tls.get('ja3') or tls.get('ja3s'):
                    tls_fingerprints.add((tls.get('ja3'), tls.get('ja3s')))

            # 検体の挙動
            for f in b_attr.get('files_dropped', []): file_ops.add(f.get('path'))
            for f in b_attr.get('files_deleted', []): deleted_files.add(f)
            if b_attr.get('processes_tree'): process_trees.append(b_attr.get('processes_tree'))
            for result in b_attr.get('sigma_analysis_results', []):
                if result.get('rule_title'): unique_sigma_titles.add(result.get('rule_title'))
            for call in b_attr.get('calls_highlighted', []): api_calls_recognition.add(call)
            
            for result in b_attr.get('sigma_analysis_results', []):
                title = result.get('rule_title', '').lower()
                if 'defender exclusion' in title or 'disable uac' in title:
                    defense_evasion.add(result.get('rule_title'))
            
            for key in b_attr.get('registry_keys_set', []):
                if 'currentversion\\run' in key.get('key', '').lower():
                    defense_evasion.add(f"Set Autorun Registry Key: {key.get('key')}")

            for sig in b_attr.get('signature_matches', []):
                if 'harvest and steal' in sig.get('description', '').lower():
                    payload_evidence.add(sig.get('description'))
            
            for key in b_attr.get('registry_keys_opened', []):
                if any(browser in key for browser in ['Chrome\\User Data\\Default\\Login Data', 'Firefox', 'IncrediMail']):
                    payload_evidence.add(f"Accessed credential storage: {key}")

    # --- 3. 抽出した情報をレポートにまとめる ---
    # DNS解決されたIPのみをフィルタリング
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
        "file_operations": sorted(list(file_ops)),
        "process_tree": process_trees,
        "similar_behaviors_sigma": sorted(list(unique_sigma_titles)),
        "environment_recognition": {
            "tags": safe_get(f_attr, ['tags'], []),
            "api_calls": sorted(list(api_calls_recognition))
        },
        "defense_evasion": sorted(list(defense_evasion)),
        "payload_content_evidence": sorted(list(payload_evidence)),
        "trace_erasure": sorted(list(deleted_files))
    }
    
    report["ioc"] = {
        **report["ioc"], # 既存のsha256を維持
        "ip_addresses": sorted(list(important_ips)),
        "urls": sorted([url for url in all_urls if url]),
        "tls_fingerprints": [{"ja3": ja3, "ja3s": ja3s} for ja3, ja3s in sorted(list(tls_fingerprints))] # 【追加】
    }

    return report

#[test]起動直後に/に行くとtest.htmlを表示するエンドポイント
@app.route('/')
def index():
    return render_template('test.html')

#[test]APIを叩くエンドポイント
@app.route('/api/test', methods=['GET'])
def api_test():
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    file_api_url = VIRUSTOTAL_FILE_API_URL
    behave_api_url = VIRUSTOTAL_BEHAVE_API_URL
    if not file_api_url or not behave_api_url:
        return jsonify({'error': 'VIRUSTOTAL_API_URLが.envファイルに設定されていません。'}), 500

    try:
        # /files/{SHA256ハッシュ値}エンドポイントを叩く処理
        files_response = requests.get(file_api_url, headers=headers)
        if files_response.status_code != 200:
            return jsonify({
                'error': f'/files APIリクエストエラー: {files_response.status_code}',
                'message': files_response.text
            }), files_response.status_code
        
        files_data = files_response.json()

        # /files/{SHA256ハッシュ値}/behavioursエンドポイントを叩く処理
        behaviours_response = requests.get(behave_api_url, headers=headers)
        behaviours_data = behaviours_response.json() if behaviours_response.status_code == 200 else None

        # 2つのレスポンスから必要な情報を抽出する関数
        report_data = extract_report_data(files_data, behaviours_data)

        # レポートを保存
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        file_name = f'virustotal_report_{timestamp}.json'
        file_path = os.path.join(RESULTS_DIR, file_name)

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=4)
        return jsonify(report_data), 200
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