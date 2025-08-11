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
        "all_file_names": safe_get(f_attr, ['names'], []),
        "file_size": safe_get(f_attr, ['size']),
        "sha256_hash": safe_get(f_attr, ['sha256'])
    }
    
    classification = safe_get(f_attr, ['popular_threat_classification'], {})
    vendor_results = safe_get(f_attr, ['last_analysis_results'], {})
    report["specimen_info"] = {
        "suggested_malware_name": safe_get(classification, ['suggested_threat_label']),
        "vendor_malware_names": {vendor: result.get('result') for vendor, result in vendor_results.items() if result.get('result')},
        "classification": [cat.get('value') for cat in safe_get(classification, ['popular_threat_category'], [])],
        "first_submitted_date": safe_get(f_attr, ['first_submission_date'])
    }
    
    report["popularity"] = {
        "times_submitted": safe_get(f_attr, ['times_submitted'])
    }

    report["ioc"]["sha256_hash"] = safe_get(f_attr, ['sha256'])

    # --- 2. /behaviours APIからの情報抽出 ---
    all_ips = set()
    all_urls = set()
    file_ops = set()
    deleted_files = set()
    process_trees = []
    similar_behaviors = []
    env_recognition = []
    defense_evasion = []
    payload_evidence = []
    
    if behaviours_data and 'data' in behaviours_data:
        for behaviour in behaviours_data.get('data', []):
            b_attr = behaviour.get('attributes', {})
            
            # 通信先
            for traffic in b_attr.get('ip_traffic', []):
                all_ips.add(f"{traffic.get('destination_ip')}:{traffic.get('destination_port')}")
            for lookup in b_attr.get('dns_lookups', []):
                all_urls.add(lookup.get('hostname'))
            for convo in b_attr.get('http_conversations', []):
                all_urls.add(convo.get('url'))

            # 検体の挙動
            for f in b_attr.get('files_dropped', []): file_ops.add(f.get('path'))
            for f in b_attr.get('files_deleted', []): deleted_files.add(f)
            if b_attr.get('processes_tree'): process_trees.append(b_attr.get('processes_tree'))
            
            for result in b_attr.get('sigma_analysis_results', []):
                similar_behaviors.append(f"{result.get('rule_title')}: {result.get('rule_description')}")
            
            for call in b_attr.get('calls_highlighted', []):
                if 'IsDebuggerPresent' in call: env_recognition.append(call)
            
            for result in b_attr.get('sigma_analysis_results', []):
                title = result.get('rule_title', '').lower()
                if 'defender exclusion' in title or 'disable uac' in title:
                    defense_evasion.append(result.get('rule_title'))
            
            for key in b_attr.get('registry_keys_set', []):
                if 'currentversion\\run' in key.get('key', '').lower():
                    defense_evasion.append(f"Set Autorun Registry Key: {key.get('key')}")

            for sig in b_attr.get('signature_matches', []):
                if 'harvest and steal' in sig.get('description', '').lower():
                    payload_evidence.append(sig.get('description'))
            
            for key in b_attr.get('registry_keys_opened', []):
                if any(browser in key for browser in ['Chrome\\User Data\\Default\\Login Data', 'Firefox', 'IncrediMail']):
                    payload_evidence.append(f"Accessed credential storage: {key}")

    # --- 3. レポートにまとめる ---
    report["communication_destination"] = {
        "ip_addresses": sorted(list(all_ips)),
        "urls": sorted([url for url in all_urls if url])
    }
    
    report["specimen_behavior"] = {
        "file_operations": sorted(list(file_ops)),
        "process_tree": process_trees,
        "similar_behaviors_sigma": similar_behaviors,
        "environment_recognition": env_recognition + safe_get(f_attr, ['tags'], []),
        "defense_evasion": defense_evasion,
        "payload_content_evidence": payload_evidence,
        "trace_erasure": sorted(list(deleted_files))
    }
    
    report["ioc"]["ip_addresses"] = sorted(list(all_ips))
    report["ioc"]["urls"] = sorted([url for url in all_urls if url])

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