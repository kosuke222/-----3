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
VIRUSTOTAL_API_URL = os.getenv('VIRUSTOTAL_API_URL')

# VIRUSTOTALからの出力を保存するファイルパス
RESULTS_DIR = 'results'
os.makedirs(RESULTS_DIR, exist_ok=True)

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
    api_url = os.getenv('VIRUSTOTAL_API_URL')
    if not api_url:
        return jsonify({'error': 'VIRUSTOTAL_API_URLが.envファイルに設定されていません。'}), 500

    try:
        response = requests.get(api_url, headers=headers)

        if response.status_code == 200:
            api_data = response.json()
            
            # --- ファイル保存処理 ---
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            
            file_name = f'virustotal_api_response_{timestamp}.json'
            
            file_path = os.path.join(RESULTS_DIR, file_name)
            
            with open(file_path, 'w', encoding='utf-8') as file:
                json.dump(api_data, file, ensure_ascii=False, indent=4)
            
            return jsonify(api_data), 200

        elif response.status_code == 404:
            return jsonify({'message': 'このハッシュ値のレポートはVirusTotalのデータベースに見つかりませんでした。'}), 200

        else:
            response.raise_for_status()
            
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