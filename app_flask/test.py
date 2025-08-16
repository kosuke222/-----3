import os
import sys
import requests
from dotenv import load_dotenv

# --- .env.flaskファイルから環境変数を読み込み ---
# スクリプトと同じ階層に .env.flask ファイルを置いてください
load_dotenv(dotenv_path='.env.flask')

# --- 定数設定 ---
API_URL = "https://mb-api.abuse.ch/api/v1/"
API_KEY = os.getenv('MALWAREBAZAAR_API_KEY')

def test_api_key():
    """
    MalwareBazaar APIキーが有効かどうかをテストする関数。
    """
    # 1. APIキーが読み込めているか確認
    if not API_KEY:
        print("--- ❌ エラー ---")
        print("'.env.flask'ファイルから'MALWAREBAZAAR_API_KEY'を読み込めませんでした。")
        print("ファイル名と変数名が正しいか確認してください。")
        sys.exit(1)

    print(f"[*] APIキーを読み込みました。キーの末尾: ...{API_KEY[-4:]}")
    print("[*] MalwareBazaar APIにテストリクエストを送信します...")

    try:
        # 2. APIへ送信するデータを作成
        # APIキーは'API-KEY'というキーでデータに含めます
        headers = {
            'Auth-Key': API_KEY
		}
        data = {
            'query': 'get_recent', # 最もシンプルなクエリでテスト
            'selector': '1',       # 直近1件を取得
        }

        # 3. HTTP POSTリクエストを送信
        response = requests.post(API_URL, data=data, headers=headers, timeout=15)

        # 4. レスポンスのステータスコードを確認
        if response.status_code == 200:
            print("\n--- ✅ 認証成功 ---")
            print("APIキーは有効です。MalwareBazaarとの通信に成功しました。")
            print("レスポンス:")
            print(response.json())
        elif response.status_code == 401:
            print("\n--- ❌ 認証失敗 (401 Unauthorized) ---")
            print("APIキーが無効か、間違っている可能性があります。")
            print("MalwareBazaarのサイトでAPIキーを再確認し、'.env.flask'ファイルに正しくコピーされているか確認してください。")
        else:
            print(f"\n--- ❌ エラー ({response.status_code}) ---")
            print("予期せぬエラーが発生しました。")
            print("レスポンス内容:", response.text)

    except requests.exceptions.RequestException as e:
        print(f"\n--- ❌ ネットワークエラー ---")
        print(f"リクエストの送信中にエラーが発生しました: {e}")

# --- メインの実行部分 ---
if __name__ == '__main__':
    test_api_key()
