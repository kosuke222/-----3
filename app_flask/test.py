import os
import json
import datetime
from openai import OpenAI
from dotenv import load_dotenv

# --- 環境変数からAPIキーを読み込み ---
load_dotenv(dotenv_path='.env.flask')
# .env.flaskからOpenAI APIキーを読み込む
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# --- OpenAIクライアントの初期化 ---
client = OpenAI(api_key=OPENAI_API_KEY)


def get_osint_info_from_openai(malware_family_name: str) -> dict | None:
    """
    OpenAI APIを使用して、マルウェアファミリ名に基づく情報を一度のAPIコールで検索する関数。
    """
    if not malware_family_name:
        print("エラー: マルウェアファミリ名が空です。")
        return None

    # APIに渡すシステムプロンプトとユーザープロンプト
    messages = [
        {
            "role": "system",
            "content": """あなたはマルウェア解析の専門家です。提供されたマルウェアファミリ名に基づき、以下のJSON形式で情報を調査し報告してください。
各項目は具体的かつ簡潔に記述してください。

形式:
{
  "investigated_family_name": "提供されたマルウェアファミリ名",
  "general_behavior": {
    "summary": "マルウェアの概要",
    "initial_compromise": "初期侵入の手法",
    "payload_behavior": "感染後のペイロードの挙動",
    "c2_communication": "C2サーバーとの通信方式や特徴",
    "other_features": "その他特筆すべき技術的な特徴"
  },
  "attack_cases": [
    {
      "case_title": "攻撃事例1のタイトル",
      "case_summary": "攻撃事例1の概要（時期、標的、影響など）"
    },
    {
      "case_title": "攻撃事例2のタイトル",
      "case_summary": "攻撃事例2の概要（時期、標的、影響など）"
    }
  ]
}
"""
        },
        {
            "role": "user",
            "content": f"マルウェアファミリ名: {malware_family_name} の一般的な挙動と、関連するサイバー攻撃事案について調査してください。"
        }
    ]

    try:
        print(f"--- OpenAI APIに '{malware_family_name}' の情報を問い合わせています... ---")
        
        response = client.responses.create(
            model="gpt-5-mini",  # Web検索機能とJSONモードに強いモデルを推奨
            tools=[{"type": "web_search_preview"}],
            input=messages
            #response_format={"type": "json_object"} # JSON形式での出力を強制
        )
        # レスポンスからコンテンツを抽出
        return response

    except json.JSONDecodeError as e:
        print(f"エラー: OpenAIからのレスポンスのJSONパースに失敗しました: {e}")
        return None
    except Exception as e:
        print(f"エラー: OpenAI APIの呼び出し中に予期せぬエラーが発生しました: {e}")
        return None

# --- メインの実行部分 ---
if __name__ == "__main__":
    # 調査したいマルウェアファミリ名を設定
    # 添付ファイル(example_virustotal_report.json)の `suggested_malware_name` を参考にしています
    test_malware_name = "AgentTesla"
    
    # 関数を実行してOSINT情報を取得
    osint_result = get_osint_info_from_openai(test_malware_name)
    
    # 結果を出力
    if osint_result:
        print("\n--- ✅ APIからのレスポンス取得成功 ---")
        response_dict = osint_result.model_dump()
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        file_name = f"OPENAI_API_response_{timestamp}.json"
        try:
            with open(file_name, 'w', encoding='utf-8') as f:
                json.dump(response_dict, f, ensure_ascii=False, indent=4)
            print(f"レスポンスをファイルに保存しました: {file_name}")
            print("\n レスポンスのコンテンツ部分")
            content_str = response_dict.get('output_text', 'No content found')
            content_json = json.loads(content_str)
            print(json.dumps(content_json, indent=2, ensure_ascii=False))
        except Exception as e:
            print(f"エラー: ファイルへの書き込み中にエラーが発生しました: {e}")
        
    else:
        print("\n--- ❌ APIからのレスポンス取得失敗 ---")