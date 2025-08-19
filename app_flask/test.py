import os
import json
import datetime
from openai import OpenAI
from dotenv import load_dotenv

# --- .env.flaskファイルから環境変数を読み込み ---
load_dotenv(dotenv_path='.env.flask')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

if not OPENAI_API_KEY:
    raise ValueError("APIキーが設定されていません。'.env.flask'ファイルに 'OPENAI_API_KEY' を設定してください。")

# --- OpenAIクライアントの初期化 ---
client = OpenAI(api_key=OPENAI_API_KEY)

def generate_markdown_report(report_data: dict) -> str | None:
    """
    収集したJSONデータを基に、LLMを使用してMarkdown形式の解析レポートを生成する。
    """
    # LLMに渡すためのJSONデータを文字列に変換
    json_data_string = json.dumps(report_data, indent=2, ensure_ascii=False)

    # LLMへの指示（システムプロンプト）
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
- 全体を通して、プロフェッショナルかつ客観的なトーンで記述してください。
"""

    # LLMへのリクエストを作成
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"以下のJSONデータを基に、指定されたフォーマットで詳細な解析レポートを作成してください。\n\n```json\n{json_data_string}\n```"}
    ]

    try:
        print("--- OpenAI APIにレポート生成をリクエストしています... ---")
        response = client.chat.completions.create(
            model="gpt-5-mini",  # 長文かつ複雑な指示のため、高性能なモデルを推奨
            messages=messages,
        )
        
        report_content = response.choices[0].message.content
        return report_content

    except Exception as e:
        print(f"エラー: OpenAI APIの呼び出し中に予期せぬエラーが発生しました: {e}")
        return None

# --- メインの実行部分 ---
if __name__ == "__main__":
    # 読み込むJSONファイル名を指定
    input_json_file = 'results/report_09a4adef9a_20250816_164203.json'
    
    try:
        print(f"--- '{input_json_file}' を読み込んでいます... ---")
        with open(input_json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # レポート生成関数を呼び出し
        markdown_report = generate_markdown_report(data)

        if markdown_report:
            # 結果をMarkdownファイルとして保存
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            output_md_file = f'final_report_{timestamp}.md'
            
            with open(output_md_file, 'w', encoding='utf-8') as f:
                f.write(markdown_report)
            
            print(f"\n--- ✅ レポート生成成功 ---")
            print(f"レポートを '{output_md_file}' に保存しました。")
        else:
            print("\n--- ❌ レポート生成失敗 ---")

    except FileNotFoundError:
        print(f"エラー: ファイル '{input_json_file}' が見つかりません。")
    except json.JSONDecodeError:
        print(f"エラー: ファイル '{input_json_file}' は有効なJSON形式ではありません。")

