# Malware-Analysis-OSINT-Tool

## 概要

本ツールは、マルウェア解析におけるOSINT調査と、その結果に基づくレポート作成を自動化するAIツールです。

### 背景

マルウェア解析の初動調査として行われるOSINTは、複数のレピュテーションサイトや技術ブログなど情報源が多岐にわたるため、調査と結果の集約に多大な工数を要するという課題があります。この作業は解析者の負担となり、本来注力すべき高度な分析業務の時間を圧迫する一因となっています。

### 目的

このツールは、以下の実現を目的としています。

* **解析業務の効率化と迅速化:** SHA256ハッシュ値を入力するだけで、関連OSINT情報を自動で収集・整理し、初動調査の時間を大幅に短縮します。
* **技術解析の精度向上支援:** 網羅的かつ体系的に整理された情報を提供し、人手による調査では見落としがちな関連情報を提示します。
* **レポート作成の負荷軽減と品質向上:** 収集した情報を基にレポートのドラフトを自動生成し、報告書作成の工数を削減すると同時に品質を標準化します。

## 主な機能

* **ハッシュ値による情報収集:** SHA256ハッシュ値を基に、VirusTotal APIを利用して基本情報（MITRE ATT&CK ID、通信先、検体の挙動など）を取得します。
* **OSINT調査の自動化:** OpenAI APIを用いて、マルウェアファミリーの一般的な挙動、流行度、関連攻撃事案などを自動で収集・要約します。
* **類似検体の挙動調査:** malware buzzer APIとVirusTotal APIを連携し、類似検体の情報を収集します。
* **レポートの自動生成と管理:** 収集した情報を統合し、Markdown形式のレポートを自動で生成・保存します。過去のレポートは一覧で閲覧可能です。
* **ユーザー管理機能:** 新規登録、ログイン、パスワード再設定など基本的なユーザー管理機能を備えています。
  
### セットアップ  

1. ローカルにファイルを作成
```bash
git clone https://github.com/kosuke222/-----3/tree/main
cd -----3
```
2. .env.dbを作成し次のように記述
```
POSTGRES_USER=(任意)
POSTGRES_PASSWORD=(任意)
POSTGRES_DB=(任意)
POSTGRES_HOST=db
POSTGRES_PORT=5432
```
3. .env.flaskをapp_flask配下に設置し次のように記述
- OpenAI APIキーを発行すること
- SMTPサーバを作成すること
```
OPENAI_API_KEY=(あなたの取得したOpenAIAPIキー)
FLASK_APP=app.py
FLASK_DEBUG=1
SECRET_KEY=(secrets.token_hex(16)などで作成したkey)
SECURITY_PASSWORD_SALT=(secrets.token_hex(16)などで作成したkey)
RESET_TOKEN_MAX_AGE=3600
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=1
MAIL_USERNAME=xxx@gmail.com   # 使用するgmailアドレス 
MAIL_PASSWORD=xxxxxxxxxxxxxxxx    # ログイン用のパスワードではなく，googleアカウントで発行可能な16桁のアプリパスワード
MAIL_DEFAULT_SENDER=xxx@gmail.com   
APP_BASE_URL=http://localhost:5001
```
### 使い方
1. docker desktopを起動し，次のコマンドを実行  
```
docker-compose up --build
```
2. localhost:5001/loginにアクセスする  
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/25cfb137-ddad-4725-a616-7a3786686cbc" />
  
3. アカウントを作成する  
アカウントをお持ちではない方をクリックし，入力フォームに情報を入力する  
<img width="2159" height="1184" alt="image" src="https://github.com/user-attachments/assets/14403c46-0e65-4ad7-9ac9-187309153b15" />
  
ログイン画面に戻るので，必要情報を入力しログインをクリック
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/66e6fcb1-4a2a-46e8-882b-ffae0109b7a4" />

ホーム画面に遷移する  
<img width="2158" height="1180" alt="image" src="https://github.com/user-attachments/assets/3b030c07-a601-46cb-a3dd-4482d0640fdb" />

4. APIキーの設定  
VirusTotal APIキーと、Malware Bazaar APIキーを取得しフォームに入力  
<img width="2154" height="1179" alt="image" src="https://github.com/user-attachments/assets/2fb37723-0784-4e09-b3d5-c124bda0957c" />

5. レポート生成  
「レポートを作成する」をクリックし、調査したい検体のsha256ハッシュ値を入力する。  
<img width="2159" height="1181" alt="image" src="https://github.com/user-attachments/assets/7739b927-4d25-416b-b329-07f043900556" />  
すると、レポートが生成される(七分ほどかかる)  
<img width="2159" height="1176" alt="image" src="https://github.com/user-attachments/assets/990509a9-1d4f-4b70-8d1b-5f3e2bb08c5b" />  

6. レポート一覧から作成したレポートの閲覧が可能  
<img width="2156" height="1180" alt="image" src="https://github.com/user-attachments/assets/179a0755-d519-4f13-8f86-fe5c38c67bcc" />  
他ユーザが生成したレポートも閲覧が可能、キーワードを用いた検索もできる  
<img width="2159" height="1180" alt="image" src="https://github.com/user-attachments/assets/827f7d9f-00ec-447c-8f0a-288e7e706449" />





