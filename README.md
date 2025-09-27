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
4. docker desktopを起動し，次のコマンドを実行 
```
docker-compose up --build
```
5. localhost:5001/loginにアクセス  
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/25cfb137-ddad-4725-a616-7a3786686cbc" />
  


### 使い方
1. **アカウントを作成しログイン**  
   ログイン画面から新規登録画面へ移動し、ユーザ名、メールアドレス、パスワードを登録します。
<img width="2159" height="1184" alt="image" src="https://github.com/user-attachments/assets/14403c46-0e65-4ad7-9ac9-187309153b15" />
  
登録後、ログイン画面からサービスにログインします。
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/66e6fcb1-4a2a-46e8-882b-ffae0109b7a4" />  

2. **APIキーの設定**  
ホーム画面の「APIキーを入力する」を押下します。  
<img width="2158" height="1180" alt="image" src="https://github.com/user-attachments/assets/3b030c07-a601-46cb-a3dd-4482d0640fdb" />  
利用するVirusTotal APIキーとMalware Bazaar APIキーを入力し、保存します。  
<img width="2154" height="1179" alt="image" src="https://github.com/user-attachments/assets/2fb37723-0784-4e09-b3d5-c124bda0957c" />

3. **レポート作成**  
ホーム画面の「レポートを作成する」を押下します。  
<img width="2158" height="1180" alt="image" src="https://github.com/user-attachments/assets/3b030c07-a601-46cb-a3dd-4482d0640fdb" />
レポート作成画面で、分析対象のSHA256ハッシュ値を入力し、「レポートを作成」を押下します。    
<img width="2159" height="1181" alt="image" src="https://github.com/user-attachments/assets/7739b927-4d25-416b-b329-07f043900556" />  
レポート作成が完了すると、結果が画面に表示されます。    
<img width="2159" height="1176" alt="image" src="https://github.com/user-attachments/assets/990509a9-1d4f-4b70-8d1b-5f3e2bb08c5b" />  

4. **レポートの閲覧**
ホーム画面の「レポート一覧を見る」から、過去に作成したレポートや、他ユーザのレポート一覧を確認できます。  
<img width="2156" height="1180" alt="image" src="https://github.com/user-attachments/assets/179a0755-d519-4f13-8f86-fe5c38c67bcc" />
検索も可能です。  
<img width="2159" height="1180" alt="image" src="https://github.com/user-attachments/assets/827f7d9f-00ec-447c-8f0a-288e7e706449" />

## 技術仕様  
### システム構成図　　
<img width="531" height="401" alt="system_mws_hackson drawio" src="https://github.com/user-attachments/assets/52f26441-3dd8-4831-a44c-5fa427d8027d" />　　
- **Webサーバー:** Nginx  
- **アプリケーションサーバー:** Flask  
- **データベース:** PostgreSQL
- **インフラストラクチャ:** Docker

上記コンテナをDocker Composeで管理しています。  

### 外部API  
- **OpenAI API:** OSINT情報の収集と要約に利用。  
- **VirusTotal API:** ハッシュ値に基づく検体の基本情報（挙動、通信先、IoCなど）の取得に利用。 
- **MalwareBazaar API:** 類似検体のハッシュ値の取得に利用。  

### データベース設計  
<img width="721" height="386" alt="ER図 drawio" src="https://github.com/user-attachments/assets/5fc66608-ea16-4f1b-a8c1-6229c482a189" />  

- **usersテーブル**  
  ユーザ情報を管理  
- **reportsテーブル**    
  生成されたレポート情報を管理  
- **rolesテーブル**  
  ロールの番号とその役割を管理  
- **users_rolesテーブル**  
  ユーザがどのロールかを管理   
