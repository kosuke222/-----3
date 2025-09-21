# Malware-Analysis-OSINT-Tool

### 概要  
マルウェア解析の初動プロセスである公開情報調査(OSINT)を自動化するツールです。  
検体のSHA256ハッシュ値を入力するだけで　　
- 検体の基本情報
- 検体の挙動や通信先
- 類似検体の挙動
- 流行度  
- etc  
  
などを調査し、md形式のレポートにまとめます。
### 使い方  

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
```
OPENAI_API_KEY=(あなたの取得したOpenAIAPIキー)
FLASK_APP=app.py
FLASK_DEBUG=1
SECRET_KEY=(作成したkey)
SECURITY_PASSWORD_SALT=(作成したkey)
RESET_TOKEN_MAX_AGE=3600
MAIL_SERVER=mailhog
MAIL_PORT=1025
MAIL_USE_TLS=0
MAIL_USERNAME=no-reply@example.com
MAIL_PASSWORD=
MAIL_DEFAULT_SENDER=no-reply@example.com
APP_BASE_URL=http://localhost:5001
```

4. docker desktopを起動し，次のコマンドを実行
```
docker-compose up --build
```
5. localhost:5001/loginにアクセスする  
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/25cfb137-ddad-4725-a616-7a3786686cbc" />

6. アカウントを作成する
アカウントをお持ちではない方をクリックし，入力フォームに情報を入力する  
<img width="2159" height="1184" alt="image" src="https://github.com/user-attachments/assets/14403c46-0e65-4ad7-9ac9-187309153b15" />

ログイン画面に戻るので，必要情報を入力しログインをクリック
<img width="2159" height="1183" alt="image" src="https://github.com/user-attachments/assets/66e6fcb1-4a2a-46e8-882b-ffae0109b7a4" />

ホーム画面に遷移する  
<img width="2158" height="1180" alt="image" src="https://github.com/user-attachments/assets/3b030c07-a601-46cb-a3dd-4482d0640fdb" />

7. APIキーの設定
VirusTotal APIキーと、Malware Bazaar APIキーを取得しフォームに入力
<img width="2154" height="1179" alt="image" src="https://github.com/user-attachments/assets/2fb37723-0784-4e09-b3d5-c124bda0957c" />

8. レポート生成
「レポートを作成する」をクリックし、調査したい検体のsha256ハッシュ値を入力する。  
<img width="2159" height="1181" alt="image" src="https://github.com/user-attachments/assets/7739b927-4d25-416b-b329-07f043900556" />
すると、レポートが生成される(七分ほどかかる)  
<img width="2159" height="1176" alt="image" src="https://github.com/user-attachments/assets/990509a9-1d4f-4b70-8d1b-5f3e2bb08c5b" />

9. レポート一覧から作成したレポートの閲覧が可能
<img width="2159" height="1179" alt="image" src="https://github.com/user-attachments/assets/da8f3b79-8867-4d90-a708-6b2b7467559a" />
他ユーザが生成したレポートも閲覧が可能、キーワードを用いた検索もできる
<img width="2159" height="1176" alt="image" src="https://github.com/user-attachments/assets/aa54a4e1-26d0-45de-8625-969ada3b01d1" />




