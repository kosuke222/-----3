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
5. localhost:5001にアクセスする

