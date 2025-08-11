document.addEventListener('DOMContentLoaded', function() {
    
    // IDを使ってボタンと出力エリアの要素を正しく「取得」する
    const testButton = document.getElementById('test-button');
    const responseOutput = document.getElementById('response-output');

    // ボタンがページ内に存在する場合のみ、クリックイベントを設定
    if (testButton) {
        testButton.addEventListener('click', function() {
            // 処理が開始したことをユーザーに通知
            responseOutput.textContent = 'APIにリクエストを送信中...';

            // Flaskの /api/test エンドポイントを呼び出す
            fetch('/api/test', {
                method: 'GET'
            })
            .then(response => {
                // サーバーからエラーが返ってきた場合、その内容をテキストで取得
                if (!response.ok) {
                    return response.text().then(text => { 
                        throw new Error(`サーバーエラー: ${response.status}\n${text}`);
                    });
                }
                // 正常な場合はJSONとして解析
                return response.json();
            })
            .then(data => {
                // 受け取ったdataオブジェクト全体を整形して表示する
                responseOutput.textContent = JSON.stringify(data, null, 2);
            })
            .catch(error => {
                // エラーが発生した場合の処理
                console.error('Fetch Error:', error);
                responseOutput.textContent = `エラーが発生しました:\n${error.message}`;
            });
        });
    }
});