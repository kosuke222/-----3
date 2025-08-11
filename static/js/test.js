document.addEventListener('DOMContentLoaded', function() {
    
    const testButton = document.getElementById('test-button');
    const responseOutput = document.getElementById('response-output');

    if (testButton) {
        testButton.addEventListener('click', function() {

            responseOutput.textContent = 'APIにリクエストを送信中...';

            fetch('/api/test', {
                method: 'GET'
            })
            .then(response => {
                if (!response.ok) {
                    return response.text().then(text => { 
                        throw new Error(`サーバーエラー: ${response.status}\n${text}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.report) {
                    let outputText = `サーバーメッセージ: ${data.message}\n\n`;
                    outputText += '--- 生成されたレポート ---\n';
                    outputText += JSON.stringify(data.report, null, 2);
                    responseOutput.textContent = outputText;
                } else {
                    responseOutput.textContent = `サーバーからのメッセージ: ${data.message || JSON.stringify(data)}`;
                }
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                responseOutput.textContent = `エラーが発生しました:\n${error.message}`;
            });
        });
    }
});
