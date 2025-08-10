from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

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