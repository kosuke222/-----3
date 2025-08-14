-- rolesテーブル
CREATE TABLE roles(
	role_id SERIAL PRIMARY KEY,
	role_name VARCHAR(50) UNIQUE NOT NULL
);

-- usersテーブル
CREATE TABLE users(
	user_id SERIAL PRIMARY KEY,
	username VARCHAR(255) UNIQUE NOT NULL,
	email VARCHAR(255) UNIQUE NOT NULL,
	password TEXT NOT NULL, -- パスワードはハッシュ化して保存
	api_key TEXT, -- APIキーは暗号化して保存
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- user_rolesテーブル
CREATE TABLE user_roles(
	user_id INT NOT NULL,
	role_id INT NOT NULL,
	PRIMARY KEY (user_id, role_id),
	FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
	FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE
);

--repotsテーブル
CREATE TABLE reports(
	report_id SERIAL PRIMARY KEY,
	user_id INT NOT NULL,
	malware_family VARCHAR(255),
	hash_sha256 VARCHAR(64) NOT NULL,
	report_markdown TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

--コメント
COMMENT ON TABLE users IS 'ユーザ情報を格納するテーブル';
COMMENT ON COLUMN users.password IS 'ユーザのパスワード（ハッシュ化済み）';
COMMENT ON COLUMN users.api_key IS 'ユーザのAPIキー（暗号化済み）';
COMMENT ON TABLE reports IS 'レポート情報を格納するテーブル';
COMMENT ON COLUMN reports.report_markdown IS 'レポートのMarkdown形式の内容';

--データ定義
INSERT INTO roles(role) VALUES ('admin'), ('user');
INSERT INTO users(username, email, password) VALUES
('sample1', 'sample1@example.com', 'your_hashed_password_here');

-- sample1はuser権限を持つ
INSERT INTO user_roles(user_id, role_id) VALUES (1, 2);