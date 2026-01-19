# FakePoC-Hunter

FakePoC-Hunter は、高深刻度（High CVSS）のCVEに対する概念実証（PoC）コードをGitHubから自動的に収集し、その安全性を分析するツールです。

## 機能

- **CVE収集**: NVD (National Vulnerability Database) APIを使用して、指定されたCVSSスコア（デフォルト7.0）以上の脆弱性情報を取得します。
- **PoC検索**: 特定されたCVE IDに基づいて、GitHub上の関連リポジトリを検索します。
- **リポジトリ取得**: 発見されたリポジトリを自動的にクローンします。
- **安全性分析**:
    - **バイナリスキャン**: クローンしたリポジトリ内のバイナリファイル（.exeなど）をVirusTotalまたはVirusShareを使用してスキャンし、悪意のあるファイルの有無を確認します。
    - **静的解析**: ソースコード内の不審なパターン（難読化、バックドア、危険な関数など）を静的に解析します。
    - **Deep Scan**: より詳細な挙動分析を行います（実装依存）。
- **レポート生成**: 分析結果をCSV形式などで保存し、概要を出力します。

## 必要要件

- Python 3.x
- requests
- python-dotenv

## セットアップ

1. リポジトリをクローンします。
2. 仮想環境を作成し、依存関係をインストールします（`requirements.txt` がある場合）。
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install requests
   ```

3. `.env` や`config.py` を編集し、必要なAPIキーを設定します。

   - **GITHUB_TOKEN**: GitHub APIトークン
   - **VT_API_KEY**: VirusTotal APIキー
   - **VIRUSSHARE_API_KEY**: VirusShare APIキー
   - その他、スキャン対象の年（`START_YEAR`, `END_YEAR`）やCVSSしきい値（`CVSS_THRESHOLD`）を設定可能です。

## 使用方法

メインスクリプトを実行して、スキャンを開始します。

```bash
python3 main.py
```

実行ログが表示され、結果は `results/` ディレクトリに保存されます。

## ディレクトリ構成

- `cloned_repos/`: クローンされたGitHubリポジトリ
- `results/`: スキャン結果のレポート
- `nvd.py`: NVD API連携モジュール
- `github_search.py`: GitHub検索モジュール
- `repo_manager.py`: リポジトリ管理（クローン）モジュール
- `virustotal.py` / `virusshareclient.py`: バイナリスキャンモジュール
- `static_analysis.py`: 静的解析モジュール

## Analysis Results

このコードを使って実際にFakePoCを調査した結果は以下のURLに掲載しています。
- Analysis Results: https://konseclab.pages.dev/fakepoc-hunter/


## 免責事項

本ツールはセキュリティ研究および教育目的でのみ使用してください。悪意のある目的での使用は固く禁じられています。スキャン対象のリポジトリに含まれるコードを実行する際は、十分な注意を払い、隔離された環境（サンドボックス等）で行ってください。
