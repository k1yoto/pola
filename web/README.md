# Pola GUI - Web Frontend

Pola PCEのWebベースのGUIフロントエンドです。

## 技術スタック

- **フレームワーク**: React 19 + TypeScript
- **ビルドツール**: Vite
- **ルーティング**: React Router v7
- **HTTPクライアント**: Axios
- **スタイリング**: CSS（カスタム、ダーク/ライトモード対応）

## 開発環境セットアップ

### 前提条件

- Node.js 18以上
- npm または yarn

### インストール

```bash
cd web
npm install
```

### 開発サーバー起動

```bash
npm run dev
```

開発サーバーは `http://localhost:5173` で起動します。

## E2Eテスト手順（バックエンド統合確認）

### 1. バックエンドサービスの起動

まず、以下のサービスを起動します:

#### gobgpd の起動

```bash
cd /home/nakata/dev/pola-verification/gobgp
# gobgpdを適切な設定で起動
```

#### polad の起動

```bash
cd /home/nakata/dev/pola-verification/pola
# polad を起動（gobgpdと接続する設定で）
./cmd/polad/polad -f configs/polad.yaml
```

#### pola-gui の起動

```bash
cd /home/nakata/dev/pola-verification/pola
# pola-gui を起動
./cmd/pola-gui/pola-gui
```

pola-guiは `http://localhost:8080` でAPIサーバーを起動します。

### 2. フロントエンド開発サーバーの起動

```bash
cd /home/nakata/dev/pola-verification/pola/web
npm run dev
```

### 3. 動作確認

ブラウザで `http://localhost:5173` にアクセスし、以下を確認:

#### ✓ PCEP Sessions セクション
- セッション一覧が表示される
- Address、State、Capabilities、Synced状態が正しく表示される
- ローディング状態が正しく表示される
- エラー時にエラーメッセージが表示される

#### ✓ SR Policies セクション
- Peerアドレスごとにグループ化されたポリシー一覧が表示される
- Name、Source、Destination、Color、Preference、Segment Listが正しく表示される
- Segment ListのSIDが正しく表示される

#### ✓ Traffic Engineering Database (TED) セクション
- TED ID、Total Nodesの情報が表示される
- ノード一覧（ASN、Router ID、Hostname、SRGB等）が表示される
- Links、Prefixes、SRv6 SIDsの個数バッジが表示される

#### ✓ ナビゲーション
- ヘッダーのDashboardリンクが動作する
- ページ遷移が正しく動作する

#### ✓ スタイリング
- ダークモード/ライトモードで適切に表示される
- レスポンシブデザインが動作する
- ホバー効果が動作する

### 4. APIエンドポイント確認

curlコマンドでバックエンドAPIを直接確認:

```bash
# Sessions取得
curl http://localhost:8080/api/sessions

# TED取得
curl http://localhost:8080/api/ted

# Policies取得
curl http://localhost:8080/api/policies
```

### 5. ブラウザ開発者ツールでの確認

- Console: エラーがないことを確認
- Network: APIリクエストが正しく送信され、レスポンスが返ってくることを確認
- CORS: CORSエラーがないことを確認

## プロジェクト構造

```
web/
├── src/
│   ├── api/              # APIクライアント
│   │   └── client.ts     # axios-based API client
│   ├── components/       # Reactコンポーネント
│   │   ├── SessionList.tsx
│   │   ├── SRPolicyList.tsx
│   │   └── TEDView.tsx
│   ├── pages/            # ページコンポーネント
│   │   └── Dashboard.tsx
│   ├── types/            # TypeScript型定義
│   │   └── api.ts
│   ├── App.tsx           # メインアプリケーション
│   ├── App.css           # アプリケーションスタイル
│   ├── main.tsx          # エントリーポイント
│   └── index.css         # グローバルスタイル
├── .env.development      # 開発環境変数
├── package.json
├── tsconfig.json
└── vite.config.ts
```

## 環境変数

### 開発環境 (`.env.development`)

```
VITE_API_BASE_URL=http://localhost:8080
```

本番環境では、適切なバックエンドURLを設定してください。

## ビルド

```bash
npm run build
```

ビルド成果物は `dist/` ディレクトリに出力されます。

## プレビュー

ビルド後のプレビュー:

```bash
npm run preview
```

## 今後の開発予定

- Phase 4: ポリシー作成・削除機能の実装
- Phase 6: トポロジビジュアライゼーション（vis-network）
- Phase 7: WebSocketによるリアルタイム更新
- Phase 8: go:embedによるReact埋め込み、本番ビルド設定
