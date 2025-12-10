# CHM
Rust 製作的基礎設施服務群組，涵蓋 CA / DNS / LDAP / DHCP / API / Controller / Agent (含 Host daemon)。所有服務以 gRPC/REST 搭配雙向 TLS 通訊，可由 Controller 統一啟停與註冊。

## 專案結構
- `apps/ca`、`apps/dns`、`apps/ldap`、`apps/dhcp`：各自負責憑證、DNS、身份與 DHCP 管理的服務。
- `apps/api`：提供前端/外部系統使用的 REST API，串接 Controller 與其他服務。
- `apps/controller`：服務註冊中心與調度器，維護 ServicesPool 與健康狀態。
- `apps/agent`：部署在節點的 gRPC agent/hostd，回報系統資訊並執行指令。
- `libs/*`：共用元件（憑證、gRPC 客戶端、cluster utils、config loader、VXLAN 工具等）。
- `config/`：各服務的 `*_config.toml`；`certs/`：服務與 RootCA 憑證；`db/`、`data/`：本地儲存與暫存檔。
- `justfile`：本地啟動、遷移、清理與釋出流程的指令集合。
- `frontend/`：前端程式碼，使用 `git subtree pull --prefix=frontend origin frontend-develop` 更新。

## 架構概念（服務職責與常用 Port）
- CA (`apps/ca`, Dev 50052)：簽發/吊銷憑證，維護 CRL。
- DNS (`apps/dns`, Dev 50053)：管理主機紀錄，依賴 Postgres。
- LDAP (`apps/ldap`, Dev 50054)：維護帳號與群組，預設 SQLite。
- DHCP (`apps/dhcp`, Dev 50055)：區域與 IP 管理，預設 SQLite。
- API (`apps/api`, Dev 50050)：對外 REST/HTTP 入口，連 Controller 與其他服務。
- Controller (`apps/controller`, Dev 50051)：節點註冊、OTP 驗證、服務池維護與健康檢查。
- Agent / Hostd (`apps/agent`, Dev 50056)：執行節點指令、收集系統資訊；Hostd 透過 socket 提供本機資訊。

Port 策略：開發環境依 App ID 拆分不同 port（如上），發行版會統一使用 `11209`（`ProjectConst::SOFTWARE_PORT`）；如需自訂，請同步調整各服務的 `Server` 及 Controller/Agent 端的目標位址。

所有服務使用雙向 TLS，Controller/Agent 會驗證對方的 fingerprint/serial。OTP 主要用於首次註冊。

## 先備需求
- Rust 1.74+（workspace edition 2021）、`cargo`, `rustup`。
- 工具：`just`、`sqlx-cli`、`protoc`（gRPC 已產生，但建議安裝）、`docker` 或 `podman`（DNS 用）。
- 資料庫：CA/LDAP/DHCP 預設 SQLite；DNS 需 Postgres 並啟用 `citext`/`inet`。
- OpenSSL vendored（已啟用 feature），musl 目標需安裝 `musl-gcc` 與 perl 套件（見文末）。

## 快速開始（開發）
1) 安裝工具  
   - `cargo install just sqlx-cli`（如需）  
   - DB：啟動 Postgres 並建立 `dns` 資料庫（或調整 `DNS_DATABASE_URL`）。
2) 設定環境變數（最低需求）
```shell
export CA_DATABASE_URL=sqlite://db/cert_store.db
export LDAP_DATABASE_URL=sqlite://db/ids.db
export DHCP_DATABASE_URL=sqlite://db/dhcp.db
export DNS_DATABASE_URL=postgres://chm:password@localhost:5432/dns
```
3) 初始化（產生配置、建立 DB、RootCA）  
   - 一次完成：`just run-init`（會對各服務執行 `-i` 並填寫預設值）  
   - 單服務生成範例設定檔：`just run-ca -i` / `just run-api -i` 等。
4) 啟動整個叢集  
   - `just start-cluster`（背景啟動 ca/dns/ldap/dhcp/api，並自動讓 Controller 加入它們）  
   - 檢查狀態：`just cluster-status`；查看 log：`just logs dns` 等。
5) 停止與清理  
   - `just stop-cluster`；必要時 `just clean-logs` 或 `just clean-all`（會清 DB/certs/config/data，慎用）。

> 單點開發：`just run-<service>` 直接前景啟動；`just run-*-bg` 背景啟動並記錄 PID。

## 配置與環境
- 檔案：`config/<SERVICE>_config.toml`；命名規則 `CHM_{ID}__{結構名稱}___{欄位名稱}` 可透過環境變數覆寫。
- 重要區段
  - `[Server]`：hostname、host、port、otp_len/time、dns_server。
  - `[Certificate]` / `[Certificate.CertInfo]`：RootCA/客戶端憑證位置、簽發資訊與 SAN。
  - `[Extend]`：各服務特有設定（例如 API 的 `Security`、Controller 的 `ServicesPool`、Agent 的降權帳號與併發度）。
- 憑證：`certs/` 內的 RootCA、服務 cert/key；`run-init` 會產生預設檔與 rootCA。
- 資料庫與 Migration：  
  - CA/LDAP/DHCP：SQLite，migration 位於 `apps/<svc>/migrations`。  
  - DNS：Postgres，需啟用 `citext`；可用 `just migrate-dns`、`reset-dns`。  
  - 全部：`just migrate-all` / `reset-all`。
- Controller 註冊：`ServicesPool` 預填本地 URI，可用 `just run-controller "add -H https://<host>:<port> -p <otp>"` 或 `remove` 來維護。
- Port/OTP：調整 `Server` 區段後，請同步更新其他服務的 Controller/CA/DNS 位址。

## 常用 Just 指令
- `just run-init`：一次完成各服務 `-i` 初始化並調整預設配置。
- `just start-cluster` / `stop-cluster` / `cluster-status`：背景啟停與狀態查詢。
- `just migrate-*`、`reset-*`：針對各服務執行 SQLx migration 或重置。
- `just run-*-bg`、`just kill-*`：單一服務背景啟動/停止。
- `just release-all`：預先準備 SQLx 並建置 release 版本；`build-release(-musl)` 直接建置。

## 開發/除錯 Tips
- Log 位置：`/tmp/chm_logs/<svc>.log`（由 `start-cluster`、`run-*-bg` 產生）。
- PID 位置：`/tmp/chm_pids/<svc>.pid`；`just cluster-status` 會讀取。
- 清理：`just clean-logs` 清除 log/OTP/PID；`just clean` 會重置 DB/憑證/配置（慎用）。
- OTP/Port 取得：`start-cluster` 會從 log 解析 OTP/Port 並顯示；若手動啟動，請檢視對應 log。
- gRPC/REST 憑證：API/Controller/Agent 皆使用雙向 TLS，開發時需保留 `certs/` 下的 pem/key。

## Shell 補齊 (chm tools)
- bash：在 `~/.bashrc` 追加
```shell
if [ -f /etc/bash_completion ]; then source /etc/bash_completion; fi
if [ -d "$HOME/.bash_completion.d" ]; then
  for bcfile in "$HOME"/.bash_completion.d/*.bash; do
    [ -r "$bcfile" ] && source "$bcfile"
  done
fi
```
- zsh：在 `~/.zshrc` 追加 `fpath+=(~/.zsh/completion)` 並執行 `autoload -Uz compinit && compinit`（使用 oh-my-zsh 時可加入 `rust` plugin）。
- fish：重啟 shell 即會載入。
- PowerShell：`notepad $PROFILE`，加入 `Import-Module cargo-chm`。

## OpenSSL vendored（musl 範例）
需要 `perl`、`perl-FindBin`、`musl-gcc`、`perl-IPC-Cmd`、`perl-Time-Piece`：
```shell
sudo ln -s /usr/bin/musl-gcc /usr/bin/x86_64-linux-musl-gcc
rustup target add x86_64-unknown-linux-musl
```
