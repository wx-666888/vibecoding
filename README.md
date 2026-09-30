# Banner 指纹识别系统 (Banner Fingerprint Engine)

基于 Golang 开发的高性能网络扫描原始 Banner 指纹识别系统。支持对目标资产的原始扫描数据（IP、端口、Banner）进行精准解析，识别协议、服务组件（Product）、版本号（Version）及操作系统标识（OS Hint），并输出置信度。

本项目采用 Client + Server 架构，通过 Docker Compose 实现生产级、轻量化与高安全规格的一键启动交付。

---

## 1. 核心架构与设计特点

* **Client + Server 架构解耦**：
  * **Server**：提供高吞吐的 `POST /fingerprint`（批量识别）与 `GET /health`（真实健康检查）接口；
  * **Client**：独立命令行程序，负责读取输入数据、通过 HTTP 批量提交，并将规范化的 JSON 结果美观打印至标准输出；
  * **Engine**：独立于 HTTP 传输层，便于纯引擎单测与跨平台复用。
* **规则与代码分离**：
  * 正则特征、优先级、版本捕获组与置信度完全解耦于 `rules/rules.json`；
  * 内置 Go `//go:embed` 规则兜底，确保在任何运行环境与容器路径下均可 100% 健壮启动。
* **协议深度解析引擎**：
  * **MySQL/MariaDB**：二进制握手报文帧解析，精准提取版本与区分 MariaDB，针对畸形报文进行越界防护；
  * **SSH**：兼容 SSH-2.0 与 SSH-1.99 规范，识别 OpenSSH 等组件及 Linux 发行版；
  * **HTTP**：覆盖 nginx, Apache, Jetty, Microsoft-IIS 及通用 HTTP 状态行回退识别；
  * **Redis**：支持 RESP 协议常见响应（`-ERR`, `-NOAUTH`, `+PONG` 等），不限端口误判；
  * **FTP**：支持 ProFTPD, vsFTPd, Pure-FTPd 及通用 FTP 响应识别；
  * **TLS**：识别 TLS/SSL Handshake 握手报文。
* **生产级安全容器加固**：
  * **极小化镜像**：多阶段构建，采用纯静态编译与 `scratch` 基础镜像，零 shell、零 curl 冗余依赖；
  * **最小权限原则**：指定非 root 用户（UID `65532:65532`），容器开启 `read_only: true`，卸载全部特权 `cap_drop: [ALL]`，启用 `no-new-privileges:true`；
  * **真实健康检查**：内置 `server healthcheck` 二进制探针，Client 严格依赖 `service_healthy`，健康轮询间隔秒级就绪；
  * **网络边界收敛**：容器间通过专用桥接网络通信，不对外暴露 Client，Server 仅默认按需绑定本机。

---

## 2. 快速开始与一键启动

### 2.1 使用 Docker Compose 一键启动（推荐）

执行以下命令即可一键构建镜像、启动 Server，并在健康就绪后自动运行 Client 完成识别：

```bash
docker compose up --build
```

**运行效果**：
Client 容器将自动等待 Server 健康检查通过，随后读取 `./examples/input.json`，完成批量识别并在控制台以美观的格式化 JSON 输出 20 条自测数据的识别深度结果。
* 默认情况下，Client 已启用 `KEEP_ALIVE=true`，输出识别结果后保持容器持续运行（Up 状态），便于随时通过 `docker compose ps` 查看状态或 `docker compose logs client` 复查结果；按 `Ctrl+C` 或执行 `docker compose down` 即可优雅关闭。
* 若在自动化 CI/批处理流水线中希望 Client 识别后自动退出，只需设置 `KEEP_ALIVE=false`：
  ```bash
  KEEP_ALIVE=false docker compose up --build --exit-code-from client
  ```

### 2.2 替换测试数据运行

若需要使用外部或评测测试数据进行验证，有以下两种方式：

1. **直接替换示例文件**：
   将你的输入 JSON 文件覆盖 `./examples/input.json`，然后重新执行 `docker compose up`。
2. **挂载外部输入文件**：
   ```bash
   docker compose run --rm -v /path/to/your_input.json:/data/input.json client
   ```

---

## 3. 本地编译与单测运行

本地需要已安装 Go 1.22+ 环境。

### 运行单元测试
```bash
go test -v ./...
```
包含：
* `internal/fingerprint`：覆盖自测 20 种典型用例、畸形报文、未识别 unknown 场景的单测；
* `internal/api`：覆盖 HTTP 路由分发、健康检查探针、大包限制与非标字符兼容测试。

### 本地编译与运行
```bash
# 启动 Server
go run ./cmd/server

# 在另一个终端运行 Client (支持 -input 与 -server 传参)
go run ./cmd/client -input ./examples/input.json -server http://localhost:8080
```

---

## 4. 接口契约说明

### 4.1 健康检查接口
* **请求**：`GET /health`
* **响应**：`200 OK`
  ```json
  {"status": "ok"}
  ```

### 4.2 批量识别接口
* **请求**：`POST /fingerprint`
* **Header**：`Content-Type: application/json`
* **请求体（示例）**：
  ```json
  [
    {"ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
    {"ip": "1.2.3.7", "port": 3306, "banner": "J\u0000\u0000\u0000\n8.0.32\u0000"}
  ]
  ```
* **响应体（示例）**：
  ```json
  [
    {
      "ip": "1.2.3.4",
      "port": 22,
      "protocol": "SSH",
      "product": "OpenSSH",
      "version": "8.9p1",
      "os_hint": "Ubuntu",
      "confidence": 0.95
    },
    {
      "ip": "1.2.3.7",
      "port": 3306,
      "protocol": "MySQL",
      "product": "MySQL",
      "version": "8.0.32",
      "os_hint": "",
      "confidence": 0.9
    }
  ]
  ```

### 4.3 无法识别情况下的语义约定
当输入的 Banner 无法命中任何已知规则或协议时，系统返回：
* `protocol`: `"unknown"`
* `product`: `""`
* `version`: `""`
* `os_hint`: `""`
* `confidence`: `0`
* **容错保证**：任何无法识别或畸形的 Banner 均不会中断批处理流程或引发 500 崩溃，接口严格按顺序返回同长度数组。

---

## 5. 二进制数据与非标转义兼容处理

在网络扫描中，二进制协议（如 MySQL Handshake、TLS Client Hello 等）包含 NUL 字节。
* **标准 JSON 格式**：建议将 `\x00` 表达为标准合法的 `\u0000` 转义；
* **非标转义自动容错**：若扫描器导出的原始 JSON 文件直接包含非 RFC 8259 的 `\xNN` 字面量文本，Server 内部的反序列化兼容层会自动在流式解析时将其无损标准化，避免因客户端 JSON 语法错误被驳回。

---

## 6. 扩展新规则

只需在 `rules/rules.json` 中追加规则即可，无需重新编译代码：

```json
{
  "id": "http-caddy",
  "priority": 90,
  "pattern": "(?im)^Server:[ \\t]*Caddy(?:/([0-9][^\\s;()]*))?",
  "protocol": "HTTP",
  "product": "Caddy",
  "version_group": 1,
  "confidence": 0.90
}
```
* `id`：全局唯一规则标识符；
* `priority`：匹配优先级（数值越高越先匹配）；
* `pattern`：支持 RE2 语法正则；
* `version_group`：指定捕获版本号的正则分组索引（0 表示无版本捕获）；
* `confidence`：识别置信度（0.0 ~ 1.0）；
* `ports`（可选）：限制仅在指定端口生效。
