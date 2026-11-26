# syntax=docker/dockerfile:1
#
# 运行镜像（不在镜像里编译）：只装常用工具，放入**预编译好的 Linux 单二进制**。
# 二进制由 CI 的 binaries job 交叉编译（纯 Go、无 QEMU），按目标架构放在
# 构建上下文的 dist/<TARGETARCH>/behemoth。这样多架构构建时 arm64 只需模拟 apt 层，
# 不再模拟 Next/Go 编译，速度快得多。
#
# 本地手动构建镜像时，先自行准备二进制：
#   cd web && npm run build:static && cd ..
#   cp -r web/out server/webui/dist
#   CGO_ENABLED=0 GOARCH=amd64 go build -tags embedui -o dist/amd64/behemoth ./cmd/behemoth
#   docker build -t behemoth:local .
FROM python:3.12-slim-bookworm
ARG TARGETARCH
# 常用工具：ripgrep / curl / vim，加一批 recon/OCR/数据库客户端/安装器常备件。
# Node 从 NodeSource 装 22.x，与前端构建使用的主版本一致。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates gnupg lsb-release tar gzip xz-utils procps \
      ripgrep curl wget vim git jq unzip tzdata \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet socat whois nmap \
      tor tesseract-ocr tesseract-ocr-eng default-mysql-client postgresql-client \
      python3-venv pipx \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装内置 MCP 服务（Playwright MCP/CLI + Sequential Thinking + Knowledge Memory），运行时不再 npx 联网下载。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
      @modelcontextprotocol/server-sequential-thinking@latest @modelcontextprotocol/server-memory@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV TZ=Asia/Shanghai
ENV PATH="/usr/local/bin:/opt/google-cloud-sdk/bin:${PATH}"
# 预编译好的对应架构二进制（dist/amd64/behemoth 或 dist/arm64/behemoth）
COPY dist/${TARGETARCH}/behemoth /app/behemoth
# 守护启动脚本与自动装机脚本（autoProvisionLinuxArsenal 在容器启动与更新后同样可执行 ./setup.sh arsenal 自愈军火库）
COPY start.sh /app/start.sh
COPY setup.sh /app/setup.sh
RUN chmod +x /app/behemoth /app/start.sh /app/setup.sh
COPY skills/ /app/skills/
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]
