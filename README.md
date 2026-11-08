# 漏洞知识库（Vuln KB）

面向小团队的、可追溯来源的漏洞复现材料知识库。首要工作流是按产品名检索已经审核的漏洞、影响版本、复现步骤、PoC/EXP 和原始来源。

## 当前实现

- FastAPI 网页检索和 JSON 查询 API；产品、厂商、版本、CVE/关键词检索，带产品建议和分页。
- PostgreSQL 生产库，SQLAlchemy 领域模型与 Alembic 迁移；SQLite 可用于本地开发。
- PostgreSQL 迁移启用 `pg_trgm` 并为产品、厂商、漏洞标题/摘要建模糊检索索引。
- 内容寻址 SHA-256 对象存储，GitHub raw、Exploit-DB 和配置 Feed 采用有大小上限的异步分块导入；来源文档和不可变修订、材料版本、原始 URL、许可证提示与审核状态分开保存。
- GitHub 仓库文件发现（沿 Git tree 分目录遍历）和 Exploit-DB CSV/材料适配器；来源抓取进入持久任务队列。
- OpenAI Chat Completions 兼容模型配置；AI 返回结构化审核结果，服务器再验证来源域、原文证据片段、产品映射、审核门槛和预算。
- 多用户角色字段（viewer/editor/admin）、管理员采集和 AI 配置、材料下载、候选发布、Markdown 代次导出。
- Markdown 导出采用规范 KB UUID 记录，再生成“开源/不开源/待确认/特殊”浏览入口和原始材料 sidecar；无法确认开源状态时进入待确认分类。
- PoC/EXP 以附件下载方式提供；服务端不执行采集到的内容。

设计基线见 [`docs/漏洞知识库爬虫与存储系统设计.md`](docs/漏洞知识库爬虫与存储系统设计.md)，任务分解见 [`docs/漏洞知识库开发计划.md`](docs/漏洞知识库开发计划.md)。
新数据源接入步骤见 [`docs/数据源适配器开发.md`](docs/数据源适配器开发.md)。

## 本地开发

需要 Python 3.12+ 和 uv。在仓库根目录执行锁文件安装：

```powershell
py -3.12 -m pip install uv
uv sync --locked
Copy-Item .env.example .env
```

修改 `.env` 中的 `SECRET_KEY` 和 `BOOTSTRAP_ADMIN_PASSWORD`，然后启动网页和采集 worker（各开一个终端）：

```powershell
uv run uvicorn vuln_kb.main:app --app-dir src --reload
uv run python -m vuln_kb.worker
```

打开 <http://localhost:8000>。若没有通过环境变量配置 `BOOTSTRAP_ADMIN_PASSWORD`，创建管理员：

```powershell
vuln-kb create-admin admin "use-a-long-unique-password"
```

默认 SQLite 文件和材料在 `data/`。设置 `DATABASE_URL` 为 PostgreSQL DSN 可切换数据库；使用 PostgreSQL 本地开发时执行 `uv sync --locked --extra postgres`（`requirements.txt` 和 Docker 镜像已包含该可选驱动）。本地启动默认自动创建 schema；部署时用 Alembic 迁移。

## Docker Compose

复制 `.env.example` 为 `.env`，设置 `APP_ENV=production`、`POSTGRES_PASSWORD`、强随机 `SECRET_KEY` 和独立的 `BOOTSTRAP_ADMIN_PASSWORD`。首次启动：

```powershell
docker compose -f compose.yml up --build -d
```

Web：<http://localhost:8000>。`web` 和 `worker` 共享对象卷，PostgreSQL 单独持久化。升级后先运行 `docker compose -f compose.yml run --rm migrate`，再重建服务。生产反向代理应启用 HTTPS，设置强密钥和备份策略。

PowerShell 可运行 `./ops/backup.ps1` 生成 PostgreSQL custom dump 和不可变对象卷压缩包。恢复时先停止 `web`/`worker` 写入，再将对象压缩包解到 `/data/objects` 对应卷，并通过 `pg_restore` 恢复数据库；之后重建导出代次。恢复演练和 RPO/RTO 尚未验证。

## 配置来源和 AI

管理员登录后进入“管理与采集”。GitHub 来源填写 `owner/repo`；GitHub API token 可通过 `GITHUB_TOKEN` 提高 API 配额。Exploit-DB 探测通过后可提交同步任务。任务在独立 worker 中处理；单轮发现上限是队列批大小，不是知识库总量上限。

可复制 `configs/sources.example.yml` 为 `configs/sources.yml` 增加公开 RSS/JSON Feed。适配器只允许 HTTPS 且主机名必须在该源自己的 `allow_hosts` 列表中；应将 `material_url` 映射到真实 PoC/EXP 或完整复现文档。新来源经候选、AI 审核和统一发布门槛，不直接写入正式漏洞表。

AI 配置支持兼容 `POST {base_url}/chat/completions` 的服务：设置服务 URL、模型名、API Key、每日预算、输入/输出单价。Key 使用 `SECRET_KEY` 派生密钥加密存储；更换 `SECRET_KEY` 前需迁移或重新录入 API Key。通过审核与自动发布是两个独立开关；关闭自动发布时，管理员可以从候选区发布已通过 AI 材料审核的记录。

远程模型主机需加入 `.env` 的 `AI_ALLOWED_HOSTS` 逗号分隔白名单（如 `api.example.com`）；本机模型 `localhost`、`127.0.0.1` 和 `::1` 默认允许。此白名单只控制服务端到模型 Provider 的连接，与来源 Adapter 的抓取主机白名单相互独立。

首次使用模型前应确认该 Provider 支持 JSON response format。系统只会评估来源内容，不向模型授予工具调用权限；模型无法访问采集 worker、对象存储或公司网络的执行能力。

## API 摘要

- `GET /healthz`：健康检查。
- `GET /readyz`：依赖就绪检查（数据库可达）。
- `GET /api/search?q=&product=&company=&version=&limit=&cursor=`：登录后按产品名/别名/厂商/版本检索已发布记录；`next_cursor` 用于稳定续页，游标绑定当前筛选条件。
- `GET /api/suggest?q=`：产品名称建议。
- `GET /api/coverage`：已发布漏洞、产品关系、合格材料、来源分区和任务状态统计；没有可靠全网总量时不计算覆盖百分比。
- `GET /api/products/{product_id}/vulnerabilities`：指定产品的已发布漏洞列表，支持 `cursor` 续页。
- `GET /api/vulnerabilities/{kb_id}`：漏洞、产品影响关系及已审核材料/复现步骤详情。
- `GET /v/{kb_id}`：漏洞详情。
- `GET /materials/{material_id}/download`：登录后以附件方式下载已发布材料。
- 管理 API：`POST /api/admin/jobs`、`PUT /api/admin/ai`、来源探测、候选发布、`POST /api/admin/export`。
- OpenAPI 文档：`/docs`。

## 已知边界

- GitHub 支持公开仓库搜索和单仓库递归发现；全量索引图谱/语义引用解析、GHSA/HackerOne/厂商公告关联、映射配置 UI、Sploitus 可用性探测和自动补全仍需按开发计划扩展。
- AI 自动发布依赖产品名、版本、证据和复现步骤提取质量；阈值与规则版本需用真实来源样本校准。材料通过内容审核不等同于团队独立实验验证。
- 自动生成导出当前支持组织/产品/版本/漏洞分层和固定代次；去重 alias view、撤销旧离线包、细粒度覆盖仪表板和完整 RPO/RTO 恢复流程尚待完成。
- SQLite 仅供本地开发和单进程使用；团队共享部署使用 PostgreSQL。应用不执行、也不建议在生产服务中执行下载的 PoC/EXP。

