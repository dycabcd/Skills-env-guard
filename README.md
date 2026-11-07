# env-guard — 把 AI 助手牢牢锁在项目里的安全门面

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

`env-guard` 是一个项目本地的 Python 安全工具。它为 AI 助手提供统一的命令检查门面：在执行依赖、构建、测试、浏览器或容器命令前，先校验程序、子命令、参数、路径和网络目标，尽量把写入与缓存留在项目根内。

## 项目定位

`env-guard` 有两种使用方式：

1. **独立 Python 工具**：直接调用 `engine/guard.py`，用 `check`、`init`、`inspect` 和 `run` 管理命令执行。
2. **AI Skill**：把整个 `env-guard/` 文件夹安装为 Codex、Trae、OpenCode 等 AI 助手的技能，让助手在执行命令前遵循同一套策略。

它面向人类开发者与 AI 生态，但不是权限提升工具，也不是沙箱替代品。

## 目录职责

| 路径 | 面向对象 | 职责 |
|---|---|---|
| `README.md` | 人类开发者 | 项目介绍、快速开始、能力边界和贡献入口 |
| `AGENTS.md` / `SKILL.md` | AI 助手 | AI 执行纪律、策略入口和安全规则 |
| `engine/` | 人类开发者与 AI | 核心策略引擎、默认策略和跨平台启动器 |
| `tests/` | 维护者与 CI | 命令策略回归测试 |
| `references/` | 维护者 | 策略说明、覆盖矩阵和配置解释 |
| `adapters/` / `agents/` | AI 生态 | 不同 AI 助手的适配说明 |
| `.github/` | 维护者与贡献者 | 议题模板、PR 模板和 CI 流水线 |

## 快速开始

### 方式一：作为独立 Python 工具

在项目根目录运行：

```bash
# 只读检查当前项目状态
python3 engine/guard.py check

# 初始化项目本地缓存目录；这是唯一会创建目录的命令
python3 engine/guard.py init

# 只校验命令，不执行
python3 engine/guard.py inspect -- npm ci

# 校验通过后执行一个命令
python3 engine/guard.py run -- python -m pytest tests
```

说明：

- `--` 后面必须是一个 argv 命令；
- 不支持 shell 语法、管道、重定向、命令替换或多命令组合；
- 未在白名单中的程序、子命令和路径会按 fail-closed 原则拒绝；
- Unix 可用 `engine/guard.sh`，Windows 可用 `engine/guard.ps1`。

### 方式二：作为 AI Skill

1. 将整个 `env-guard/` 文件夹复制到目标 AI 助手的 skills 目录；
2. 按该助手的文档注册或启用这个 skill；
3. 让助手读取 `AGENTS.md` 或 `SKILL.md`；
4. 要求助手执行命令前先调用 `engine/guard.py inspect`，确认允许后再调用 `run`。

不要只复制 `engine/` 目录：`SKILL.md`、`AGENTS.md` 和策略文档负责约束 AI 的调用方式。

## 能力边界声明

> **本工具是命令门面，不是操作系统沙箱。**

`env-guard` 只能检查传给它的 argv，无法控制已启动进程的后续行为。它不能替代操作系统沙箱、容器隔离、文件权限或网络防火墙。

以下场景超出保障范围：

- 命令未经过 `engine/guard.py run` 执行；
- shell 管道、重定向、命令替换或多命令组合；
- 编译后二进制文件内部行为；
- 已启动进程后续访问文件或网络；
- 通过其他进程间通信、内核接口或系统工具发起的操作；
- 绕过本工具直接执行的 shell 内建命令；
- `python -c`、`node -e` 等动态载荷入口的深层语义。

引擎会阻断常见动态载荷入口，但无法证明所有载荷都安全。因此不应将 `env-guard` 作为唯一的隔离边界。

## 贡献指南

- 提交缺陷或功能建议：使用 `.github/ISSUE_TEMPLATE/bug_report.md` 或 `feature_request.md`；
- 参与代码贡献：先阅读 `CONTRIBUTING.md`；
- 提交 PR：使用 `.github/PULL_REQUEST_TEMPLATE.md`；
- 行为规范：见 `CODE_OF_CONDUCT.md`。

## 许可证

MIT License，详见 `LICENSE`。
