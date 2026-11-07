# 贡献指南

感谢你考虑为 `env-guard` 做贡献。本文说明开发环境、测试、提交规范和 PR 流程。

## 环境配置

1. Fork 并克隆本仓库。
2. 在项目根目录创建虚拟环境：

   ```bash
   python3 -m venv .venv
   ```

3. 激活虚拟环境：

   ```bash
   source .venv/bin/activate
   ```

4. `env-guard` 只依赖 Python 标准库，无需安装第三方依赖。
5. 项目要求 Python 3.11 或更高版本。

如需初始化项目本地缓存目录，可运行：

```bash
python engine/guard.py init
```

## 如何跑测试

每次修改策略、CLI 或启动器后都应运行：

```bash
python3 tests/test_guard.py
```

提交前请确保：

- 测试全部通过；
- 未引入新的第三方依赖；
- 未削弱默认 fail-closed 安全边界；
- 未绕过 `engine/guard.py` 的命令策略。

## 项目约定

- `engine/guard.py` 是唯一策略引擎；
- `check` 是只读命令；
- `init` 是唯一初始化命令；
- 执行命令前先用 `inspect` 验证；
- 确认允许后再通过 `run` 执行；
- 不把 shell 语法、管道、重定向或命令替换传给 `run`；
- 不把密钥写入代码、命令行参数或日志。

## Commit 规范

使用 Conventional Commits：

```text
<type>(<scope>): <subject>
```

常用 `type`：

- `feat`：新增功能；
- `fix`：修复缺陷；
- `docs`：文档变更；
- `test`：测试变更；
- `refactor`：不改变行为的重构；
- `chore`：构建、工具或仓库维护。

示例：

```text
feat(engine): block host-mounted Docker volumes
docs(readme): clarify the security boundary
```

提交主题使用英文，保持简洁、准确，完整描述变更意图。

## PR 流程

1. 从最新 `main` 分支创建功能分支；
2. 完成代码、测试和文档变更；
3. 运行 `python3 tests/test_guard.py`；
4. 推送分支并创建 PR；
5. 在 PR 中说明变更、测试结果和安全影响；
6. 等待 CI 在 Ubuntu 和 Windows 上完成测试；
7. 根据评审意见更新分支，直到获得批准。

PR 模板见 `.github/PULL_REQUEST_TEMPLATE.md`。
