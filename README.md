# LogSleuth · Web 日志安全调查平台

[English](#english) · [中文](#中文)

## 中文

LogSleuth 是一个**本地优先**的 Web 日志调查工具。上传 Apache 或 Nginx 访问日志后，它会在浏览器中生成可核实的攻击时间线；日志不会被发送到第三方服务。

### 前端页面

项目已包含完整前端页面，入口为 [`app/page.tsx`](app/page.tsx)。界面默认显示中文，右上角可一键切换 `中文 / EN`。

前端功能：

- 上传 `.log`、`.txt` 格式的 Web 访问日志，或使用内置安全演示日志。
- 本地检测 SQL 注入、XSS、目录穿越、敏感文件探测、命令注入探测与可疑登录攻击。
- 展示风险评分、攻击事件时间线和可疑 IP 活动集中度。
- 导出 Markdown 格式调查报告。
- 不发起扫描、利用或任何外部网络攻击；规则命中应作为人工复核线索。

### 使用方法

准备环境：安装 [Node.js 22.13 或更高版本](https://nodejs.org/)。在项目目录执行：

```bash
npm install
npm run dev
```

终端会显示本地访问地址。打开它后：

1. 点击“上传访问日志”，选择 Nginx 或 Apache 的访问日志；或点击“加载安全演示”。
2. 查看风险评分、事件时间线与可疑来源 IP。
3. 使用时间线右上方筛选按钮聚焦 `Critical`、`High` 或 `Medium` 事件。
4. 点击“导出 Markdown 报告”保存调查结论。

生产构建与测试：

```bash
npm run build
npm test
```

### 隐私与边界

日志解析和规则匹配完全在客户端浏览器完成。应用没有 API Key、遥测、持久化数据库或外部目标交互。

### 项目结构

```text
app/page.tsx       前端界面、本地解析器与规则引擎
app/globals.css    响应式仪表盘样式
tests/             页面渲染冒烟测试
```

## English

LogSleuth is a **local-first** web log investigation workspace. Upload an Apache or Nginx access log to generate an analyst-verifiable attack timeline in the browser; evidence never leaves the device.

### Features

- Browser-side common-log parsing.
- Detection of SQL injection, XSS, path traversal, sensitive-file probes, command-injection probes, and concentrated login attempts.
- Severity-ranked timeline, suspicious-IP concentration, risk scoring, and Markdown report export.
- A safe synthetic demo log with no active scanning, exploitation, or external target interaction.

### Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

Open the local URL printed by the development server. Use `npm run build` for a production build and `npm test` to run the rendered-page test.

## License

MIT. See [LICENSE](LICENSE).
