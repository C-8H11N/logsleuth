# LogSleuth — Web 日志与抓包安全分析平台

[中文](#中文) · [English](#english)

## 中文

LogSleuth 是一个本地优先的安全调查工具。它能在浏览器中分析 Apache/Nginx 访问日志和 PCAP/PCAPNG 抓包文件，并生成可供人工复核的风险时间线。默认分析不会把原始数据发送给第三方。

### 功能

- 上传 `.log`、`.txt` Web 访问日志，检测 SQL 注入、XSS、目录穿越、敏感文件探测、命令注入探测和可疑登录活动。
- 上传 `.pcap` 或 `.pcapng` 抓包；程序根据文件头自动识别实际格式，不依赖扩展名。
- 本地解析 Ethernet、IPv4、TCP、UDP，检测 TCP 端口扫描、DNS 高频活动和可疑 HTTP 明文载荷。
- 对超过 32 MiB 的抓包只读取并分析开头 32 MiB，避免浏览器一次加载整个大文件；页面会明确显示“采样”。
- 展示协议计数、主机数量、风险分数、事件时间线，并导出 Markdown 报告。
- 连续出现的同类、同来源安全事件会自动折叠，避免大型日志产生过长页面；完整发现仍会保留在导出报告中。
- 可选 AI 研判，兼容 OpenAI、DeepSeek、通义千问、Kimi 和 OpenAI Chat Completions 兼容接口。只发送结构化命中结果，不发送原始日志。

### 本地运行

需要 Node.js 22.13 或更高版本：

```bash
npm install
npm run dev
```

打开终端显示的本地地址（通常为 `http://localhost:3000`），点击“上传访问日志”，选择日志或抓包文件即可。也可以点击“加载安全演示”体验日志检测。

生产构建与测试：

```bash
npm run build
npm test
```

### 可选 AI API

可以直接在页面底部展开“在页面中配置 API”，填写 API Key、Base URL 和模型名称。页面配置只保存在当前浏览器页面的内存中，刷新后清除。也可以复制 `.env.example` 为 `.env`，填写所需供应商的 `*_API_KEY`、`*_BASE_URL` 和 `*_MODEL` 作为服务端默认配置。`.env` 已被 Git 忽略，请勿提交 API Key。未配置 API 时，本地规则分析和抓包分析仍可直接使用。

### 检测边界

抓包分析目前支持 Ethernet 上的 IPv4/TCP/UDP。加密的 HTTPS 内容不能直接匹配 HTTP 载荷规则。采样模式只代表文件开头 32 MiB 的结果，不能证明整个抓包没有异常。

## English

LogSleuth is a local-first security investigation tool for Apache/Nginx access logs and PCAP/PCAPNG captures. Raw input stays in the browser unless the optional AI review is explicitly used.

### Features

- Detect common web attack indicators in access logs.
- Auto-detect PCAP and PCAPNG by file signature, regardless of the filename extension.
- Parse Ethernet/IPv4/TCP/UDP and flag possible port scans, high-volume DNS activity, and suspicious plaintext HTTP payloads.
- Analyze only the first 32 MiB of large captures to keep browser memory use bounded, with a visible sampling notice.
- Show protocol baselines, risk findings, timelines, and exportable Markdown reports.
- Optional OpenAI-compatible AI review using structured findings only.

### Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

Open the printed local URL and upload a `.log`, `.txt`, `.pcap`, or `.pcapng` file. Run `npm run build` and `npm test` for verification.

## License

MIT. See [LICENSE](LICENSE).
