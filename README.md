# LogSleuth

**Local-first web log investigation workspace.** Upload an Apache or Nginx common-log file and turn it into an analyst-verifiable incident timeline—without sending the log to an external service.

## What it does

- Parses common-log-format web-server requests in the browser.
- Detects high-signal SQL injection, XSS, path traversal, sensitive-file probing, command-injection probes, and concentrated login attempts.
- Shows a severity-ranked timeline, suspicious source-IP concentration, and a deterministic risk score.
- Exports a compact Markdown investigation report.
- Includes a safe synthetic demo log; no active scanning, exploitation, or network requests are performed.

## Run locally

Requires Node.js 22.13 or later.

```bash
npm install
npm run dev
```

Open the local address shown by the development server. To create a production build:

```bash
npm run build
npm test
```

## Privacy and scope

Log parsing and detection happen entirely in the client browser. The application has no API key, telemetry, persistence layer, or external target interaction. Treat rule matches as investigation leads and verify them against the preserved request context.

## Project structure

```text
app/page.tsx       Browser-side parser, rule engine, and investigation UI
app/globals.css    Responsive dashboard styling
tests/             Rendered-page smoke test
```

## License

MIT. See [LICENSE](LICENSE).
