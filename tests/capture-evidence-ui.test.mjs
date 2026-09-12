import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";
import { parseCapture } from "../app/pcapng.ts";
import { pcap, request, response } from "./capture-fixtures.mjs";

// Compile this local, pure React component; no browser or network required.
const source = readFileSync(new URL("../app/capture-evidence.tsx", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
const componentModule = { exports: {} };
new Function("require", "module", "exports", compiled)(createRequire(import.meta.url), componentModule, componentModule.exports);
const { CaptureEvidencePanel } = componentModule.exports;
const result = parseCapture(pcap([{ text: request }, { text: response, reverse: true }]).buffer);

test("packet evidence panel renders both languages with native accessible disclosure", () => {
  const zh = renderToStaticMarkup(createElement(CaptureEvidencePanel, { result, language: "zh" }));
  const en = renderToStaticMarkup(createElement(CaptureEvidencePanel, { result, language: "en" }));
  assert.match(zh, /HTTP 请求与响应证据/);
  assert.match(zh, /推断关联 H#2/);
  assert.match(en, /Inferred pair H#2/);
  assert.match(en, /<details/);
  assert.match(en, /<summary/);
  assert.doesNotMatch(en, /[\u4e00-\u9fff]/);
  assert.doesNotMatch(zh + en, /synthetic-secret|synthetic-cookie|synthetic-token/);
});
test("packet evidence panel escapes untrusted paths and states empty coverage", () => {
  const hostile = { ...result, httpObservations: [{ ...result.httpObservations[0], path: "<img src=x onerror=alert(1)>" }] };
  const html = renderToStaticMarkup(createElement(CaptureEvidencePanel, { result: hostile, language: "en" }));
  assert.doesNotMatch(html, /<img/);
  const empty = renderToStaticMarkup(createElement(CaptureEvidencePanel, { result: { ...result, httpObservations: [] }, language: "en" }));
  assert.match(empty, /does not establish safety/);
});
