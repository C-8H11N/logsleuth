import assert from "node:assert/strict";
import test from "node:test";
import { analyzeLog, decodeForDetection } from "../app/log-analyzer.ts";

test("malformed attack encodings do not abort log analysis",()=>{
  const log=[
    '172.16.12.1 - - [31/Oct/2017:15:11:30 +0800] "GET /uploads/%uff0e%uff0e/etc/passwd HTTP/1.1" 403 12 "-" "scanner"',
    '172.16.12.1 - - [31/Oct/2017:15:11:31 +0800] "GET /search?q=%C0%AE%ZZ<script HTTP/1.1" 200 12 "-" "scanner"',
  ].join("\n");
  const result=analyzeLog(log);
  assert.equal(result.parsed.length,2);
  assert.ok(result.findings.some((finding)=>finding.category==="Path traversal"));
  assert.ok(result.findings.some((finding)=>finding.category==="Cross-site scripting"));
  assert.doesNotThrow(()=>decodeForDetection("/%u2215/%C0%AE/%"));
});
