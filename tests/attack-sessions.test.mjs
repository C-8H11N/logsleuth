import assert from "node:assert/strict";
import test from "node:test";
import { correlateSessions } from "../app/attack-sessions.ts";

test("correlates findings by source and 30 minute window",()=>{
  const finding=(id,timestamp,category,severity="High")=>({id,timestamp,ip:"10.0.0.8",method:"GET",path:"/",status:404,category,severity,evidence:""});
  const sessions=correlateSessions([finding(1,"31/Oct/2017:15:00:00 +0800","Sensitive-file probing","Medium"),finding(2,"31/Oct/2017:15:05:00 +0800","SQL injection","Critical"),finding(3,"31/Oct/2017:16:00:00 +0800","Web shell probing")]);
  assert.equal(sessions.length,2);assert.equal(sessions[0].severity,"Critical");assert.deepEqual(sessions[0].stages,["Reconnaissance","Exploitation"]);
});
