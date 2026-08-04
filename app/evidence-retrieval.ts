import type { Finding } from "./log-analyzer";
import type { AttackSession } from "./attack-sessions";

export type ToolTrace={name:string;query:string;results:number};
export type RetrievalInfo={findings:number;sessions:number;tools:ToolTrace[]};
const evidencePattern=/\[?E#(\d+)\]?/gi,sessionPattern=/\[?S#(\d+)\]?/gi,ipPattern=/\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const refs=(pattern:RegExp,value:string)=>new Set([...value.matchAll(pattern)].map((match)=>Number(match[1])));

export function retrieveEvidence(question:string,findings:Finding[],sessions:AttackSession[]){
  const lower=question.toLowerCase(),evidenceIds=refs(evidencePattern,question),sessionIds=refs(sessionPattern,question),ips=new Set(question.match(ipPattern)??[]),tokens=lower.match(/[a-z0-9_./%-]{3,}/g)??[],tools:ToolTrace[]=[];
  const scored=findings.flatMap((finding)=>{let score=evidenceIds.has(finding.id)?1000:0;if(ips.has(finding.ip))score+=300;const text=`${finding.category} ${finding.ip} ${finding.method} ${finding.path} ${finding.severity}`.toLowerCase();tokens.forEach((token)=>{if(text.includes(token))score+=12;});if((lower.includes("sql")||lower.includes("注入"))&&finding.category==="SQL injection")score+=150;if((lower.includes("成功")||lower.includes("status"))&&finding.status>=200&&finding.status<400)score+=80;return score?[{finding,score}]:[];});
  if(evidenceIds.size)tools.push({name:"get_evidence",query:[...evidenceIds].join(","),results:evidenceIds.size});if(ips.size)tools.push({name:"search_findings",query:[...ips].join(","),results:scored.length});
  let selectedSessions=sessions.filter((session)=>sessionIds.has(session.id)||ips.has(session.ip)||/会话|session|时间线|timeline/i.test(question));if(sessionIds.size)tools.push({name:"get_session",query:[...sessionIds].join(","),results:selectedSessions.length});if(/会话|session|时间线|timeline/i.test(question))tools.push({name:"summarize_timeline",query:question,results:selectedSessions.length});
  const candidates=scored.length?scored:findings.map((finding)=>({finding,score:finding.severity==="Critical"?30:finding.severity==="High"?20:10}));if(!scored.length)tools.push({name:"search_findings",query:"highest severity fallback",results:findings.length});
  const seen=new Set<number>(),selected:Finding[]=[];candidates.sort((a,b)=>b.score-a.score).forEach(({finding})=>{if(!seen.has(finding.id)&&selected.length<30){seen.add(finding.id);selected.push(finding);}});if(!selectedSessions.length)selectedSessions=sessions.slice(0,8);
  return {findings:selected,sessions:selectedSessions.slice(0,12),info:{findings:selected.length,sessions:Math.min(selectedSessions.length,12),tools} satisfies RetrievalInfo};
}

export function validateCitations(analysis:string,findings:Finding[],sessions:AttackSession[]){const validEvidence=new Set(findings.map((item)=>item.id)),validSessions=new Set(sessions.map((item)=>item.id)),invalid=new Set<string>();for(const match of analysis.matchAll(evidencePattern)){const id=Number(match[1]);if(!validEvidence.has(id))invalid.add(`[E#${id}]`);}for(const match of analysis.matchAll(sessionPattern)){const id=Number(match[1]);if(!validSessions.has(id))invalid.add(`[S#${id}]`);}return {citationsValid:invalid.size===0,invalidCitations:[...invalid]};}
