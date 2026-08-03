import type { Finding } from "./log-analyzer";

export type AttackSession = { id:number; ip:string; startedAt:string; endedAt:string; severity:Finding["severity"]; stages:string[]; evidenceIds:number[]; count:number; confidence:number };

const months:Record<string,number>={Jan:0,Feb:1,Mar:2,Apr:3,May:4,Jun:5,Jul:6,Aug:7,Sep:8,Oct:9,Nov:10,Dec:11};
function timestamp(value:string){const m=value.match(/^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})$/);if(!m)return 0;const utc=Date.UTC(+m[3],months[m[2]],+m[1],+m[4],+m[5],+m[6]);const offset=(+m[8]*60 + +m[9])*60000;return utc+(m[7]==="+"?-offset:offset);}
function stage(category:string){if(category==="Sensitive-file probing"||category==="Path traversal")return "Reconnaissance";if(category==="Suspected credential attack")return "Credential Access";if(category==="Web shell probing")return "Persistence";if(["SQL injection","Cross-site scripting","Command-injection probe","Log4Shell/JNDI probe","SSRF probe","Suspicious HTTP payload","Possible TCP port scan"].includes(category))return "Exploitation";return "Suspicious Activity";}
const rank={Critical:3,High:2,Medium:1};

export function correlateSessions(findings:Finding[]):AttackSession[]{
  const sources=new Map<string,Finding[]>();findings.forEach((finding)=>sources.set(finding.ip,[...(sources.get(finding.ip)??[]),finding]));
  const sessions:AttackSession[]=[];
  sources.forEach((items,ip)=>{
    items.sort((a,b)=>timestamp(a.timestamp)-timestamp(b.timestamp));let current:Finding[]=[];
    const flush=()=>{if(!current.length)return;const stages=[...new Set(current.map((finding)=>stage(finding.category)))];const severity=current.reduce<Finding["severity"]>((highest,finding)=>rank[finding.severity]>rank[highest]?finding.severity:highest,"Medium");const successful=current.some((finding)=>finding.status>=200&&finding.status<400);const confidence=Math.min(95,30+Math.min(current.length*3,30)+Math.min(stages.length*8,24)+(successful?8:0));sessions.push({id:0,ip,startedAt:current[0].timestamp,endedAt:current.at(-1)!.timestamp,severity,stages,evidenceIds:current.map((finding)=>finding.id),count:current.length,confidence});current=[];};
    items.forEach((finding)=>{const previous=current.at(-1);if(previous){const gap=timestamp(finding.timestamp)-timestamp(previous.timestamp);if(gap>30*60*1000&&timestamp(finding.timestamp)&&timestamp(previous.timestamp))flush();}current.push(finding);});flush();
  });
  return sessions.sort((a,b)=>b.confidence-a.confidence||timestamp(a.startedAt)-timestamp(b.startedAt)).map((session,index)=>({...session,id:index+1}));
}
