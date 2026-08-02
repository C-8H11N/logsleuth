export type Finding = { id:number; timestamp:string; ip:string; method:string; path:string; status:number; category:string; severity:"Critical"|"High"|"Medium"; evidence:string };
export type ParsedLog = { timestamp:string; ip:string; method:string; path:string; status:number; raw:string };

const RULES = [
  { category:"SQL injection", severity:"Critical" as const, pattern:/(?:union(?:\s+all)?\s+select|select.+from|\bor\s+['"]?1['"]?\s*=\s*['"]?1|sleep\s*\(|benchmark\s*\(|information_schema)/i },
  { category:"Cross-site scripting", severity:"High" as const, pattern:/(?:<script|%3cscript|onerror\s*=|onload\s*=|javascript:|alert\s*\()/i },
  { category:"Path traversal", severity:"High" as const, pattern:/(?:\.\.\/(?:\.\.\/)?|\.\.\\|%2e%2e%2f|\/etc\/passwd|win\.ini)/i },
  { category:"Sensitive-file probing", severity:"Medium" as const, pattern:/(?:\.env(?:\.|$)|\.git(?:\/|$)|id_rsa|wp-config\.php|\.bak(?:\?|$)|backup\.(?:zip|sql))/i },
  { category:"Command-injection probe", severity:"High" as const, pattern:/(?:;\s*(?:cat|whoami|id|curl|wget)\b|\|\s*(?:cat|whoami|id)\b|\$\{(?:IFS|PATH))/i },
];

export function parseLine(raw:string):ParsedLog|null {
  const match=raw.match(/^(?<ip>\S+)\s+\S+\s+\S+\s+\[(?<timestamp>[^\]]+)\]\s+"(?<method>[A-Z]+)\s+(?<path>\S+)(?:\s+[^"\s]+)?"\s+(?<status>\d{3})/);
  if(!match?.groups) return null;
  return {...match.groups,status:Number(match.groups.status),raw} as ParsedLog;
}

export function decodeForDetection(value:string) {
  const legacy=value.replace(/%u([0-9a-f]{4})/gi,(_,hex:string)=>String.fromCharCode(Number.parseInt(hex,16)));
  try { return `${value}\n${decodeURIComponent(legacy)}`; }
  catch { return `${value}\n${legacy.replace(/%([0-9a-f]{2})/gi,(_,hex:string)=>String.fromCharCode(Number.parseInt(hex,16)))}`; }
}

export function analyzeLog(text:string) {
  const parsed=text.split(/\r?\n/).filter(Boolean).map(parseLine).filter((item):item is ParsedLog=>item!==null);
  const findings:Finding[]=[];
  parsed.forEach((entry,index)=>{
    const detectionValue=decodeForDetection(entry.path);
    RULES.forEach((rule)=>{ if(rule.pattern.test(detectionValue)) findings.push({id:index*10+findings.length,timestamp:entry.timestamp,ip:entry.ip,method:entry.method,path:entry.path,status:entry.status,category:rule.category,severity:rule.severity,evidence:entry.raw}); });
  });
  const loginAttempts=new Map<string,ParsedLog[]>();
  parsed.filter((entry)=>/\/(?:login|auth|sign-in|wp-login)/i.test(entry.path)).forEach((entry)=>{const attempts=loginAttempts.get(entry.ip)??[];attempts.push(entry);loginAttempts.set(entry.ip,attempts);});
  loginAttempts.forEach((attempts,ip)=>{if(attempts.length>=3){const last=attempts[attempts.length-1];findings.push({id:9000+findings.length,timestamp:last.timestamp,ip,method:last.method,path:last.path,status:last.status,category:"Suspected credential attack",severity:"High",evidence:`${attempts.length} login requests from ${ip}; final response status ${last.status}.`});}});
  return {parsed,findings:findings.sort((a,b)=>a.timestamp.localeCompare(b.timestamp))};
}
