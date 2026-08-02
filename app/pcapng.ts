export type PcapFinding = { id:number; timestamp:string; ip:string; method:string; path:string; status:number; category:string; severity:"Critical"|"High"|"Medium"; evidence:string };
export type PcapResult = { packets:number; findings:PcapFinding[]; stats:{ipv4:number;tcp:number;udp:number;dns:number;http:number;hosts:number} };
const ip=(v:DataView,o:number)=>`${v.getUint8(o)}.${v.getUint8(o+1)}.${v.getUint8(o+2)}.${v.getUint8(o+3)}`;

export function parsePcapng(buffer:ArrayBuffer):PcapResult {
  const v=new DataView(buffer); if(v.byteLength<28||v.getUint32(0,true)!==0x0a0d0d0a) throw new Error("不是有效的 PCAPNG 文件。");
  const little=v.getUint32(8,true)===0x1a2b3c4d, u=(o:number)=>v.getUint32(o,little), u16=(o:number)=>v.getUint16(o,little);
  const links:number[]=[],syn=new Map<string,Set<number>>(),dns=new Map<string,number>(),findings:PcapFinding[]=[],hosts=new Set<string>(); let packets=0,offset=0,ipv4=0,tcp=0,udp=0,http=0;
  const add=(category:string,severity:PcapFinding["severity"],source:string,detail:string)=>findings.push({id:findings.length+1,timestamp:"PCAPNG capture",ip:source,method:"NET",path:detail,status:0,category,severity,evidence:detail});
  while(offset+12<=v.byteLength){
    const type=u(offset),len=u(offset+4); if(len<12||offset+len>v.byteLength) break;
    if(type===1) links.push(u16(offset+8));
    if(type===6){
      const iface=u(offset+8),cap=u(offset+20),start=offset+28;
      if(links[iface]===1&&start+cap<=offset+len-4&&cap>=34){
        packets++; let l3=start+14,ether=v.getUint16(start+12,false);
        if(ether===0x8100&&cap>=38){ether=v.getUint16(start+16,false);l3+=4;}
        if(ether===0x0800){
          const ihl=(v.getUint8(l3)&15)*4,proto=v.getUint8(l3+9),src=ip(v,l3+12),dst=ip(v,l3+16),l4=l3+ihl;
          ipv4++; hosts.add(src); hosts.add(dst); if(proto===6) tcp++; if(proto===17) udp++;
          if((proto===6||proto===17)&&l4+4<=start+cap){
            const sport=v.getUint16(l4,false),dport=v.getUint16(l4+2,false);
            if(proto===6&&l4+14<start+cap&&(v.getUint8(l4+13)&2)&&!(v.getUint8(l4+13)&16)){const ports=syn.get(src)??new Set<number>();ports.add(dport);syn.set(src,ports);}
            if(sport===53||dport===53) dns.set(src,(dns.get(src)??0)+1);
            if(proto===6&&(sport===80||dport===80||sport===8080||dport===8080)){
              http++;
              const head=String.fromCharCode(...new Uint8Array(buffer.slice(Math.min(l4+20,start+cap),Math.min(l4+280,start+cap))));
              if(/union\s+select|<script|\.\.\//i.test(head)) add("Suspicious HTTP payload","High",src,`${src}:${sport} → ${dst}:${dport}`);
            }
          }
        }
      }
    }
    offset+=len;
  }
  syn.forEach((ports,source)=>{if(ports.size>=10)add("Possible TCP port scan","High",source,`SYN packets to ${ports.size} distinct destination ports`);});
  dns.forEach((count,source)=>{if(count>=30)add("High-volume DNS activity","Medium",source,`${count} DNS packets observed`);});
  return {packets,findings,stats:{ipv4,tcp,udp,dns:[...dns.values()].reduce((a,b)=>a+b,0),http,hosts:hosts.size}};
}
