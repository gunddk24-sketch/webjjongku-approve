// Shared, dependency-free wire protocol. No execution or credentials in this module.
export const REPO='gunddk24-sketch/webjjongku-control';
export const MAX_BYTES=4*1024*1024, CHUNK_BYTES=24*1024;
export const APPROVE='WEBJJONGKU_REMOTE_APPROVE_V1\n', CHUNK='WEBJJONGKU_REMOTE_CHUNK_V1\n';
export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const need=(ok,message)=>{if(!ok)throw new Error(message);};
export function proposalShape(p,now=Date.now()){
  need(p&&Object.keys(p).sort().join(',')==='contract,created_utc,expires_utc,proposal_id,task,validation_config_sha256','Invalid proposal fields');
  need(p.contract==='webjjongku-remote-proposal-v1'&&UUID.test(p.proposal_id),'Invalid proposal identity');
  const created=Date.parse(p.created_utc),expires=Date.parse(p.expires_utc);
  need(Number.isFinite(created)&&Number.isFinite(expires)&&created<=now+60000&&expires>now&&expires>created&&expires-created<=7200000,'Proposal expired or invalid lifetime (maximum 2 hours)');
  need(/^[0-9a-f]{64}$/.test(p.validation_config_sha256),'Validation fingerprint required');
  need(p.task?.contract==='webjjongku-task-v2','Deterministic V2 task required');
  return p;
}
export async function digest(bytes){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');}
export async function encodeProposal(bytes){
  need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=MAX_BYTES,'Proposal exceeds 4 MiB transport limit');
  const proposal=proposalShape(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
  const chunks=[];
  for(let i=0;i<bytes.length;i+=CHUNK_BYTES){const part=bytes.slice(i,i+CHUNK_BYTES);chunks.push({index:chunks.length,bytes:part.length,sha256:await digest(part),data:btoa(String.fromCharCode(...part))});}
  return {proposal,chunks,bytes:bytes.length,sha256:await digest(bytes)};
}
// Called only by the explicit approval button. Failed/uncertain POSTs are never retried.
export async function uploadProposal(encoded,api,{pause=()=>new Promise(r=>setTimeout(r,1100)),progress=()=>{}}={}){
  proposalShape(encoded.proposal);
  const id=encoded.proposal.proposal_id;
  const issue=await api('/issues',{title:'WEBJJONGKU PROPOSAL '+id,body:'Untrusted staging only. No execution until a final owner approval comment.\nProposal: '+id});
  need(Number.isSafeInteger(issue.number)&&issue.number>0,'Invalid staging issue response');
  const chunks=[];
  for(const chunk of encoded.chunks){
    await pause();
    const comment=await api(`/issues/${issue.number}/comments`,{body:CHUNK+JSON.stringify({proposal_id:id,index:chunk.index,data:chunk.data})});
    need(Number.isSafeInteger(comment.id)&&comment.id>0,'Invalid chunk response');
    chunks.push({id:comment.id,index:chunk.index,bytes:chunk.bytes,sha256:chunk.sha256});progress(chunks.length,encoded.chunks.length);
  }
  await pause();
  const manifest={contract:'webjjongku-remote-approval-v1',proposal_id:id,bytes:encoded.bytes,sha256:encoded.sha256,chunks};
  await api(`/issues/${issue.number}/comments`,{body:APPROVE+JSON.stringify(manifest)});
  return {issue_number:issue.number,approval_id:id};
}
