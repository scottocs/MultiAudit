#!/usr/bin/env node
// Complete signed transaction execution in Geth's offline Shanghai transition tool.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
const modules=cp.execFileSync('npm',['root','-g'],{encoding:'utf8',env:{...process.env,npm_config_cache:'/private/tmp/multiaudit-npm-cache'}}).trim();
const pkg=require(path.join(modules,'web3')),Web3=pkg.Web3||pkg;
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const hex=n=>'0x'+BigInt(n).toString(16);
async function main(){
 const [input,compiled,output,...flags]=process.argv.slice(2),key=flags.indexOf('--evm'),selected=flags.indexOf('--scheme');
 if(!input||!compiled||!output||key<0)throw Error('usage: run_transition.cjs fixtures contract.json output --evm EVM [--scheme NAME]');
 const evm=path.resolve(flags[key+1]),out=path.resolve(output);fs.mkdirSync(out,{recursive:true});
 const web3=new Web3(),artifact=Object.values(JSON.parse(fs.readFileSync(compiled)).contracts)[0],abi=typeof artifact.abi==='string'?JSON.parse(artifact.abi):artifact.abi;
 const template=new web3.eth.Contract(abi);
 // Public deterministic test keys, never production accounts.
 const ownerKey='0x'+'1'.padStart(64,'0'),verifierKey='0x'+'2'.padStart(64,'0');
 const owner=web3.eth.accounts.privateKeyToAccount(ownerKey).address,verifier=web3.eth.accounts.privateKeyToAccount(verifierKey).address;
 const address='0x'+web3.utils.keccak256('0xd694'+owner.slice(2)+'80').slice(-40);
 let files=fs.statSync(input).isDirectory()?JSON.parse(fs.readFileSync(path.join(input,'index.json'))).map(f=>path.join(input,f)):[input];
 if(selected>=0)files=files.filter(f=>path.basename(f).startsWith(flags[selected+1]+'-'));
 const smokeIndex=flags.indexOf('--smoke-metadata');
 const smokeFile=smokeIndex>=0?flags[smokeIndex+1]:'experiments/results/paper/onchain/smoke/metadata.json';
 const base=JSON.parse(fs.readFileSync(smokeFile));
 const meta={...base,complete:false,evm:cp.execFileSync(evm,['--version'],{encoding:'utf8'}).trim(),evm_backend:'Geth offline signed-transaction state transition',
  engine_binary_sha256:sha(fs.readFileSync(evm)),engine_arguments:['t8n','--state.fork','Shanghai','--state.chainid','20261124','--state.reward','-1'],transaction_gas_limit:1000000000,negative_transaction_gas_limit:400000000,
  block_context:'one independent Shanghai block per fixture; constructor and owner challenge registrations execute before verification; their gas is excluded from plotted rows',
  node_arch:process.arch,node_version:process.version,negative_checks:[],fixtures:[],m_scan:[],
  source_sha256:{...base.source_sha256,'experiments/onchain/batch/run_transition.cjs':sha(fs.readFileSync('experiments/onchain/batch/run_transition.cjs'))}};
 if(meta.bytecode_sha256!==sha(Buffer.from(artifact['bin-runtime'],'hex')))throw Error('compiled artifact differs from smoke-checked verifier');
 const work=fs.mkdtempSync('/private/tmp/multiaudit-t8n-');meta.temporary_input_directory=work;
 const rows=[];const save=()=>{fs.writeFileSync(path.join(out,'records.json'),JSON.stringify(rows,null,2)+'\n');fs.writeFileSync(path.join(out,'metadata.json'),JSON.stringify(meta,null,2)+'\n');};save();
 for(const file of files){
  const fixtureBytes=fs.readFileSync(file),f=JSON.parse(fixtureBytes);if(!f.native_verified)throw Error('unverified fixture');
  const dir=path.join(work,f.scheme+'-m'+f.m);fs.mkdirSync(dir,{recursive:true});
  const archive=path.join(out,'transitions',f.scheme+'-m'+f.m);fs.mkdirSync(archive,{recursive:true});
  const deploy=template.deploy({data:'0x'+artifact.bin,arguments:[{XuTIFS26:0,YuTC25:1,MultiAudit:2}[f.scheme],f.roots,f.ids,f.n,f.s,f.c,'0x'+(f.srs||[]).map(x=>x.slice(2)).join(''),f.g2,f.tau_g2,f.prefix]}).encodeABI();
  let ownerNonce=0,verifierNonce=0;
  const tx=(data,to,gas,isOwner)=>({type:'0x0',chainId:hex(20261124),nonce:hex(isOwner?ownerNonce++:verifierNonce++),gasPrice:hex(1000000000),gas:hex(gas),to,value:'0x0',input:data,v:'0x0',r:'0x0',s:'0x0',secretKey:isOwner?ownerKey:verifierKey});
  const transactions=[tx(deploy,null,50000000,true)],calls=[];
  for(const a of f.audits){
   transactions.push(tx(template.methods.setChallenge(web3.utils.keccak256(a.challenge)).encodeABI(),address,100000,true));
   const data=template.methods.verify(a.challenge,a.proof).encodeABI();calls.push({index:transactions.length,data,a});transactions.push(tx(data,address,1000000000,false));
  }
  const a=f.audits[0],mutate=(value,offset)=>{const b=Buffer.from(value.slice(2),'hex');b[offset]^=1;return '0x'+b.toString('hex');};
  transactions.push(tx(template.methods.setChallenge(web3.utils.keccak256(a.challenge)).encodeABI(),address,100000,true));
  const tagOffset=f.scheme==='MultiAudit'?192:(f.scheme==='YuTC25'?96+32*(f.s-1):96);
  const negatives=[['changed issued challenge',mutate(a.challenge,0),a.proof],['truncated proof header',a.challenge,'0x00'],['changed first sampled tag',a.challenge,mutate(a.proof,tagOffset)]];
  const negativeStart=transactions.length;
  for(const [,ch,pr] of negatives)transactions.push(tx(template.methods.verify(ch,pr).encodeABI(),address,400000000,false));
  const alloc={[owner]:{balance:hex(100000n*10n**18n)},[verifier]:{balance:hex(100000n*10n**18n)}};
  const env={currentCoinbase:'0x'+'00'.repeat(20),currentGasLimit:hex(5000000000),currentNumber:'0x1',currentTimestamp:'0x1',currentRandom:'0x'+'00'.repeat(32),currentDifficulty:'0x0',currentBaseFee:hex(1000000000),withdrawals:[]};
  for(const [name,data] of [['alloc',alloc],['env',env],['txs',transactions]])fs.writeFileSync(path.join(dir,name+'.json'),JSON.stringify(data));
  const args=['t8n','--input.alloc',path.join(dir,'alloc.json'),'--input.env',path.join(dir,'env.json'),'--input.txs',path.join(dir,'txs.json'),'--output.basedir',dir,'--output.alloc','post-alloc.json','--output.result','result.json','--output.body','txs.rlp','--state.fork','Shanghai','--state.chainid','20261124','--state.reward','-1'];
  console.log('Executing',f.scheme,'m='+f.m,'audits='+f.audits.length);
  await new Promise((resolve,reject)=>{const log=fs.openSync(path.join(dir,'engine.log'),'w'),child=cp.spawn(evm,args,{stdio:['ignore',log,log]});child.on('error',reject);child.on('exit',code=>{fs.closeSync(log);code===0?resolve():reject(Error('t8n exited '+code+'; see '+dir));});});
  for(const name of ['result.json','post-alloc.json','env.json','alloc.json','engine.log'])fs.copyFileSync(path.join(dir,name),path.join(archive,name));
  const result=JSON.parse(fs.readFileSync(path.join(dir,'result.json')));if(result.rejected?.length)throw Error('transaction rejected before EVM execution: '+JSON.stringify(result.rejected));
  if(result.receipts.length!==transactions.length)throw Error('receipt count mismatch');
  for(let i=0;i<negativeStart;++i)if(Number(BigInt(result.receipts[i].status))!==1)throw Error('valid transition reverted at '+i);
  if(result.receipts[0].contractAddress.toLowerCase()!==address.toLowerCase())throw Error('CREATE address mismatch');
  for(let repeat=0;repeat<calls.length;++repeat){
   const {index,data,a}=calls[repeat],receipt=result.receipts[index],raw=Buffer.from(data.slice(2),'hex');let zero=0;for(const byte of raw)if(byte===0)++zero;
   const nonzero=raw.length-zero,intrinsic=21000+4*zero+16*nonzero,total=Number(BigInt(receipt.gasUsed));
   rows.push({scheme:f.scheme,m:f.m,repeat:repeat+1,n:f.n,s:f.s,c:f.c,challenge_bytes:(a.challenge.length-2)/2,response_bytes:(a.proof.length-2)/2,calldata_bytes:raw.length,zero_bytes:zero,nonzero_bytes:nonzero,intrinsic_gas:intrinsic,execution_gas:total-intrinsic,receipt_gas:total,eip7623_projected_gas:21000+Math.max(total-21000,10*(zero+4*nonzero)),accepted:true,transaction_hash:receipt.transactionHash,block_number:1,calldata_sha256:sha(raw)});
   console.log(f.scheme,'m='+f.m,'audit='+(repeat+1),'gas='+total);
  }
  for(let i=0;i<negatives.length;++i){if(Number(BigInt(result.receipts[negativeStart+i].status))!==0)throw Error('invalid verification accepted');meta.negative_checks.push({scheme:f.scheme,m:f.m,case:negatives[i][0],rejected:true,transaction_hash:result.receipts[negativeStart+i].transactionHash});}
  meta.n=f.n;meta.s=f.s;meta.c=f.c;meta.B_MB=f.n===3907&&f.s===80?10:f.n*f.s*32/1000000;meta.audits_per_scheme_per_m=f.audits.length;
  if(!meta.m_scan.includes(f.m))meta.m_scan.push(f.m);
  meta.fixtures.push({scheme:f.scheme,m:f.m,n:f.n,s:f.s,c:f.c,audits:f.audits.length,sha256:sha(fixtureBytes),contract:address,transition_result_sha256:sha(fs.readFileSync(path.join(dir,'result.json'))),signed_transaction_body_sha256:sha(fs.readFileSync(path.join(dir,'txs.rlp')))});save();
 }
 meta.m_scan.sort((a,b)=>a-b);meta.complete=true;save();
}
main().catch(e=>{console.error(e);process.exitCode=1;});
