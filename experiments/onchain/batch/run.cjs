#!/usr/bin/env node
// Real receipts from native multi-file verification, under an explicit simulator limit.
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process'),crypto=require('node:crypto');
const modules=cp.execFileSync('npm',['root','-g'],{encoding:'utf8',env:{...process.env,npm_config_cache:'/private/tmp/multiaudit-npm-cache'}}).trim();
const ganache=require(path.join(modules,'ganache'));
const web3Package=require(path.join(modules,'web3'));const Web3=web3Package.Web3||web3Package;
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const readWord=(b,o)=>Number(BigInt('0x'+b.subarray(o,o+32).toString('hex')));
const toWord=x=>Buffer.from(x.toString(16).padStart(64,'0'),'hex');
async function main(){
 const [input,compiled,outArg,...flags]=process.argv.slice(2);if(!input||!compiled||!outArg)throw Error('usage: run.cjs fixtures-or-directory contract.json output [--scheme NAME] [--m COUNT] [--negative]');
 const schemeIndex=flags.indexOf('--scheme');const selected=schemeIndex>=0?flags[schemeIndex+1]:null;
 const fileCountIndex=flags.indexOf('--m');const fileCount=fileCountIndex>=0?Number(flags[fileCountIndex+1]):null;
 const negative=flags.includes('--negative');const out=path.resolve(outArg);fs.mkdirSync(out,{recursive:true});
 let files=fs.statSync(input).isDirectory()?JSON.parse(fs.readFileSync(path.join(input,'index.json'))).map(p=>path.join(input,p)):[input];
 if(selected)files=files.filter(p=>path.basename(p).startsWith(selected+'-'));
 if(fileCount!==null)files=files.filter(p=>path.basename(p).endsWith('-m'+fileCount+'.json'));
 if(files.length===0)throw Error('empty selected fixture grid');
 const blockGasLimit=5000000000,transactionGasLimit=4500000000;
 const provider=ganache.provider({chain:{hardfork:'shanghai',chainId:20261124},miner:{blockGasLimit},wallet:{totalAccounts:2,defaultBalance:100000},logging:{quiet:true}});
 const rows=[],checks=[],fixtures=[];
 const sourceFiles=['experiments/onchain/batch/AuditBatchVerifier.sol','experiments/onchain/batch/fixtures.go','experiments/onchain/batch/run.cjs',
  ...['multiaudit','xutifs26','yutc25','benchcore'].flatMap(dir=>fs.readdirSync('schemes/'+dir).filter(p=>p.endsWith('.go')&&!p.endsWith('_test.go')).map(p=>'schemes/'+dir+'/'+p)),'go.mod','go.sum'];
 const meta={measurement_source:'local_evm_batch_transaction_receipts',complete:false,B_MB:null,n:0,s:0,c:0,m_scan:[],audits_per_scheme_per_m:0,
  node_arch:process.arch,node_version:process.version,
  evm:'Ganache '+require(path.join(modules,'ganache/package.json')).version,hardfork:'shanghai',
  solidity:cp.execFileSync('solc',['--version'],{encoding:'utf8'}).trim(),compiler_options:['--optimize','--via-ir','--evm-version','shanghai'],
  block_gas_limit:blockGasLimit,transaction_gas_limit:transactionGasLimit,limit_scope:'raised simulator limits for cost measurement; not a claim of target-chain single-transaction feasibility',
  execution_gas:'receipt minus exact EIP-2028 intrinsic gas',registration_and_deployment:'excluded; current ordered roots/IDs and SRS fixed at deployment; owner registers the exact challenge digest before each transaction',
  native_batch_semantics:'Xu shared-point global opening check; Yu m independent native file checks inside one transaction; MultiAudit one distinct-point two-witness check',
  challenge_encoding:'32-byte indices; Xu one shared expanded challenge, Yu independent per-file expanded challenges, MultiAudit shared indices and per-file coefficients/points',
  optimization_version:'memory_reuse_v2_unmasked',
  common_optimizations:'all schemes use shared in-place ECADD/ECMUL, reusable point buffers, temporary challenge-hash scratch and SHA-256 helpers; Xu moves G2 multiplication to G1; Yu coefficient-combines its shifted SRS relation; MultiAudit uses reusable canonical-transcript scratch and CMM arrays',
  native_fixtures_verified:true,public_verifier_account:true,negative_checks:checks,fixtures,
  source_sha256:Object.fromEntries(sourceFiles.map(p=>[p,digest(fs.readFileSync(p))]))};
 const save=()=>{fs.writeFileSync(path.join(out,'records.json'),JSON.stringify(rows,null,2)+'\n');fs.writeFileSync(path.join(out,'metadata.json'),JSON.stringify(meta,null,2)+'\n');};
 save();
 try{
  const web3=new Web3(provider);const [owner,outsider]=await web3.eth.getAccounts();
  const artifact=Object.values(JSON.parse(fs.readFileSync(compiled)).contracts)[0];const abi=typeof artifact.abi==='string'?JSON.parse(artifact.abi):artifact.abi;
  meta.bytecode_sha256=digest(Buffer.from(artifact['bin-runtime'],'hex'));
  for(const file of files){
   const fixtureBytes=fs.readFileSync(file),f=JSON.parse(fixtureBytes);if(!f.native_verified)throw Error('unverified native fixture');
   const mode={XuTIFS26:0,YuTC25:1,MultiAudit:2}[f.scheme];
   console.log('Deploying',f.scheme,'m='+f.m,'n='+f.n,'c='+f.c);
   const contract=await new web3.eth.Contract(abi).deploy({data:'0x'+artifact.bin,arguments:[mode,f.roots,f.ids,f.n,f.s,f.c,'0x'+(f.srs||[]).map(x=>x.slice(2)).join(''),f.g2,f.tau_g2,f.prefix]}).send({from:owner,gas:50000000});
   fixtures.push({scheme:f.scheme,m:f.m,n:f.n,s:f.s,c:f.c,audits:f.audits.length,sha256:digest(fixtureBytes),contract:contract.options.address});
   meta.n=f.n;meta.s=f.s;meta.c=f.c;meta.B_MB=f.n===3907&&f.s===80?10:f.n*f.s*32/1000000;meta.audits_per_scheme_per_m=f.audits.length;if(!meta.m_scan.includes(f.m))meta.m_scan.push(f.m);
   const reject=async(label,ch,pr)=>{
    let failed=false;try{failed=(await contract.methods.verify(ch,pr).call({from:outsider,gas:transactionGasLimit}))!==true;}catch(e){failed=true;}
    if(!failed)throw Error(f.scheme+' m='+f.m+' accepted '+label);
    checks.push({scheme:f.scheme,m:f.m,case:label,rejected:true});
   };
   const mutate=(hex,off)=>{const b=Buffer.from(hex.slice(2),'hex');b[off]^=1;return '0x'+b.toString('hex');};
   for(let repeat=0;repeat<f.audits.length;++repeat){
    const a=f.audits[repeat];await contract.methods.setChallenge(web3.utils.keccak256(a.challenge)).send({from:owner,gas:100000});
    const data=contract.methods.verify(a.challenge,a.proof).encodeABI();
    const receipt=await web3.eth.sendTransaction({from:outsider,to:contract.options.address,data,gas:transactionGasLimit});
    if(!receipt.status)throw Error('valid batch transaction reverted');
    const raw=Buffer.from(data.slice(2),'hex');let zero=0;for(const b of raw)if(b===0)++zero;const nonzero=raw.length-zero;
    const intrinsic=21000+4*zero+16*nonzero,total=Number(receipt.gasUsed),execution=total-intrinsic;
    rows.push({scheme:f.scheme,m:f.m,repeat:repeat+1,n:f.n,s:f.s,c:f.c,challenge_bytes:(a.challenge.length-2)/2,response_bytes:(a.proof.length-2)/2,
     calldata_bytes:raw.length,zero_bytes:zero,nonzero_bytes:nonzero,intrinsic_gas:intrinsic,execution_gas:execution,receipt_gas:total,
     eip7623_projected_gas:21000+Math.max(total-21000,10*(zero+4*nonzero)),accepted:true,transaction_hash:receipt.transactionHash,block_number:Number(receipt.blockNumber),calldata_sha256:digest(raw)});
    console.log(f.scheme,'m='+f.m,'audit='+String(repeat+1),'gas='+total,'bytes='+raw.length);save();
    if(!negative&&repeat===0){
     await reject('changed issued challenge',mutate(a.challenge,0),a.proof);
     await reject('truncated proof header',a.challenge,'0x00');
     await reject('changed first sampled tag',a.challenge,mutate(a.proof,mode===2?192:(mode===1?96+32*(f.s-1):96)));
     save();
    }
    if(negative&&repeat===0){
     const pr=Buffer.from(a.proof.slice(2),'hex');const head=mode===1?96+32*(f.s-1):96;const fileSize=head+f.c*(64+32*Math.ceil(Math.log2(f.n)));
     let offsets=[];if(mode===2){let off=128;for(let i=0;i<f.m;++i){offsets.push(off);off+=64+64*f.c+32*readWord(pr,off+32);}}else offsets=Array.from({length:f.m},(_,i)=>i*fileSize);
     const valueOffset=mode===2?128:0,tagOffset=mode===2?192:head;
     await reject('changed issued challenge',mutate(a.challenge,0),a.proof);
     await reject('changed last authentication hash',a.challenge,mutate(a.proof,pr.length-1));
     await reject('changed first evaluation',a.challenge,mutate(a.proof,valueOffset+31));
     await reject('changed sampled tag',a.challenge,mutate(a.proof,tagOffset));
     await reject('truncated proof',a.challenge,a.proof.slice(0,-2));
     await reject('trailing proof byte',a.challenge,a.proof+'00');
     const noncanonical=Buffer.from(pr);toWord(21888242871839275222246405745257275088548364400416034343698204186575808495617n).copy(noncanonical,valueOffset);
     await reject('noncanonical evaluation',a.challenge,'0x'+noncanonical.toString('hex'));
     if(f.m>1){
      const swapped=mode===2?Buffer.concat([pr.subarray(0,128),pr.subarray(offsets[1],offsets[2]||pr.length),pr.subarray(offsets[0],offsets[1]),pr.subarray(offsets[2]||pr.length)]):Buffer.concat([pr.subarray(fileSize,2*fileSize),pr.subarray(0,fileSize),pr.subarray(2*fileSize)]);
      await reject('swapped file proof records',a.challenge,'0x'+swapped.toString('hex'));
     }
     if(mode===2){
      await reject('changed first witness',a.challenge,mutate(a.proof,0));await reject('changed second witness',a.challenge,mutate(a.proof,64));
      if(f.m>1){
       const b=Buffer.from(pr),order=21888242871839275222246405745257275088548364400416034343698204186575808495617n;
       const v0=BigInt('0x'+b.subarray(offsets[0],offsets[0]+32).toString('hex')),v1=BigInt('0x'+b.subarray(offsets[1],offsets[1]+32).toString('hex'));
       toWord((v0+1n)%order).copy(b,offsets[0]);toWord((v1+order-1n)%order).copy(b,offsets[1]);await reject('opposite per-file evaluation changes',a.challenge,'0x'+b.toString('hex'));
       const ch=Buffer.from(a.challenge.slice(2),'hex'),point=32+32*f.c;ch.copy(ch,point+32*(f.c+1),point,point+32);const bad='0x'+ch.toString('hex');
       await contract.methods.setChallenge(web3.utils.keccak256(bad)).send({from:owner,gas:100000});await reject('duplicate per-file points',bad,a.proof);
       await contract.methods.setChallenge(web3.utils.keccak256(a.challenge)).send({from:owner,gas:100000});
      }
     }
     let denied=false;try{await contract.methods.setChallenge(web3.utils.keccak256(a.challenge)).send({from:outsider,gas:100000});}catch(e){denied=true;}
     if(!denied)throw Error('unauthorized challenge update accepted');checks.push({scheme:f.scheme,m:f.m,case:'unauthorized challenge update',rejected:true});save();
    }
   }
  }
  meta.m_scan.sort((a,b)=>a-b);meta.complete=true;save();
 }finally{await provider.disconnect();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
