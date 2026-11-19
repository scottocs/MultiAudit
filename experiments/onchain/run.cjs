#!/usr/bin/env node
// Execute full verification transactions on an isolated local EVM.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const crypto = require('node:crypto');
const globalModules = cp.execFileSync('npm', ['root', '-g'], {encoding:'utf8',env:{...process.env,npm_config_cache:'/private/tmp/multiaudit-npm-cache'}}).trim();
const ganache = require(path.join(globalModules,'ganache'));
const Web3 = require(path.join(globalModules,'web3'));

async function main() {
  const input = process.argv[2] || '/private/tmp/multiaudit-onchain-fixtures.json';
  const compiled = process.argv[3] || '/private/tmp/multiaudit-onchain-contract.json';
  const out = path.resolve(process.argv[4] || 'experiments/results/paper/onchain');
  fs.mkdirSync(out,{recursive:true});
  const provider = ganache.provider({chain:{hardfork:'shanghai',chainId:20261119},
    miner:{blockGasLimit:100000000},wallet:{totalAccounts:2,defaultBalance:1000},logging:{quiet:true}});
  try {
    const web3 = new Web3(provider);
    const [owner,outsider] = await web3.eth.getAccounts();
    const artifact = Object.values(JSON.parse(fs.readFileSync(compiled)).contracts)[0];
    const abi = typeof artifact.abi === 'string' ? JSON.parse(artifact.abi) : artifact.abi;
    const fixtures = JSON.parse(fs.readFileSync(input));
    const rows = []; const checks = [];
    const columns = ['scheme','repeat','challenge_bytes','response_bytes','calldata_bytes',
      'zero_bytes','nonzero_bytes','intrinsic_gas','execution_gas','receipt_gas',
      'eip7623_projected_gas','accepted','calldata_sha256'];
    const mutate = (value,offset) => {const b=Buffer.from(value.slice(2),'hex');b[offset]^=1;return '0x'+b.toString('hex');};
    for (const fixture of fixtures) {
      const mode={XuTIFS26:0,YuTC25:1,MultiAudit:2}[fixture.scheme];
      console.log('Deploying',fixture.scheme);
      const contract=await new web3.eth.Contract(abi).deploy({data:'0x'+artifact.bin,
        arguments:[mode,fixture.root,'0x'+(fixture.srs||[]).map(x=>x.slice(2)).join(''),fixture.g2||'0x',fixture.tau_g2||'0x',fixture.prefix||'0x']
      }).send({from:owner,gas:30000000});
      let rejected=0;
      const mustReject=async(label,ch,pr,from=owner)=>{
        let failed=false;
        try { const result=await contract.methods.verify(ch,pr).call({from,gas:90000000});failed=result!==true; }
        catch (_) {failed=true;}
        if (!failed) throw new Error(`${fixture.scheme}: accepted ${label}`);
        checks.push({scheme:fixture.scheme,case:label,rejected:true});++rejected;
      };
      for (let run=0;run<fixture.audits.length;++run) {
        const audit=fixture.audits[run];
        await contract.methods.setChallenge(web3.utils.keccak256(audit.challenge)).send({from:owner,gas:100000});
        // A party with no owner secrets can execute the same registered audit.
        const data=contract.methods.verify(audit.challenge,audit.proof).encodeABI();
        const receipt=await web3.eth.sendTransaction({from:outsider,to:contract.options.address,data,gas:90000000});
        if (!receipt.status) throw new Error('verification transaction reverted');
        const raw=Buffer.from(data.slice(2),'hex');
        const zero=[...raw].reduce((n,b)=>n+(b===0),0),nonzero=raw.length-zero;
        const intrinsic=21000+4*zero+16*nonzero;
        const execution=Number(receipt.gasUsed)-intrinsic;
        const projected=21000+Math.max(4*(zero+4*nonzero)+execution,10*(zero+4*nonzero));
        rows.push([fixture.scheme,run+1,(audit.challenge.length-2)/2,(audit.proof.length-2)/2,
          raw.length,zero,nonzero,intrinsic,execution,Number(receipt.gasUsed),projected,true,
          crypto.createHash('sha256').update(raw).digest('hex')]);
        if (run===0) {
          await mustReject('changed challenge',mutate(audit.challenge,0),audit.proof);
          await mustReject('changed authentication hash',audit.challenge,mutate(audit.proof,(audit.proof.length-2)/2-1));
          await mustReject('changed evaluation',audit.challenge,mutate(audit.proof,mode===2?159:31));
          await mustReject('truncated proof',audit.challenge,audit.proof.slice(0,-2));
          const tagStart=mode===2?352:(mode===1?96+79*32:96);
          await mustReject('changed tag',audit.challenge,mutate(audit.proof,tagStart));
          if (mode===2) {
            await mustReject('changed first witness',audit.challenge,mutate(audit.proof,0));
            await mustReject('changed second witness',audit.challenge,mutate(audit.proof,64));
            await mustReject('changed Schnorr response',audit.challenge,mutate(audit.proof,319));
          }
          let denied=false;
          try {await contract.methods.setChallenge(web3.utils.keccak256(audit.challenge)).send({from:outsider,gas:100000});}
          catch(_){denied=true;}
          if (!denied) throw new Error('unauthorized registry update');
          checks.push({scheme:fixture.scheme,case:'unauthorized challenge update',rejected:true});
        }
        console.log(fixture.scheme,run+1,'gas',receipt.gasUsed,'execution',execution,'bytes',raw.length);
      }
      console.log(fixture.scheme,`${rejected} malformed-input cases rejected`);
    }
    fs.writeFileSync(path.join(out,'gas.csv'),[columns.join(','),...rows.map(r=>r.join(','))].join('\n')+'\n');
    const sourceFiles=['experiments/onchain/AuditVerifier.sol','experiments/onchain/fixtures.go','experiments/onchain/run.cjs',
      'schemes/multiaudit/protocol.go','schemes/multiaudit/transcript.go','schemes/xutifs26/protocol.go','schemes/yutc25/protocol.go'];
    const meta={measurement_source:'local_evm_transaction_receipts',m:1,B_MB:10,n:3907,s:80,c:690,
      encoded_file_bytes:3907*80*32,audits_per_scheme:fixtures[0].audits.length,
      evm:'Ganache '+require(path.join(globalModules,'ganache/package.json')).version,hardfork:'shanghai',
      solidity:cp.execFileSync('solc',['--version'],{encoding:'utf8'}).trim(),compiler_options:['--optimize','--via-ir','--evm-version','shanghai'],
      execution_gas:'receipt minus exact EIP-2028 intrinsic gas',
      eip7623_projection:'reprice exact calldata and measured Shanghai execution; not a Prague/Fusaka measurement',
      block_gas_limit:100000000,registration_and_deployment:'excluded; roots/SRS bound at deployment, challenge digest owner-registered before each audit',
      authentication:'native separate paths for Xu/Yu; native CMM and full Fiat-Shamir/Schnorr checks for MultiAudit',
      algebraic_rearrangements:'Xu shifts G2 scalar multiplication to G1; Yu combines (X-z)q+y coefficients; MultiAudit expands data MSM',
      native_fixtures_verified:true,public_verifier_account:true,negative_checks:checks,
      bytecode_sha256:crypto.createHash('sha256').update(Buffer.from(artifact['bin-runtime'],'hex')).digest('hex'),
      source_sha256:Object.fromEntries(sourceFiles.map(p=>[p,crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex')]))};
    fs.writeFileSync(path.join(out,'metadata.json'),JSON.stringify(meta,null,2)+'\n');
  } finally {await provider.disconnect();}
}
main().catch(e=>{console.error(e);process.exitCode=1;});
