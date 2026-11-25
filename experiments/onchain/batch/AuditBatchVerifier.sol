// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Native batch verification: one Xu batch equation, one MultiAudit batch
// equation, or m native single-file Yu checks in one transaction.
contract AuditBatchVerifier {
    uint256 constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant FP = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    struct Point { uint256 x; uint256 y; }
    uint8 public immutable mode;
    uint256 public immutable M;
    uint256 public immutable N;
    uint256 public immutable S;
    uint256 public immutable C;
    uint256 public immutable L;
    address public immutable owner;
    bytes32[] private roots;
    bytes[] private fileIDs;
    bytes private srs;
    bytes private pairingParameters;
    bytes private transcriptPrefix;
    bytes32 public challengeHash;

    constructor(uint8 kind,bytes32[] memory fileRoots,bytes[] memory ids,
                uint256 n,uint256 s,uint256 c,bytes memory publicSRS,
                bytes memory g2,bytes memory tauG2,bytes memory prefix) {
        require(kind<3 && fileRoots.length>0 && fileRoots.length==ids.length);
        require(n>0 && s>=2 && c>0 && c<=n);
        mode=kind; M=fileRoots.length; N=n; S=s; C=c;
        uint256 height;for(uint256 k=n-1;k>0;k>>=1)++height; L=height;
        roots=fileRoots;fileIDs=ids;owner=msg.sender;srs=publicSRS;
        pairingParameters=bytes.concat(g2,tauG2);transcriptPrefix=prefix;
    }
    function setChallenge(bytes32 digest) external {
        require(msg.sender==owner,"owner");challengeHash=digest;
    }
    function _r(bytes calldata ch,uint256 file) internal view returns(uint256) {
        if(mode==2)return _word(ch,32+32*C+file*32*(C+1));
        return _word(ch,(mode==1 ? file*(64+64*C):0)+32);
    }
    function _index(bytes calldata ch,uint256 file,uint256 j) internal view returns(uint256) {
        if(mode==2)return _word(ch,32+32*j);
        return _word(ch,(mode==1 ? file*(64+64*C):0)+64+64*j);
    }
    function _coefficient(bytes calldata ch,uint256 file,uint256 j) internal view returns(uint256) {
        if(mode==2)return _word(ch,64+32*C+file*32*(C+1)+32*j);
        return _word(ch,(mode==1 ? file*(64+64*C):0)+96+64*j);
    }
    function verify(bytes calldata ch,bytes calldata pr) external view returns(bool) {
        uint256 expected=mode==2 ? 32+32*C+32*M*(C+1) : (mode==1 ? M:1)*(64+64*C);
        require(ch.length==expected && _challengeDigest(ch)==challengeHash,"challenge");
        for(uint256 i;i<(mode==1 ? M:1);++i){
            uint256 last;
            for(uint256 j;j<C;++j){uint256 index=_index(ch,i,j);require(index<N && (j==0||index>last),"indices");last=index;}
        }
        for(uint256 i;i<(mode==0 ? 1:M);++i){
            require(_r(ch,i)<FR,"point");
            if(mode==2)for(uint256 k;k<i;++k)require(_r(ch,i)!=_r(ch,k),"distinct points");
            for(uint256 j;j<C;++j)require(_coefficient(ch,i,j)<FR,"coefficient");
        }
        if(mode==2)return _multi(ch,pr);
        return _paths(ch,pr);
    }
    function _word(bytes calldata b, uint256 off) internal pure returns (uint256 v) {
        assembly ("memory-safe") { v := calldataload(add(b.offset,off)) }
    }
    // The digest's input is temporary. Reuse this area after hashing instead of
    // retaining an expanded challenge allocation throughout verification.
    function _challengeDigest(bytes calldata ch) internal pure returns(bytes32 digest) {
        assembly ("memory-safe") {
            let d:=mload(0x40)
            calldatacopy(d,ch.offset,ch.length)
            digest:=keccak256(d,ch.length)
        }
    }
    function _point(bytes calldata b, uint256 off) internal pure returns (Point memory) {
        return Point(_word(b,off),_word(b,off+32));
    }
    function _read(Point memory p,bytes calldata b,uint256 off) internal pure {
        assembly ("memory-safe") {calldatacopy(p,add(b.offset,off),64)}
    }
    function _readMemory(Point memory p,bytes memory b,uint256 off) internal pure {
        assembly ("memory-safe") {mstore(p,mload(add(add(b,32),off))) mstore(add(p,32),mload(add(add(b,64),off)))}
    }
    function _copy(Point memory dst,Point memory src) internal pure {
        assembly ("memory-safe") {mstore(dst,mload(src)) mstore(add(dst,32),mload(add(src,32)))}
    }
    function _zero(Point memory p) internal pure {
        assembly ("memory-safe") {mstore(p,0) mstore(add(p,32),0)}
    }
    // All modes use these same in-place helpers. Inputs are copied into scratch
    // before STATICCALL, so the output may safely alias either point input.
    function _addInto(Point memory out,Point memory a,Point memory b) internal view {
        bool ok;
        assembly ("memory-safe") {
            let d:=mload(0x40)
            mstore(d,mload(a)) mstore(add(d,32),mload(add(a,32)))
            mstore(add(d,64),mload(b)) mstore(add(d,96),mload(add(b,32)))
            ok:=staticcall(150,6,d,128,out,64)
        }
        require(ok,"add");
    }
    function _mulInto(Point memory out,Point memory p,uint256 v) internal view {
        bool ok;
        assembly ("memory-safe") {
            let d:=mload(0x40)
            mstore(d,mload(p)) mstore(add(d,32),mload(add(p,32))) mstore(add(d,64),v)
            ok:=staticcall(6000,7,d,96,out,64)
        }
        require(ok,"mul");
    }
    function _neg(Point memory p) internal pure returns (Point memory) {
        require(p.x<FP && p.y<FP);
        return Point(p.x,p.y==0 ? 0 : FP-p.y);
    }
    function _eq(Point memory a, Point memory b) internal pure returns (bool) {
        return a.x==b.x && a.y==b.y;
    }
    function _pair(Point memory left,Point memory right) internal view returns (bool) {
        bytes memory pp=pairingParameters;
        require(pp.length==256);
        bytes memory input=new bytes(384);
        Point memory negative=_neg(right);
        assembly ("memory-safe") {
            let d := add(input,32)
            mstore(d,mload(left)) mstore(add(d,32),mload(add(left,32)))
            for { let i := 0 } lt(i,128) { i := add(i,32) } { mstore(add(add(d,64),i),mload(add(add(pp,32),i))) }
            mstore(add(d,192),mload(negative)) mstore(add(d,224),mload(add(negative,32)))
            for { let i := 0 } lt(i,128) { i := add(i,32) } { mstore(add(add(d,256),i),mload(add(add(pp,160),i))) }
        }
        uint256[1] memory result; bool ok;
        assembly ("memory-safe") { ok := staticcall(113000,8,add(input,32),384,result,32) }
        require(ok,"pair"); return result[0]==1;
    }
    function _inverse(uint256 x) internal view returns (uint256 v) {
        require(x>0 && x<FR);
        bool ok;uint256 exponent=FR-2;uint256 modulus=FR;
        assembly ("memory-safe") {
            let d:=mload(0x40)
            mstore(d,32) mstore(add(d,32),32) mstore(add(d,64),32)
            mstore(add(d,96),x) mstore(add(d,128),exponent) mstore(add(d,160),modulus)
            ok:=staticcall(gas(),5,d,192,d,32)
            v:=mload(d)
        }
        require(ok);
    }
    function _nodeFrame(bool compact) internal pure returns (bytes memory) {
        bytes memory label=compact ? bytes("multiaudit:merkle:node") : bytes("benchcore:merkle:node");
        return abi.encodePacked(uint64(label.length),label,uint64(32),bytes32(0),uint64(32),bytes32(0));
    }
    function _node(bytes memory scratch,bytes32 a,bytes32 b) internal pure returns (bytes32) {
        uint256 off=scratch.length-72;
        assembly ("memory-safe") { mstore(add(add(scratch,32),off),a) mstore(add(add(scratch,72),off),b) }
        return sha256(scratch);
    }
    function _leafFrame(uint8 kind,bytes memory id) internal pure returns (bytes memory) {
        if (kind==2) {
            bytes memory label=bytes("multiaudit:merkle:leaf");
            return abi.encodePacked(uint64(label.length),label,uint64(id.length),id,uint64(8),uint64(0),uint64(64),bytes32(0),bytes32(0));
        }
        bytes memory name=kind==0 ? bytes("xutifs26:leaf") : bytes("yutc25:tag-imht");
        return abi.encodePacked(uint64(name.length),name,uint64(64),bytes32(0),bytes32(0));
    }
    function _leaf(bytes memory scratch,bytes calldata pr,uint256 off,uint256 index,bool compact) internal pure returns (bytes32) {
        uint256 tagOff=scratch.length-64;
        assembly ("memory-safe") { calldatacopy(add(add(scratch,32),tagOff),add(pr.offset,off),64) }
        if (compact) {
            uint256 indexOff=tagOff-16;
            assembly ("memory-safe") { mstore(add(add(scratch,32),indexOff),shl(192,add(index,1))) }
            // Restore the following tag-length word after the unaligned store.
            assembly ("memory-safe") { mstore(add(add(scratch,40),indexOff),shl(192,64)) }
            assembly ("memory-safe") { calldatacopy(add(add(scratch,32),tagOff),add(pr.offset,off),64) }
        }
        return sha256(scratch);
    }
    function _part(bytes memory dest,uint256 pos,bytes calldata src,uint256 off,uint256 size) internal pure returns (uint256) {
        assembly ("memory-safe") {
            let d := add(add(dest,32),pos)
            mstore(d,shl(192,size))
            calldatacopy(add(d,8),add(src.offset,off),size)
        }
        return pos+8+size;
    }
    function _intPart(bytes memory dest,uint256 pos,uint256 v) internal pure returns (uint256) {
        assembly ("memory-safe") { let d := add(add(dest,32),pos) mstore(d,shl(192,8)) mstore(add(d,8),shl(192,v)) }
        return pos+16;
    }
    function _paths(bytes calldata ch,bytes calldata pr) internal view returns(bool) {
        bool yu=mode==1;
        uint256 head=yu ? 96+(S-1)*32:96;
        uint256 stride=64+32*L;
        uint256 fileSize=head+C*stride;
        require(pr.length==M*fileSize,"length");
        bytes32[] memory fileRoots=roots;
        bytes memory leafFrame=_leafFrame(mode,bytes(""));
        bytes memory nodeFrame=_nodeFrame(false);
        bytes memory bases=yu ? srs:bytes("");
        if(yu)require(bases.length>=S*64,"srs");
        Point memory global=Point(0,0);Point memory witness=Point(0,0);
        Point memory total=Point(0,0);Point memory term=Point(0,0);
        Point memory right=Point(0,0);Point memory basePoint=Point(0,0);
        Point memory generator=Point(1,2);uint256 value;
        for(uint256 file;file<M;++file){
            uint256 base=file*fileSize;require(_word(pr,base)<FR,"value");
            _zero(total);
            for(uint256 j;j<C;++j){
                uint256 index=_index(ch,file,j);uint256 pos=index;
                uint256 off=base+head+j*stride;
                bytes32 current=_leaf(leafFrame,pr,off,index,false);
                for(uint256 level;level<L;++level){
                    bytes32 sibling=bytes32(_word(pr,off+64+32*level));
                    current=pos%2==0 ? _node(nodeFrame,current,sibling):_node(nodeFrame,sibling,current);pos>>=1;
                }
                require(current==fileRoots[file],"path");
                _read(term,pr,off);_mulInto(term,term,_coefficient(ch,file,j));
                if(j==0)_copy(total,term);else _addInto(total,total,term);
            }
            if(!yu){
                if(file==0)_copy(global,total);else _addInto(global,global,total);
                _read(term,pr,base+32);
                if(file==0)_copy(witness,term);else _addInto(witness,witness,term);
                value=addmod(value,_word(pr,base),FR);
            }else{
                bytes memory label=bytes("yutc25/eta");
                uint256 eta=uint256(sha256(abi.encodePacked(uint64(label.length),label,uint64(64),pr[base+32:base+96])))%FR;
                if(eta==0)eta=1;
                _read(term,pr,base+32);_mulInto(term,term,eta);_addInto(total,total,term);
                _zero(right);uint256 r=_r(ch,file);
                for(uint256 k;k<S;++k){
                    uint256 prev=k==0 ? _word(pr,base):_word(pr,base+96+32*(k-1));
                    uint256 current=k==S-1 ? 0:_word(pr,base+96+32*k);
                    require(prev<FR && current<FR,"quotient");
                    uint256 coefficient=addmod(prev,FR-mulmod(r,current,FR),FR);
                    _readMemory(basePoint,bases,64*k);_mulInto(term,basePoint,coefficient);
                    if(k==0)_copy(right,term);else _addInto(right,right,term);
                }
                require(_eq(total,right),"Yu");
            }
        }
        if(!yu){
            _mulInto(term,generator,(FR-value)%FR);_addInto(global,global,term);
            _mulInto(term,witness,_r(ch,0));_addInto(global,global,term);
            require(_pair(global,witness),"Xu");
        }
        return true;
    }
    function _field(string memory domain,bytes memory parts,bool nonzero,uint256[] memory excluded) internal pure returns(uint256 value){
        bytes memory label=bytes(domain);
        for(uint64 counter;;++counter){
            value=uint256(sha256(abi.encodePacked(uint64(label.length),label,parts,uint64(8),counter)))&((uint256(1)<<254)-1);
            bool valid=value<FR && (!nonzero || value!=0);
            if(valid){for(uint256 i;i<excluded.length;++i)if(value==excluded[i]){valid=false;break;}}
            if(valid)return value;
        }
    }
    function _compactRoot(bytes calldata ch,bytes calldata pr,uint256 file,uint256 off,uint256 aux,uint256[] memory positions,bytes32[] memory hashes,bytes memory nodeFrame) internal view {
        bytes memory leafFrame=_leafFrame(2,fileIDs[file]);
        for(uint256 j;j<C;++j){positions[j]=_index(ch,file,j);hashes[j]=_leaf(leafFrame,pr,off+64+64*j,positions[j],true);}
        uint256 count=C;uint256 cursor;
        for(uint256 level;level<L;++level){
            uint256 read;uint256 write;
            while(read<count){
                uint256 index=positions[read];bytes32 a=hashes[read];bytes32 b;
                if(index%2==0 && read+1<count && positions[read+1]==index+1){b=hashes[read+1];read+=2;}
                else{require(cursor<aux,"missing auxiliary");b=bytes32(_word(pr,off+64+64*C+32*cursor++));++read;if(index%2==1)(a,b)=(b,a);}
                positions[write]=index/2;hashes[write]=_node(nodeFrame,a,b);++write;
            }
            count=write;
        }
        require(count==1 && cursor==aux && hashes[0]==roots[file],"CMM");
    }
    function _transcript(bytes calldata ch,bytes calldata pr,uint256[] memory offsets) internal view returns(bytes32 digest){
        bytes memory prefix=transcriptPrefix;uint256 count=M;uint256 samples=C;
        // Build and hash the identical canonical transcript inside one assembly
        // scope. Its temporary arena can then serve later hash/EC scratch work.
        assembly ("memory-safe") {
            let start:=mload(0x40)
            let prefixSize:=mload(prefix)
            for {let i:=0} lt(i,prefixSize) {i:=add(i,32)} {mstore(add(start,i),mload(add(add(prefix,32),i)))}
            let p:=add(start,prefixSize)
            mstore(p,shl(192,32)) calldatacopy(add(p,8),ch.offset,32) p:=add(p,40)
            for {let j:=0} lt(j,samples) {j:=add(j,1)} {
                mstore(p,shl(192,8))
                mstore(add(p,8),shl(192,add(calldataload(add(add(ch.offset,32),mul(j,32))),1)))
                p:=add(p,16)
            }
            for {let file:=0} lt(file,count) {file:=add(file,1)} {
                let record:=add(add(32,mul(32,samples)),mul(mul(file,32),add(samples,1)))
                let off:=mload(add(add(offsets,32),mul(file,32)))
                for {let j:=0} lt(j,samples) {j:=add(j,1)} {
                    mstore(p,shl(192,32))
                    calldatacopy(add(p,8),add(add(add(ch.offset,record),32),mul(j,32)),32)
                    p:=add(p,40)
                }
                mstore(p,shl(192,32)) calldatacopy(add(p,8),add(ch.offset,record),32) p:=add(p,40)
                for {let j:=0} lt(j,samples) {j:=add(j,1)} {
                    mstore(p,shl(192,64))
                    calldatacopy(add(p,8),add(add(add(pr.offset,off),64),mul(j,64)),64)
                    p:=add(p,72)
                }
                mstore(p,shl(192,32)) calldatacopy(add(p,8),add(pr.offset,off),32) p:=add(p,40)
            }
            let size:=sub(p,start)
            let expected:=add(add(add(prefixSize,40),mul(16,samples)),mul(count,add(mul(112,samples),80)))
            if iszero(eq(size,expected)) {revert(0,0)}
            if iszero(staticcall(gas(),2,start,size,start,32)) {revert(0,0)}
            digest:=mload(start)
        }
    }
    function _multi(bytes calldata ch,bytes calldata pr) internal view returns(bool){
        require(pr.length>=128+M*(64+64*C),"length");
        uint256[] memory offsets=new uint256[](M);
        uint256[] memory points=new uint256[](M);
        uint256[] memory positions=new uint256[](C);bytes32[] memory hashes=new bytes32[](C);
        bytes memory nodeFrame=_nodeFrame(true);uint256 cursor=128;
        for(uint256 file;file<M;++file){
            uint256 off=cursor;offsets[file]=off;points[file]=_r(ch,file);
            require(off+64+64*C<=pr.length && _word(pr,off)<FR,"file header");
            uint256 aux=_word(pr,off+32);require(aux<=C*L,"auxiliary count");
            cursor=off+64+64*C+32*aux;require(cursor<=pr.length,"file length");
            _compactRoot(ch,pr,file,off,aux,positions,hashes,nodeFrame);
        }
        require(cursor==pr.length,"trailing data");
        bytes32 transcript=_transcript(ch,pr,offsets);
        uint256[] memory empty=new uint256[](0);
        uint256 gamma=_field("multiaudit:gamma",abi.encodePacked(uint64(32),transcript),true,empty);
        uint256 z=_field("multiaudit:z",abi.encodePacked(uint64(32),transcript,uint64(64),pr[0:64]),false,points);
        Point memory total=Point(0,0);Point memory term=Point(0,0);
        Point memory generator=Point(1,2);uint256 power=1;uint256 value;
        for(uint256 file;file<M;++file){
            uint256 off=offsets[file];
            uint256 beta=mulmod(power,_inverse(addmod(z,FR-points[file],FR)),FR);power=mulmod(power,gamma,FR);
            for(uint256 j;j<C;++j){
                _read(term,pr,off+64+64*j);_mulInto(term,term,mulmod(beta,_coefficient(ch,file,j),FR));
                if(file==0&&j==0)_copy(total,term);else _addInto(total,total,term);
            }
            value=addmod(value,mulmod(beta,_word(pr,off),FR),FR);
        }
        _mulInto(term,generator,(FR-value)%FR);_addInto(total,total,term);
        _read(term,pr,64);_mulInto(term,term,z);_addInto(total,total,term);
        _read(term,pr,0);_addInto(total,total,_neg(term));
        require(_pair(total,_point(pr,64)),"MultiAudit");return true;
    }
}
