// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Fixed single-file benchmark. Hash domains and framing match the native code.
contract AuditVerifier {
    uint256 constant N = 3907;
    uint256 constant S = 80;
    uint256 constant C = 690;
    uint256 constant FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant FP = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    struct Point { uint256 x; uint256 y; }
    uint8 public immutable mode; // 0: Xu, 1: Yu, 2: MultiAudit
    bytes32 public immutable root;
    address public immutable owner;
    bytes32 public challengeHash;
    bytes private srs;
    bytes private pairingParameters;
    bytes private transcriptPrefix;

    constructor(uint8 kind, bytes32 fileRoot, bytes memory publicSRS,
                bytes memory g2, bytes memory tauG2, bytes memory prefix) {
        require(kind < 3);
        mode = kind; root = fileRoot; owner = msg.sender;
        srs = publicSRS;
        pairingParameters = bytes.concat(g2, tauG2);
        transcriptPrefix = prefix;
    }
    function setChallenge(bytes32 digest) external {
        require(msg.sender == owner);
        challengeHash = digest;
    }
    function verify(bytes calldata ch, bytes calldata pr) external view returns (bool) {
        require(ch.length == 64 + C * 64 && keccak256(ch) == challengeHash, "challenge");
        require(_word(ch,32) < FR);
        uint256 last;
        for (uint256 i; i<C; ++i) {
            uint256 index = _word(ch,64+64*i);
            require(index<N && (i==0 || index>last) && _word(ch,96+64*i)<FR);
            last=index;
        }
        if (mode == 2) return _fold(ch,pr);
        return _paths(ch,pr);
    }
    function _word(bytes calldata b, uint256 off) internal pure returns (uint256 v) {
        assembly { v := calldataload(add(b.offset,off)) }
    }
    function _point(bytes calldata b, uint256 off) internal pure returns (Point memory) {
        return Point(_word(b,off),_word(b,off+32));
    }
    function _memoryPoint(bytes memory b, uint256 off) internal pure returns (Point memory p) {
        p=Point(0,0);
        assembly { mstore(p,mload(add(add(b,32),off))) mstore(add(p,32),mload(add(add(b,64),off))) }
    }
    function _add(Point memory a, Point memory b) internal view returns (Point memory out) {
        uint256[4] memory input=[a.x,a.y,b.x,b.y]; out=Point(0,0);
        bool ok; assembly { ok := staticcall(150,6,input,128,out,64) }
        require(ok,"add");
    }
    function _mul(Point memory p,uint256 v) internal view returns (Point memory out) {
        uint256[3] memory input=[p.x,p.y,v]; out=Point(0,0);
        bool ok; assembly { ok := staticcall(6000,7,input,96,out,64) }
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
        assembly {
            let d := add(input,32)
            mstore(d,mload(left)) mstore(add(d,32),mload(add(left,32)))
            for { let i := 0 } lt(i,128) { i := add(i,32) } { mstore(add(add(d,64),i),mload(add(add(pp,32),i))) }
            mstore(add(d,192),mload(negative)) mstore(add(d,224),mload(add(negative,32)))
            for { let i := 0 } lt(i,128) { i := add(i,32) } { mstore(add(add(d,256),i),mload(add(add(pp,160),i))) }
        }
        uint256[1] memory result; bool ok;
        assembly { ok := staticcall(113000,8,add(input,32),384,result,32) }
        require(ok,"pair"); return result[0]==1;
    }
    function _inverse(uint256 x) internal view returns (uint256 v) {
        require(x>0 && x<FR);
        uint256[6] memory input=[uint256(32),32,32,x,FR-2,FR];
        uint256[1] memory output; bool ok;
        assembly { ok := staticcall(gas(),5,input,192,output,32) }
        require(ok); v=output[0];
    }
    function _nodeFrame(bool compact) internal pure returns (bytes memory) {
        bytes memory label=compact ? bytes("multiaudit:merkle:node") : bytes("benchcore:merkle:node");
        return abi.encodePacked(uint64(label.length),label,uint64(32),bytes32(0),uint64(32),bytes32(0));
    }
    function _node(bytes memory scratch,bytes32 a,bytes32 b) internal pure returns (bytes32) {
        uint256 off=scratch.length-72;
        assembly { mstore(add(add(scratch,32),off),a) mstore(add(add(scratch,72),off),b) }
        return sha256(scratch);
    }
    function _leafFrame(uint8 kind) internal pure returns (bytes memory) {
        if (kind==2) {
            bytes memory label=bytes("multiaudit:merkle:leaf");
            return abi.encodePacked(uint64(label.length),label,uint64(6),bytes("file-0"),uint64(8),uint64(0),uint64(64),bytes32(0),bytes32(0));
        }
        bytes memory name=kind==0 ? bytes("xutifs26:leaf") : bytes("yutc25:tag-imht");
        return abi.encodePacked(uint64(name.length),name,uint64(64),bytes32(0),bytes32(0));
    }
    function _leaf(bytes memory scratch,bytes calldata pr,uint256 off,uint256 index,bool compact) internal pure returns (bytes32) {
        uint256 tagOff=scratch.length-64;
        assembly { calldatacopy(add(add(scratch,32),tagOff),add(pr.offset,off),64) }
        if (compact) {
            uint256 indexOff=tagOff-16;
            assembly { mstore(add(add(scratch,32),indexOff),shl(192,add(index,1))) }
            // Restore the following tag-length word after the unaligned store.
            assembly { mstore(add(add(scratch,40),indexOff),shl(192,64)) }
            assembly { calldatacopy(add(add(scratch,32),tagOff),add(pr.offset,off),64) }
        }
        return sha256(scratch);
    }
    function _paths(bytes calldata ch,bytes calldata pr) internal view returns (bool) {
        bool yu=mode==1;
        uint256 start=yu ? 96+(S-1)*32 : 96;
        require(pr.length==start+C*448 && _word(pr,0)<FR,"length");
        bytes memory leafFrame=_leafFrame(mode);
        bytes memory nodeFrame=_nodeFrame(false);
        Point memory total=Point(0,0);
        for (uint256 i; i<C; ++i) {
            uint256 pos=_word(ch,64+64*i);
            uint256 off=start+i*448;
            bytes32 current=_leaf(leafFrame,pr,off,pos,false);
            for (uint256 level;level<12;++level) {
                bytes32 sibling=bytes32(_word(pr,off+64+32*level));
                current=pos%2==0 ? _node(nodeFrame,current,sibling) : _node(nodeFrame,sibling,current);
                pos>>=1;
            }
            require(current==root,"path");
            Point memory term=_mul(_point(pr,off),_word(ch,96+64*i));
            total=i==0 ? term : _add(total,term);
        }
        uint256 r=_word(ch,32);
        if (!yu) {
            total=_add(total,_mul(Point(1,2),(FR-_word(pr,0))%FR));
            total=_add(total,_mul(_point(pr,32),r));
            require(_pair(total,_point(pr,32)),"Xu");
        } else {
            bytes memory label=bytes("yutc25/eta");
            uint256 eta=uint256(sha256(abi.encodePacked(uint64(label.length),label,uint64(64),pr[32:96])))%FR;
            if (eta==0) eta=1;
            total=_add(total,_mul(_point(pr,32),eta));
            bytes memory bases=srs;
            require(bases.length>=(S*64));
            Point memory right=Point(0,0);
            for (uint256 k;k<S;++k) {
                uint256 prev=k==0 ? _word(pr,0) : _word(pr,96+32*(k-1));
                uint256 now=k==S-1 ? 0 : _word(pr,96+32*k);
                require(prev<FR && now<FR);
                uint256 coefficient=addmod(prev,FR-mulmod(r,now,FR),FR);
                Point memory term=_mul(_memoryPoint(bases,64*k),coefficient);
                right=k==0 ? term : _add(right,term);
            }
            require(_eq(total,right),"Yu");
        }
        return true;
    }
    function _part(bytes memory dest,uint256 pos,bytes calldata src,uint256 off,uint256 size) internal pure returns (uint256) {
        assembly {
            let d := add(add(dest,32),pos)
            mstore(d,shl(192,size))
            calldatacopy(add(d,8),add(src.offset,off),size)
        }
        return pos+8+size;
    }
    function _intPart(bytes memory dest,uint256 pos,uint256 v) internal pure returns (uint256) {
        assembly { let d := add(add(dest,32),pos) mstore(d,shl(192,8)) mstore(add(d,8),shl(192,v)) }
        return pos+16;
    }
    function _transcript(bytes calldata ch,bytes calldata pr) internal view returns (bytes32) {
        bytes memory prefix=transcriptPrefix;
        bytes memory data=new bytes(prefix.length+192+128*C);
        for (uint256 i;i<prefix.length;i+=32) {
            assembly { mstore(add(add(data,32),i),mload(add(add(prefix,32),i))) }
        }
        uint256 pos=_part(data,prefix.length,ch,0,32);
        for (uint256 i;i<C;++i) pos=_intPart(data,pos,_word(ch,64+64*i)+1);
        for (uint256 i;i<C;++i) pos=_part(data,pos,ch,96+64*i,32);
        pos=_part(data,pos,ch,32,32);
        for (uint256 i;i<C;++i) pos=_part(data,pos,pr,352+64*i,64);
        pos=_part(data,pos,pr,128,32);
        pos=_part(data,pos,pr,160,64);
        require(pos==data.length);
        return sha256(data);
    }
    function _hashField(string memory domain,bytes memory parts,uint256 kind,uint256 r) internal pure returns (uint256 value) {
        bytes memory label=bytes(domain);
        for (uint64 counter;;++counter) {
            value=uint256(sha256(abi.encodePacked(uint64(label.length),label,parts,uint64(8),counter))) & ((uint256(1)<<254)-1);
            if (value<FR && (kind!=0 || value!=0) && (kind!=1 || value!=r)) return value;
        }
    }
    function _compactRoot(bytes calldata ch,bytes calldata pr,uint256 aux) internal view {
        uint256[] memory positions=new uint256[](C);
        bytes32[] memory hashes=new bytes32[](C);
        bytes memory leafFrame=_leafFrame(2);
        bytes memory nodeFrame=_nodeFrame(true);
        for (uint256 i;i<C;++i) {
            positions[i]=_word(ch,64+64*i);
            hashes[i]=_leaf(leafFrame,pr,352+64*i,positions[i],true);
        }
        uint256 count=C;uint256 cursor;
        for (uint256 level;level<12;++level) {
            uint256 read;uint256 write;
            while (read<count) {
                uint256 index=positions[read];
                bytes32 a=hashes[read];bytes32 b;
                if (index%2==0 && read+1<count && positions[read+1]==index+1) {
                    b=hashes[read+1];read+=2;
                } else {
                    require(cursor<aux,"missing auxiliary");
                    b=bytes32(_word(pr,352+64*C+32*cursor++));++read;
                    if (index%2==1) (a,b)=(b,a);
                }
                positions[write]=index/2;
                hashes[write]=_node(nodeFrame,a,b);++write;
            }
            count=write;
        }
        require(count==1 && cursor==aux && hashes[0]==root,"CMM");
    }
    function _fold(bytes calldata ch,bytes calldata pr) internal view returns (bool) {
        require(pr.length>=352+64*C && _word(pr,128)<FR && _word(pr,288)<FR);
        uint256 aux=_word(pr,320);
        require(aux<=C*12 && pr.length==352+64*C+32*aux,"length");
        _compactRoot(ch,pr,aux);
        bytes32 transcript=_transcript(ch,pr);
        uint256 gamma=_hashField("multiaudit:gamma",abi.encodePacked(uint64(32),transcript),0,0);
        require(gamma>0);
        uint256 z=_hashField("multiaudit:z",abi.encodePacked(uint64(32),transcript,uint64(64),pr[0:64]),1,_word(ch,32));
        uint256 chi=_hashField("multiaudit:mask",abi.encodePacked(uint64(32),transcript,uint64(64),pr[0:64],uint64(64),pr[64:128],uint64(8),uint64(1),uint64(64),pr[160:224],uint64(64),pr[224:288]),2,0);
        require(_eq(_mul(Point(1,2),_word(pr,288)),_add(_point(pr,224),_mul(_point(pr,160),chi))),"Schnorr");
        uint256 beta=_inverse(addmod(z,FR-_word(ch,32),FR));
        Point memory total=Point(0,0);
        for (uint256 i;i<C;++i) {
            Point memory term=_mul(_point(pr,352+64*i),mulmod(beta,_word(ch,96+64*i),FR));
            total=i==0 ? term : _add(total,term);
        }
        total=_add(total,_mul(_point(pr,160),beta));
        total=_add(total,_mul(Point(1,2),(FR-mulmod(beta,_word(pr,128),FR))%FR));
        total=_add(total,_mul(_point(pr,64),z));
        total=_add(total,_neg(_point(pr,0)));
        require(_pair(total,_point(pr,64)),"MultiAudit");
        return true;
    }
}
