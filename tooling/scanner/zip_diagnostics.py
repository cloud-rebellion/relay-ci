"""Read-only diagnostic probes. No outcome here qualifies a scanner or limit."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

from daemon_policy import CONFIG, REFERENCE, MARKER, stream_chunks
from registry import require

MIB=1<<20
LIMIT=25*MIB
CONTROL_COUNT=3
SPECS=tuple(("zip"+str(bits)+"-"+name,bits,size,offset)
    for name,size,offset in (("small-marker",256<<10,64<<10),
                             ("large-marker-before",26*MIB,64<<10),
                             ("large-marker-after",26*MIB,LIMIT+(64<<10))) for bits in (32,64))


def sha(raw):return hashlib.sha256(raw).hexdigest()


def payload_blocks(size, offset):
    require(type(size) is int and 0<size<=26*MIB and type(offset) is int and 0<=offset<=size-len(MARKER),
            "zip-diagnostic-payload-bound")
    for start in range(0,size,65536):
        body=bytearray(b"A"*min(65536,size-start))
        low=max(start,offset);high=min(start+len(body),offset+len(MARKER))
        if low<high:body[low-start:high-start]=MARKER[low-offset:high-offset]
        yield bytes(body)


def extras(raw):
    require(len(raw)<=128,"zip-diagnostic-extra-bound")
    values={};cursor=0
    while cursor<len(raw):
        require(cursor+4<=len(raw),"zip-diagnostic-extra-truncated")
        name,length=struct.unpack_from("<HH",raw,cursor);cursor+=4
        require(name not in values and cursor+length<=len(raw),"zip-diagnostic-extra-duplicate-or-truncated")
        values[name]=raw[cursor:cursor+length];cursor+=length
    return values


def headers(raw,bits,size):
    require(bits in (32,64) and 0<len(raw)<=MIB and MARKER not in raw,"zip-diagnostic-wire-bound-or-literal-marker")
    require(len(raw)>=22 and raw[-22:-18]==b"PK\x05\x06","zip-diagnostic-exact-EOCD")
    end=struct.unpack_from("<4s4H2LH",raw,len(raw)-22)
    require(end[1:5]==(0,0,1,1) and end[7]==0 and end[6]+end[5]==len(raw)-22,
            "zip-diagnostic-single-disk-one-member")
    local=struct.unpack_from("<4s5H3L2H",raw,0)
    central=struct.unpack_from("<4s6H3L5H2L",raw,end[6])
    require(local[0]==b"PK\x03\x04" and central[0]==b"PK\x01\x02" and central[16]==0
            and local[3]==central[4]==8 and local[2]==central[3] and not local[2]&9
            and central[9]==size and central[8]>0 and local[6]==central[7],
            "zip-diagnostic-local-central-method-flags-size-CRC")
    name=raw[30:30+local[9]];extra=extras(raw[30+local[9]:30+local[9]+local[10]])
    require(name==b"payload.bin" and raw[end[6]+46:end[6]+46+central[10]]==name
            and central[11]==central[12]==central[13]==0
            and 30+local[9]+local[10]+central[8]==end[6],"zip-diagnostic-name-offset-extra-shape")
    if bits==64:
        require(local[1]==central[2]==45 and local[7]==local[8]==0xffffffff
                and set(extra)=={1} and len(extra[1])==16
                and struct.unpack("<QQ",extra[1])==(size,central[8]),"zip-diagnostic-ZIP64-sentinels-and-decoded-sizes")
    else:
        require(local[1]==central[2]==20 and not extra and local[7:9]==(central[8],size),
                "zip-diagnostic-ZIP32-real-local-sizes")
    return {"local_version_needed":local[1],"flags":local[2],"method":local[3],"crc32":local[6],
        "local_compressed_size_field":local[7],"local_uncompressed_size_field":local[8],
        "local_extra_ids":sorted(extra),"ZIP64_extra_uncompressed_size":size if bits==64 else None,
        "ZIP64_extra_compressed_size":central[8] if bits==64 else None,
        "central_version_needed":central[2],"central_compressed_size":central[8],"central_uncompressed_size":central[9],
        "central_offset":end[6],"data_descriptor":False,"compressed_literal_marker_present":False,
        "local_header_hex":raw[:30+local[9]+local[10]].hex(),
        "central_header_hex":raw[end[6]:len(raw)-22].hex(),"EOCD_hex":raw[-22:].hex()}


def decoded(path,size,offset,expected_sha):
    fingerprint=hashlib.sha256();total=0;carry=b"";positions=[]
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist()==["payload.bin"] and archive.infolist()[0].file_size==size,
                "zip-diagnostic-decode-member")
        with archive.open("payload.bin") as stream:
            while True:
                block=stream.read(65536)
                if not block:break
                require(total+len(block)<=size,"zip-diagnostic-decode-size-bound")
                joined=carry+block;origin=total-len(carry);cursor=0
                while True:
                    found=joined.find(MARKER,cursor)
                    if found<0:break
                    positions.append(origin+found);cursor=found+1
                fingerprint.update(block);total+=len(block);carry=joined[-(len(MARKER)-1):]
    require(total==size and fingerprint.hexdigest()==expected_sha and positions==[offset],
            "zip-diagnostic-decoded-size-hash-and-single-marker-position")
    return {"bytes":total,"sha256":fingerprint.hexdigest(),"marker_offsets":positions}


def build_matrix(root):
    root=Path(root)
    require(root.resolve()==root and not root.exists() and root.parent.is_dir()
            and root.parent.stat().st_uid==os.getuid() and stat.S_IMODE(root.parent.stat().st_mode)==0o700,
            "zip-diagnostic-fresh-private-root")
    root.mkdir(mode=0o700);rows=[]
    for name,bits,size,offset in SPECS:
        path=root/(name+".zip");fingerprint=hashlib.sha256()
        info=zipfile.ZipInfo("payload.bin",date_time=(2026,11,15,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        info.file_size=size;info.external_attr=0o600<<16
        with zipfile.ZipFile(path,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
            with archive.open(info,"w",force_zip64=bits==64) as output:
                for block in payload_blocks(size,offset):fingerprint.update(block);output.write(block)
        raw=path.read_bytes();shape=headers(raw,bits,size)
        content=decoded(path,size,offset,fingerprint.hexdigest())
        rows.append({"name":name,"path":str(path),"archive_bytes":len(raw),"archive_sha256":sha(raw),
                     "format_bits":bits,"member_bytes":size,"marker_offset":offset,
                     "headers":shape,"generated_payload_sha256":fingerprint.hexdigest(),"decoded":content,
                     "qualification_credit":False,"accepted":False})
    require(len(rows)==6 and len({row["name"] for row in rows})==6
            and sum(row["archive_bytes"] for row in rows)<=8*MIB,"zip-diagnostic-matrix-bound")
    return rows


def make_matrix(daemon):
    daemon.verify_mount()
    rows=build_matrix(daemon.mount/"assessment/zip-limit-diagnostics")
    daemon.verify_mount();return rows


def response_kind(response):
    require(type(response) is bytes and 0<len(response)<=4096,"zip-diagnostic-response-bound")
    value=response.rstrip(b"\x00\n")
    if value==b"stream: OK":return "clean-observed-not-accepted"
    if re.fullmatch(rb"stream: Relay\.CI\.Controlled(?:\.UNOFFICIAL)? FOUND",value):return "controlled-observed-not-accepted"
    if re.fullmatch(rb"stream: Heuristics\.Limits\.Exceeded\.[A-Za-z]+ FOUND",value):return "limit-alert-observed-not-accepted"
    return "other-response-observed-not-accepted"


def observe_matrix(candidate,rows,results):
    results=Path(results);report=results/"zip-limit-diagnostics-before-strict-corpus.json"
    cid=getattr(candidate,"cid","")
    require(type(cid) is str and re.fullmatch(r"[0-9a-f]{64}",cid) is not None,"zip-diagnostic-exact-candidate-CID")
    require(not report.exists() and len(rows)==6 and {row["name"] for row in rows}=={row[0] for row in SPECS}
            and all(row.get("qualification_credit") is False and row.get("accepted") is False for row in rows),
            "zip-diagnostic-once-exact-matrix")
    observations=[]
    def save():
        report.write_text(json.dumps({"schema":1,"kind":"relay-ZIP32-ZIP64-diagnostics-only-v1",
            "before_original_strict_corpus":True,"owned_candidate_CID":cid,
            "scanner_reference":REFERENCE,"scanner_config":CONFIG,"observations":observations,
            "qualification_credit":False,"accepted":False,"full_scanner_qualified":False,
            "application_acceptance":False,"deployment_authorized":False},sort_keys=True,indent=2)+"\n")
    save()
    for row in rows:
        path=Path(row["path"]);meta=path.lstat();raw=path.read_bytes()
        require(stat.S_ISREG(meta.st_mode) and not path.is_symlink() and meta.st_uid==os.getuid() and meta.st_nlink==1
                and len(raw)==row["archive_bytes"] and sha(raw)==row["archive_sha256"] and MARKER not in raw,
                "zip-diagnostic-archive-changed")
        item={key:value for key,value in row.items() if key!="path"}
        item.update(qualification_credit=False,accepted=False);observations.append(item);save()
        try:
            response=candidate.exchange(stream_chunks(raw))
            item["observation"]=response_kind(response)
            item.update(response_bytes=len(response),response_sha256=sha(response))
            with (results/("zip-diagnostic-"+row["name"]+".stdout")).open("xb") as output:output.write(response)
        except Exception as error:
            item.update(observation="transport-or-response-error-no-credit",error_type=type(error).__name__)
            # Diagnostics cannot clear or replace the original strict test that follows.
        finally:save()
    return observations
