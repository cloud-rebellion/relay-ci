"""Wake only the inherited owned updater once; require a genuinely new completed check."""
import hashlib
import json
import os
from pathlib import Path
import re
import time

from registry import require, Refusal

LOG_PATH = "/var/log/clamav/freshclam.log"
CONFIG_PATH = "/etc/clamav/freshclam.conf"
PROBE = r'''
import base64,json,os,pathlib,signal,stat,sys
mode,pid,start,cid=sys.argv[1],int(sys.argv[2]),sys.argv[3],sys.argv[4]
assert mode in ('baseline','read','signal') and pid>1 and len(cid)==64 and all(c in '0123456789abcdef' for c in cid)
assert hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal')
pfd=os.pidfd_open(pid,0)
try:
 p=pathlib.Path('/proc')/str(pid)
 def bounded(path,maximum=16384):
  with open(path,'rb') as stream:value=stream.read(maximum+1)
  assert len(value)<=maximum
  return value
 def owned():
  raw=bounded(p/'stat').decode();assert raw.split('(',1)[0].strip()==str(pid)
  assert raw.rsplit(')',1)[1].split()[19]==start
  groups=[x[3:] for x in bounded(p/'cgroup').decode().splitlines() if x.startswith('0::')]
  assert len(groups)==1 and cid in groups[0]
  assert os.readlink(p/'exe').endswith('/freshclam')
  argv=bounded(p/'cmdline',8192).decode().split('\0')[:-1]
  assert '--daemon' in argv or '-d' in argv
  status=dict(line.split(':',1) for line in bounded(p/'status').decode().splitlines() if ':' in line)
  return bool(int(status['SigCgt'].strip(),16)&(1<<(int(signal.SIGUSR1)-1)))
 caught=owned()
 path=p/'root/var/log/clamav/freshclam.log'
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  meta=os.fstat(fd);assert stat.S_ISREG(meta.st_mode) and meta.st_nlink==1 and 0<=meta.st_size<=8<<20
  fds=list((p/'fd').iterdir());assert len(fds)<=64
  writers=[]
  for item in fds:
   try:
    st=os.stat(item)
    info=dict(line.split(':',1) for line in bounded(p/'fdinfo'/item.name).decode().splitlines() if ':' in line)
   except FileNotFoundError:continue
   if (st.st_dev,st.st_ino)==(meta.st_dev,meta.st_ino) and int(info['flags'].strip(),8)&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR):writers.append(int(item.name))
  assert writers
  cursor={'dev':meta.st_dev,'ino':meta.st_ino,'size':meta.st_size}
  if mode=='baseline':
   assert caught
   result={'cursor':cursor,'caught_sigusr1':True,'writer_fd_count':len(writers)}
  else:
   previous=json.loads(sys.argv[5]);assert set(previous)=={'dev','ino','size'}
   assert all(type(previous[k]) is int and previous[k]>=0 for k in previous)
   assert (meta.st_dev,meta.st_ino)==(previous['dev'],previous['ino']) and meta.st_size>=previous['size']
   if mode=='signal':
    assert caught and meta.st_size==previous['size']
    assert owned()  # recheck caught handler and generation while pidfd is held
    signal.pidfd_send_signal(pfd,signal.SIGUSR1)
    result={'signal_sent_once':True,'pid':pid,'start_ticks':start,'cursor':cursor}
   else:
    size=meta.st_size-previous['size'];assert size<=2<<20
    os.lseek(fd,previous['size'],os.SEEK_SET);raw=os.read(fd,size);assert len(raw)==size
    after=os.fstat(fd);assert (after.st_dev,after.st_ino)==(meta.st_dev,meta.st_ino) and after.st_size>=meta.st_size
    owned()
    result={'cursor':cursor,'new_bytes_base64':base64.b64encode(raw).decode()}
 finally:os.close(fd)
finally:os.close(pfd)
print(json.dumps(result,sort_keys=True))
'''


def config_proof(raw,parsed,argv):
    require(0<len(raw)<=256<<10 and 0<len(parsed)<=1<<20,"freshclam-config-bound")
    active={"UpdateLogFile":[],"Checks":[]}
    for line in raw.decode().splitlines():
        parts=line.strip().split(None,1)
        if parts and not parts[0].startswith("#") and parts[0] in active:
            require(len(parts)==2,"freshclam-config-directive")
            active[parts[0]].append(parts[1].strip().strip('"'))
    require(active["UpdateLogFile"] and set(active["UpdateLogFile"])=={LOG_PATH},"freshclam-log-conflict")
    sections=re.split(r"(?m)^Config file:\s*",parsed.decode())
    selected=[x for x in sections[1:] if x.splitlines()[0].strip()=="freshclam.conf"]
    require(len(selected)==1,"freshclam-parser-section")
    values={}
    for line in selected[0].splitlines()[1:]:
        match=re.fullmatch(r'\s*(UpdateLogFile|Checks|Bytecode)\s*=\s*(.*?)\s*',line)
        if match:
            require(match[1] not in values,"freshclam-parser-duplicate")
            values[match[1]]=match[2].strip('"')
    require(values.get("UpdateLogFile")==LOG_PATH and re.fullmatch(r"[0-9]+",values.get("Checks",""))
            and values.get("Bytecode","").lower() in {"yes","true","1","no","false","0"},"freshclam-parser-policy")
    require(not active["Checks"] or set(active["Checks"])=={values["Checks"]},"freshclam-config-checks-conflict")
    checks=[]
    for index,arg in enumerate(argv):
        if arg in {"-c","--checks"}:
            require(index+1<len(argv),"freshclam-checks-argv");checks.append(argv[index+1])
        elif arg.startswith("--checks="):checks.append(arg.split("=",1)[1])
        elif re.fullmatch(r"-c[0-9]+",arg):checks.append(arg[2:])
        require(not arg.lower().startswith("--bytecode"),"freshclam-bytecode-argv-needs-review")
    require(len(checks)<=1 and (checks==["4"] if checks else values["Checks"]=="4"),"freshclam-effective-checks-not-four")
    bytecode=values["Bytecode"].lower() in {"yes","true","1"}
    return {"checks_source":"daemon-argv" if checks else "observed-config-parser","file_checks":int(values["Checks"]),
            "config_sha256":hashlib.sha256(raw).hexdigest(),"clamconf_sha256":hashlib.sha256(parsed).hexdigest(),
            "checks":4,"bytecode_enabled":bytecode,"databases":["main","daily"]+(["bytecode"] if bytecode else [])}


def completed_generation(raw,databases):
    require(len(raw)<=2<<20,"freshclam-new-log-bound")
    text=raw.decode("utf-8","strict")
    require(not re.search(r"(?im)ERROR:|Update failed\.|FreshClam was forbidden|FATAL",text),"freshclam-new-check-failed")
    wake=text.find("Received signal: wake up")
    if wake<0:return None
    begin=text.find("ClamAV update process started at ",wake)
    if begin<0:return None
    end=text.find("--------------------------------------",begin)
    if end<0:return None
    cycle=text[begin:end];observed={}
    for name in databases:
        pattern=r'\b'+name+r'\.(?:cvd|cld) (database is up-to-date|updated) \(version: ([0-9]+),'
        matches=list(re.finditer(pattern,cycle))
        require(len(matches)==1,"freshclam-database-terminal-not-proven")
        observed[name]={"result":matches[0][1],"version":int(matches[0][2])}
    return {"new_wakeup_marker":True,"new_update_start":True,"completed_cycle_delimiter":True,
            "databases":observed,"version_advance_required_or_claimed":False}


def durable_intent(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb",closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def check_inherited(candidate,results):
    results=Path(results);intent=results/"freshclam-wakeup-intent.json"
    require(not intent.exists(),"freshclam-wakeup-intent-exists-no-repeat")
    candidate.inspect()
    top=candidate.d.docker(["top",candidate.cid,"-eo","pid,comm"]).stdout.decode().splitlines()
    pids=[int(parts[0]) for line in top[1:] if len(parts:=line.split())==2 and parts[0].isdecimal() and parts[1]=="freshclam"]
    require(len(pids)==1,"owned-inherited-freshclam-not-unique")
    process=candidate.process_metadata(pids[0]);argv=process.get("cmdline",[])
    require(process.get("exe","").endswith("/freshclam") and ("--daemon" in argv or "-d" in argv),"owned-freshclam-not-daemon")
    require(not any(x.startswith("--config-file") for x in argv),"freshclam-explicit-config-needs-review")
    proof=config_proof(candidate.execute(["cat",CONFIG_PATH]),candidate.execute(["clamconf","--config-dir=/etc/clamav"]),argv)
    def probe(mode,cursor=None):
        candidate.inspect()
        args=["sudo","-n","python3","-c",PROBE,mode,str(pids[0]),process["start_ticks"],candidate.cid]
        if cursor is not None:args.append(json.dumps(cursor,sort_keys=True,separators=(',',':')))
        value=candidate.d.command(args)
        require(value.returncode==0 and 0<len(value.stdout)<=3<<20,"freshclam-probe-bound")
        return json.loads(value.stdout)
    baseline=probe("baseline");cursor=baseline["cursor"]
    require(baseline.get("caught_sigusr1") is True,"freshclam-wakeup-handler-not-caught")
    intent_sha=durable_intent(intent,{"schema":1,"cid":candidate.cid,"pid":pids[0],"start_ticks":process["start_ticks"],
        "signal":"SIGUSR1","baseline_cursor":cursor,"log_path":LOG_PATH,"config":proof})
    acknowledged=False
    try:
        sent=probe("signal",cursor)
        acknowledged=sent.get("signal_sent_once") is True
    except Exception:
        pass  # Ambiguous signal response: observe only; NEVER resend or launch another updater.
    import base64
    body=bytearray();deadline=time.monotonic()+360
    raw_path=results/"real-freshclam-check.stdout"
    with raw_path.open("xb") as output:
        while time.monotonic()<deadline:
            read=probe("read",cursor);cursor=read["cursor"]
            new=base64.b64decode(read["new_bytes_base64"],validate=True)
            require(len(body)+len(new)<=2<<20,"freshclam-new-log-total")
            body.extend(new);output.write(new);output.flush()
            completed=completed_generation(bytes(body),proof["databases"])
            if completed is not None:
                after=candidate.execute(["cat",CONFIG_PATH])
                require(hashlib.sha256(after).hexdigest()==proof["config_sha256"],"freshclam-config-changed")
                return {"owned_inherited_updater":True,"cid":candidate.cid,"pid":pids[0],"start_ticks":process["start_ticks"],
                    "intent_sha256":intent_sha,"signal_attempts":1,"signal_response_acknowledged":acknowledged,
                    "new_log_sha256":hashlib.sha256(body).hexdigest(),"new_log_bytes":len(body),"config":proof,**completed}
            time.sleep(1)
    raise Refusal("freshclam-new-check-not-proven-no-repeat")
