"""Synthetic direct-INSTREAM utility/quota fixtures; all payloads stay in owned8GiB storage."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import subprocess
import sys
import zipfile
import zlib

from daemon_policy import MARKER, stream_chunks, verdict
from storage import BoundedDaemon
from registry import require

MIB = 1 << 20
PASSWORD = "relay-synthetic-fixture-only"
CONTROL_COUNT = 8
APT_PREFERENCES = "Package: *\nPin: release o=Ubuntu,l=Ubuntu\nPin-Priority: 990\n\nPackage: *\nPin: release *\nPin-Priority: -1\n"
CASE_NAMES = {"clean-pdf", "controlled-pdf", "clean-docx", "controlled-docx", "encrypted-pdf",
              "encrypted-zip", "individual-size", "expanded-size", "recursion", "file-count", "clean-csv-near-ceiling"}
ALERTS = {"encrypted-zip":"Heuristics.Encrypted.Zip", "encrypted-pdf":"Heuristics.Encrypted.PDF",
          "individual-size":"Heuristics.Limits.Exceeded.MaxFileSize", "expanded-size":"Heuristics.Limits.Exceeded.MaxScanSize",
          "recursion":"Heuristics.Limits.Exceeded.MaxRecursion", "file-count":"Heuristics.Limits.Exceeded.MaxFiles"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pdf_bytes(text):
    require(isinstance(text,bytes) and len(text) <= 4096, "synthetic-pdf-text-bound")
    text = text.replace(b"\\",b"\\\\").replace(b"(",b"\\(").replace(b")",b"\\)")
    stream=zlib.compress(b"BT /F1 12 Tf 72 720 Td ("+text+b") Tj ET\n",9)
    objects=[b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "+str(len(stream)).encode()+b" /Filter /FlateDecode >>\nstream\n"+stream+b"\nendstream"]
    raw=b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"; offsets=[]
    for i,obj in enumerate(objects,1):
        offsets.append(len(raw));raw+=str(i).encode()+b" 0 obj\n"+obj+b"\nendobj\n"
    start=len(raw);raw+=b"xref\n0 6\n0000000000 65535 f \n"
    raw+=b"".join(("%010d 00000 n \n"%offset).encode() for offset in offsets)
    return raw+b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"+str(start).encode()+b"\n%%EOF\n"


def write_zip(path, entries):
    with zipfile.ZipFile(path,"x",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        count = 0; seen = set()
        for name,value in entries:
            count += 1
            require(count <= 10001 and isinstance(name,str) and name not in seen and name.isascii() and len(name)<=80
                    and str(PurePosixPath(name))==name and not PurePosixPath(name).is_absolute()
                    and all(part not in (".","..") for part in PurePosixPath(name).parts)
                    and not any(ord(c)<32 or ord(c)==127 for c in name), "synthetic-zip-entry-name-bound")
            seen.add(name)
            if type(value) is int:
                require(0 < value <= 26*MIB, "synthetic-zip-member-bound")
                with archive.open(name,"w",force_zip64=True) as output:
                    left=value
                    while left:
                        amount=min(left,65536)
                        seed=b"Relay harmless distinct member "+name.encode()+b"\n"
                        output.write((seed*(amount//len(seed)+1))[:amount]);left-=amount
            else:
                require(type(value) is bytes and len(value)<=MIB,"synthetic-zip-byte-member-bound")
                archive.writestr(name,value)


def docx(path,text):
    require(isinstance(text,bytes) and len(text)<=4096 and b"<" not in text and b"&" not in text,"synthetic-docx-text")
    write_zip(path,[("[Content_Types].xml",b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'),
        ("_rels/.rels",b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'),
        ("word/document.xml",b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'+text+b'</w:t></w:r></w:p></w:body></w:document>')])


def specific_alert(response,kind):
    require(kind in ALERTS and 0 < len(response) <= 4096,"direct-alert-input")
    value=response.rstrip(b"\x00\n")
    require(value==("stream: "+ALERTS[kind]+" FOUND").encode(),"direct-specific-"+kind+"-not-proven")
    return {"expected":kind,"alert":ALERTS[kind]}


def fingerprint(path):
    meta=path.lstat()
    require(stat.S_ISREG(meta.st_mode) and not path.is_symlink() and meta.st_size<=8*MIB,"host-fixture-tool-file")
    return {"sha256":sha(path.read_bytes()),"dev":meta.st_dev,"ino":meta.st_ino,"uid":meta.st_uid,"gid":meta.st_gid,
            "mode":stat.S_IMODE(meta.st_mode),"bytes":meta.st_size,"mtime_ns":meta.st_mtime_ns,"ctime_ns":meta.st_ctime_ns}


class HostTools:
    def __init__(self,results):
        self.results=Path(results)
        path=self.results/"fixture-host-tools.json";meta=path.lstat()
        require(stat.S_ISREG(meta.st_mode) and not path.is_symlink() and meta.st_uid==os.getuid()
                and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600 and meta.st_size<=64<<10,
                "host-fixture-metadata-custody")
        self.metadata=json.loads(path.read_bytes())
        require(self.metadata.get("os")=={"ID":"ubuntu","VERSION_ID":"24.04"}
                and set(self.metadata.get("tools",{}))=={"qpdf","zip"}
                and self.metadata.get("installed_on_host_only") is True
                and self.metadata.get("authenticated_ubuntu_apt_only") is True
                and self.metadata.get("cache_in_owned8GiB") is True
                and self.metadata.get("release_selection_sha256")==sha(APT_PREFERENCES.encode()),"host-fixture-tool-metadata")
        self.calls=0

    def run(self,name,args,root):
        require(name in {"qpdf","zip"} and root.resolve()==root and root.is_dir() and root.stat().st_uid==os.getuid()
                and stat.S_IMODE(root.stat().st_mode)==0o700,"host-generator-owned-root")
        program=Path("/usr/bin")/name; pin=self.metadata["tools"][name]
        require(fingerprint(program)==pin["file"],"host-fixture-tool-changed")
        self.calls+=1;leaf="fixture-tool-"+str(self.calls)
        environment={"PATH":"/usr/bin:/bin","HOME":str(root),"TMPDIR":str(root),"LANG":"C","LC_ALL":"C"}
        def bound():resource.setrlimit(resource.RLIMIT_FSIZE,(MIB,MIB))
        with (self.results/(leaf+".stdout")).open("xb") as out,(self.results/(leaf+".stderr")).open("xb") as err:
            result=subprocess.run([str(program),*args],cwd=root,env=environment,stdout=out,stderr=err,timeout=45,preexec_fn=bound)
        require(fingerprint(program)==pin["file"] and result.returncode==0,"host-fixture-generator-failed")
        require(sum(p.stat().st_size for p in self.results.iterdir() if p.is_file()) <= 32*MIB,"direct-diagnostic-total")


class FixtureDaemon(BoundedDaemon):
    """Preserve the owned backend if a privileged fixture installer is unreaped."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fixture_processes = []

    def __exit__(self, exc_type, primary, traceback):
        rows = [{"role":role,"pid":child.pid,"exit_code":child.poll(),
                 "reaped":child.returncode is not None} for role,child in self.fixture_processes]
        try:
            (self.results/"fixture-host-processes.json").write_text(json.dumps({"processes":rows,
                "all_reaped":all(row["reaped"] for row in rows)},sort_keys=True)+"\n")
        except OSError:
            if primary is not None:
                return False  # Preserve the original failure and backend; receipt custody is unknown.
            raise
        if not all(row["reaped"] for row in rows):
            if primary is None:
                require(False,"fixture-host-process-unsettled-backend-preserved")
            return False  # Original failure propagates; do not unmount a still-writable cache.
        return super().__exit__(exc_type,primary,traceback)


LOG_WRITER = "import shutil,sys;shutil.copyfileobj(sys.stdin.buffer,sys.stdout.buffer,65536);sys.stdout.buffer.flush()"


def capture_apt_operation(daemon, results, phase, options, timeout_identity):
    require(phase in {"update","install"},"host-apt-operation-phase")
    result_path=Path(results)/("fixture-apt-"+phase+".json")
    require(not result_path.exists(),"host-apt-operation-already-attempted-no-retry")
    value={"phase":phase,"status":"intent-before-host-operation","phase_timeout_seconds":240,
           "root_kill_grace_seconds":10,"parent_wait_seconds":260,"writer_wait_seconds":5,
           "writer_terminate_grace_seconds":2,"writer_kill_grace_seconds":2,
           "per_log_limit_bytes":MIB,"timeout_binary":timeout_identity,"writers":[]}
    with result_path.open("x") as output:
        json.dump(value,output,sort_keys=True);output.write("\n");output.flush();os.fsync(output.fileno())
    require(fingerprint(Path("/usr/bin/timeout"))==timeout_identity,"host-timeout-binary-changed")
    writers=[];handles=[];apt=None;failure=None
    def file_limit():resource.setrlimit(resource.RLIMIT_FSIZE,(MIB,MIB))
    try:
        for suffix in ("stdout","stderr"):
            output=(Path(results)/("fixture-apt-"+phase+"."+suffix)).open("xb")
            handles.append(output)
            child=subprocess.Popen([sys.executable,"-B","-c",LOG_WRITER],stdin=subprocess.PIPE,
                stdout=output,stderr=subprocess.DEVNULL,preexec_fn=file_limit,start_new_session=True,
                env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"})
            writers.append(child);daemon.fixture_processes.append((phase+"-log-"+suffix,child))
        args=["update"] if phase=="update" else ["install","-y","--no-install-recommends","qpdf","zip"]
        # timeout itself runs as root and owns apt's process group; no broad kill or retry.
        apt=subprocess.Popen(["sudo","-n","/usr/bin/timeout","--signal=TERM","--kill-after=10s","240s",
                "apt-get",*options,*args],stdout=writers[0].stdin,stderr=writers[1].stdin,
                env={"PATH":"/usr/bin:/bin","LANG":"C","DEBIAN_FRONTEND":"noninteractive"},start_new_session=True)
        daemon.fixture_processes.append((phase+"-root-timeout",apt))
        value["root_timeout_client_pid"]=apt.pid
        value["exit_code"]=apt.wait(timeout=260)
    except BaseException as error:
        failure=error;value["error_type"]=type(error).__name__
    finally:
        settlement_errors=[]
        for child in writers:
            try:
                if child.stdin is not None:child.stdin.close()
            except OSError:
                settlement_errors.append("writer-pipe-close-failed")
        for child in writers:
            try:
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:child.terminate()  # Only this exact owned unprivileged writer PID.
                    except OSError:pass
                    try:child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        try:child.kill()
                        except OSError:pass
                        child.wait(timeout=2)
            except (OSError,subprocess.TimeoutExpired):
                settlement_errors.append("writer-reap-unknown")
        for output in handles:
            try:output.close()
            except OSError:settlement_errors.append("writer-file-close-failed")
        value["writers"]=[{"pid":child.pid,"exit_code":child.returncode,"reaped":child.returncode is not None}
                          for child in writers]
        value["root_timeout_started"]=apt is not None
        value["root_timeout_reaped"]=apt is not None and apt.returncode is not None
        value["settlement_errors"]=settlement_errors
        value["status"]="passed" if failure is None and not settlement_errors and value.get("exit_code")==0 \
            and len(writers)==2 and all(child.returncode==0 for child in writers) else "failed-or-unknown-no-retry"
        result_path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
    if failure is not None:raise failure
    require(fingerprint(Path("/usr/bin/timeout"))==timeout_identity and value["status"]=="passed",
            "authenticated-host-apt-operation-or-bounded-log-failed")
    return value


def authenticated_apt_options(work):
    require(work.resolve()==work and work.is_dir() and work.stat().st_uid==os.getuid()
            and stat.S_IMODE(work.stat().st_mode)==0o700, "host-apt-owned-work")
    preference=work/"ubuntu-publisher.pref";parts=work/"preferences.d"
    meta=preference.lstat()
    require(stat.S_ISREG(meta.st_mode) and not preference.is_symlink() and meta.st_uid==os.getuid()
            and meta.st_nlink==1 and stat.S_IMODE(meta.st_mode)==0o600 and meta.st_size<=1024
            and preference.read_text()==APT_PREFERENCES and parts.resolve()==parts and parts.is_dir()
            and parts.stat().st_uid==os.getuid() and stat.S_IMODE(parts.stat().st_mode)==0o700
            and not list(parts.iterdir()), "host-apt-ubuntu-publisher-selection")
    return ["-o","APT::Get::AllowUnauthenticated=false","-o","Acquire::AllowInsecureRepositories=false",
            "-o","Acquire::AllowDowngradeToInsecureRepositories=false",
            "-o","Acquire::Check-Valid-Until=true","-o","Acquire::Languages=none",
            "-o","Dir::Etc::preferences="+str(preference),"-o","Dir::Etc::preferencesparts="+str(parts),
            "-o","Dir::State::lists="+str(work/"lists"),"-o","Dir::Cache::archives="+str(work/"archives"),
            "-o","Dir::Cache::pkgcache="+str(work/"pkgcache.bin"),
            "-o","Dir::Cache::srcpkgcache="+str(work/"srcpkgcache.bin")]


def prepare_host_tools(daemon, results):
    # Host tools only. Downloads/caches are in the existing owned hard8GiB filesystem.
    # Never add a repository, bypass authentication, or alter the scanner image.
    from binding import HARNESS, verify_public
    from storage import public_runner
    public_runner(os.environ);verify_public(HARNESS);daemon.verify_mount()
    results=Path(results)
    runner=Path(os.environ["RUNNER_TEMP"]).resolve()
    require(results==runner/("relay-scanner-phase1-"+os.environ["GITHUB_RUN_ID"]+"-"+os.environ["GITHUB_RUN_ATTEMPT"])
            and results.resolve()==results and results.stat().st_uid==os.getuid()
            and stat.S_IMODE(results.stat().st_mode)==0o700, "host-tool-private-results")
    os_release=dict(line.split("=",1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    selected={key:os_release.get(key,"").strip('"') for key in ("ID","VERSION_ID")}
    require(selected=={"ID":"ubuntu","VERSION_ID":"24.04"},"fixture-tools-ubuntu24-required")
    work=daemon.mount/"assessment/fixture-host-tools"
    require(not work.exists() and work.resolve()==work, "fresh-host-tool-work")
    work.mkdir(mode=0o700)
    for name in ("lists/partial","archives/partial"):
        (work/name).mkdir(parents=True,mode=0o700)
    (work/"ubuntu-publisher.pref").write_text(APT_PREFERENCES)
    (work/"ubuntu-publisher.pref").chmod(0o600)
    (work/"preferences.d").mkdir(mode=0o700)
    options=authenticated_apt_options(work)
    timeout_identity=fingerprint(Path("/usr/bin/timeout"))
    require(timeout_identity["uid"]==0 and not timeout_identity["mode"]&0o022,
            "host-timeout-root-custody")
    timeout_version=subprocess.run(["/usr/bin/timeout","--version"],capture_output=True,timeout=10,
        env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"})
    require(timeout_version.returncode==0 and len(timeout_version.stdout)+len(timeout_version.stderr)<=64<<10
            and timeout_version.stdout.startswith(b"timeout (GNU coreutils)")
            and fingerprint(Path("/usr/bin/timeout"))==timeout_identity,"host-GNU-timeout-identity")
    (results/"fixture-apt-timeout-tool.json").write_text(json.dumps({"file":timeout_identity,
        "version_output_sha256":sha(timeout_version.stdout)},sort_keys=True)+"\n")
    for phase in ("update","install"):
        daemon.verify_mount()
        capture_apt_operation(daemon,results,phase,options,timeout_identity)
        daemon.verify_mount()
    def query(args):
        done=subprocess.run(args,env={"PATH":"/usr/bin:/bin","LANG":"C","LC_ALL":"C"},capture_output=True,timeout=15)
        require(done.returncode==0 and len(done.stdout)+len(done.stderr)<=128<<10,"host-tool-package-query-failed")
        return done.stdout.decode()
    require(not query(["dpkg","-V","qpdf","zip"]).strip(),"installed-host-tool-package-drift")
    tools={}
    for name in ("qpdf","zip"):
        path=Path("/usr/bin")/name;before=fingerprint(path)
        require(before["uid"]==0 and not before["mode"]&0o022,"host-tool-root-custody")
        require(query(["dpkg-query","-S",str(path)]).strip()==name+": "+str(path),"host-tool-package-owner")
        fields=query(["dpkg-query","-W","-f=${Status}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\t${source:Version}\\n",name]).strip().split("\t")
        require(len(fields)==6 and fields[0]=="install ok installed" and fields[1]==name and fields[3]=="amd64"
                and all(re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}",value) for value in fields[1:]),"host-tool-package-identity")
        version=query([str(path),"--version" if name=="qpdf" else "-v"])
        require(fingerprint(path)==before,"host-tool-changed-during-pin")
        tools[name]={"file":before,"package":dict(zip(("status","binary","version","architecture","source","source_version"),fields)),
                     "version_output_sha256":sha(version.encode())}
    (results/"fixture-host-tools.json").write_text(json.dumps({"os":selected,"tools":tools,
        "installed_on_host_only":True,"authenticated_ubuntu_apt_only":True,"cache_in_owned8GiB":True,
        "release_selection_sha256":sha(APT_PREFERENCES.encode())},sort_keys=True,indent=2)+"\n")
    daemon.verify_mount();verify_public(HARNESS)
    return HostTools(results)


def add_quota_cases(root,add):
    path=root/"individual.zip";write_zip(path,[("large.txt",25*MIB+1)]);add("individual-size",path,"individual-size",expanded_bytes=25*MIB+1)
    path=root/"expanded.zip";write_zip(path,[("part%d.txt"%i,21*MIB) for i in range(5)]);add("expanded-size",path,"expanded-size",expanded_bytes=105*MIB,largest_member_bytes=21*MIB)
    current=b"Relay clean nested content\n"
    for depth in range(18):
        path=root/("nested-%02d.zip"%depth);write_zip(path,[("inside.zip" if depth else "inside.txt",current)]);current=path.read_bytes()
    add("recursion",path,"recursion",nesting=18)
    path=root/"many.zip";write_zip(path,[("file-%05d.txt"%i,("Relay distinct harmless file %d\n"%i).encode()) for i in range(10001)]);add("file-count",path,"file-count",file_count=10001)
    path=root/"near-ceiling.csv"
    with path.open("xb") as output:
        output.write(b"v\n");left=24*MIB-2
        while left:
            count=min(left,65536);output.write(b"1\n"*(count//2));left-=count
    add("clean-csv-near-ceiling",path,"clean",raw_bytes=24*MIB)


def build_corpus(daemon,tools):
    daemon.verify_mount()
    root=daemon.mount/"assessment/direct-fixtures"
    require(root.resolve()==root and not root.exists(),"fresh-bounded-fixture-root")
    root.mkdir(mode=0o700)
    cases=[]
    def add(name,path,expected,**shape):
        raw=path.read_bytes();require(0<len(raw)<=25*MIB,"fixture-compressed-stream-bound")
        cases.append({"name":name,"path":str(path),"bytes":len(raw),"sha256":sha(raw),"expected":expected,**shape})
    for label,text,expected in (("clean",b"Relay ordinary clean document", "clean"),("controlled",MARKER,"controlled")):
        path=root/(label+".pdf");path.write_bytes(pdf_bytes(text));add(label+"-pdf",path,expected)
        path=root/(label+".docx");docx(path,text);add(label+"-docx",path,expected)
        require(expected!="controlled" or MARKER not in path.read_bytes(),"office-marker-must-be-compressed")
        require(expected!="controlled" or MARKER not in (root/(label+".pdf")).read_bytes(),"pdf-marker-must-be-compressed")
    for name in ("clean.pdf","controlled.pdf"):
        tools.run("qpdf",["--check",name],root)
    tools.run("qpdf",["--encrypt",PASSWORD,PASSWORD+"-owner","256","--","clean.pdf","encrypted.pdf"],root)
    tools.run("qpdf",["--is-encrypted","encrypted.pdf"],root)
    tools.run("qpdf",["--password="+PASSWORD,"--check","encrypted.pdf"],root)
    add("encrypted-pdf",root/"encrypted.pdf","encrypted-pdf")
    (root/"plain.txt").write_bytes(b"Relay synthetic encrypted archive utility\n")
    tools.run("zip",["-q","-P",PASSWORD,"encrypted.zip","plain.txt"],root)
    with zipfile.ZipFile(root/"encrypted.zip") as archive:
        require(archive.namelist()==["plain.txt"] and archive.infolist()[0].flag_bits&1
                and archive.read("plain.txt",pwd=PASSWORD.encode())==(root/"plain.txt").read_bytes(),"actual-encrypted-zip-fixture")
    add("encrypted-zip",root/"encrypted.zip","encrypted-zip")
    add_quota_cases(root,add)
    require(sum(p.stat().st_size for p in root.iterdir() if p.is_file())<=64*MIB,"fixture-total-bound")
    require(len(cases)==len(CASE_NAMES) and {x["name"] for x in cases}==CASE_NAMES,"exact-direct-fixture-inventory")
    daemon.verify_mount()
    return cases


def scan_corpus(candidate,cases,results,phase):
    require(re.fullmatch(r"[a-z0-9-]{1,60}",phase),"direct-fixture-phase")
    observed=[]
    report=Path(results)/("direct-fixtures-"+phase+".json")
    require(not report.exists(),"direct-fixture-phase-already-attempted")
    def save():
        report.write_text(json.dumps({"phase":phase,"cases":observed,
            "full_scanner_qualified":False},sort_keys=True,indent=2)+"\n")
    save()
    for case in cases:
        raw=Path(case["path"]).read_bytes()
        require(len(raw)==case["bytes"] and sha(raw)==case["sha256"],"synthetic-fixture-changed")
        require(case["name"] in CASE_NAMES,"direct-fixture-name")
        item={key:value for key,value in case.items() if key!="path"}
        item["status"]="attempted";observed.append(item);save()
        try:
            response=candidate.exchange(stream_chunks(raw))
            require(0<len(response)<=4096,"direct-response-bound")
            with (Path(results)/(phase+"-"+case["name"]+".stdout")).open("xb") as output:
                output.write(response)
            item["verdict"]=verdict(response,case["expected"]) if case["expected"] in {"clean","controlled"} else specific_alert(response,case["expected"])
            item["status"]="passed"
        except BaseException as error:
            item.update(status="failed",error_type=type(error).__name__)
            raise
        finally:
            save()
    return observed


if __name__=="__main__":
    raise SystemExit("Inert fixture module; only the reviewed owned daemon assessment may invoke it")
