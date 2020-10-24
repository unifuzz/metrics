# general experiment load to database
import sys,os,functools
from common import runsql
from bugid import getbugid
from pprint import pprint
cwd = os.getcwd()
data = [
    [1, "exiv2", "@@", "jpg"],
    [2,"tiffsplit","@@","tiff"],
    [3,"mp3gain","@@","mp3"],
    [4,"wav2swf","-o /dev/null @@","wav"],
    [5,"pdftotext","@@ /dev/null","pdf"],
    [6,"infotocap","-o /dev/null @@","text"],
    [7,"mp42aac","@@ /dev/null","mp4"],
    [8,"flvmeta","@@","flv"],
    [9,"objdump","-S @@","obj"],
    [10,"uniq","@@","uniq"],
    [11,"base64","-d @@","base64"],
    [12,"md5sum","-c @@","md5sum"],
    [13,"who","@@","who"], 
    [14, "tcpdump", "-e -vv -nr @@", "tcpdump100"], 
    [15, "ffmpeg", "-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null", "ffmpeg100"],
    [None, "gdk-pixbuf-pixdata", "@@ /dev/null", "pixbuf"],
    [None, "cflow", "@@", "cflow"],
    [None, "nm-new", "-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@", "nm"], #, name2="binutils-latest", folder="binutils-latest/")
    [None, "sqlite3", " < @@", "sql"], 
    [None, "lame3.99.5", "@@ /dev/null", "lame3.99.5"],
    [None, "jhead", "@@", "jhead"],
    [None, "imginfo", "-f @@", "imginfo"], 
    [None, "pngimage", "@@", "pngimage"],
    [None, "jq", ". @@", "json"],
    [None, "mujs", "@@", "mujs"], #mujs 1.0.2
]

@functools.lru_cache(maxsize=8888)
def getstarttime_real(fuzzer, line0, line1):
    base = "/c/ori/"+fuzzer+"/"+line0+"/"+line1+"/"
    if "qsym" in line1:
        if os.path.exists(base+"afl-master/crashes/README.txt"):
            base += "afl-master/"
        else:
            assert os.path.exists(base+"afl-slave/crashes/README.txt")
            base += "afl-slave/"
    fuzzerstats = open(base+"fuzzer_stats").readlines()
    record_starttime = int([i.split()[2] for i in fuzzerstats if i.startswith("start_time")][0])
    record_lasttime = int([i.split()[2] for i in fuzzerstats if i.startswith("last_crash")][0])
    try:
        real_lasttime = os.path.getmtime(base+"crashes/"+[i for i in os.listdir(base+"crashes") if i!="README.txt"][-1])
    except:
        print(base)
        exit()
    #if  (fuzzer, line0, line1) == ('afl_dockervsvm', '2.tiffsplit_d2', 'dockervsvm_afl2_11'):
    #    print(record_starttime, record_lasttime, real_lasttime, os.listdir(base+"crashes"))
    return record_starttime - record_lasttime + real_lasttime

def get_vulntype(err):
    res = "???"
    for line in err.split("\n"):
        if "AddressSanitizer" in line:
            #print(line)
            if " leaked in" in line:
                res = "memory_leak"
            elif "unknown-crash on address" in line:
                res = "unknown-crash"
            elif "failed to allocate" in line:
                res = "excessive_memory_allocation"
            elif "attempting free on address which was not malloc" in line:
                res = "free_error"
            else:
                for item in ["SEGV", "heap-buffer-overflow", "heap-use-after-free","stack-buffer-overflow","global-buffer-overflow","stack-use-after-return","stack-use-after-scope","initialization-order-fiasco", "stack-overflow","memcpy-param-overlap", "alloc-dealloc-mismatch", "use-after-poison", "stack-buffer-underflow", "odr-violation", "new-delete-type-mismatch", "negative-size-param", "invalid-pointer-pair", "intra-object-overflow", "illegal-instruction", "dynamic-stack-buffer-overflow", "container-overflow", "calloc-overflow", "double-free", "alloc-dealloc-mismatch", "allocation-size-too-big", "access-violation"]:
                    if item+" " in line:
                        res = item
    return res

def get_asanuniq(err):
    keywords = set()
    for part in err.split("FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART"):
        if "FUNCTIONENDFUNCTIONENDFUNCTIONEND" in part:
            keywords.add(part.split("FUNCTIONENDFUNCTIONENDFUNCTIONEND")[0])
    return str(tuple(sorted(keywords)))

cvedb = {}# cveid: [cveid, function name, file name, vuln type]
funcname2cve = {} # {funcname: [cve1, cve2]

def addtodict(dict, name, value):
    if name not in dict:
        dict[name] = []
    dict[name].append(value)

CVE_translate = {
    "NULL_pointer_dereference" :"SEGV",
    "heap-based_buffer_over-read": "heap-buffer-overflow",
    "heap-based_buffer_overflow": "heap-buffer-overflow",
}

def init_cve():
    global funcname2cve, cvedb
    for f in os.listdir("/d/_cvedb"):
        prog = f.replace("cvedb_","").replace(".txt", "")
        for line in open("/d/_cvedb/"+f,"r"):
            l = line[:-1].split("\t")
            funcname = l[1].replace("()","")
            if funcname.endswith("."):
                funcname = funcname[:-1]
            funcname = funcname.split("->")[-1]
            l[1] = funcname
            if l[3] in CVE_translate:
                l[3] = CVE_translate[l[3]]
            cvedb[l[0]] = l
            
            funcname = l[1]
            addtodict(funcname2cve.setdefault(prog, {}), funcname, l)
            if "::" in funcname:
                addtodict(funcname2cve.setdefault(prog, {}), funcname.split("::")[1], l)

def choose_match_cve(filepath, funcname, vulntype, cve_candidate, crashfilename):
    res = []
    notequal = []
    for c in cve_candidate: #[cveid, function name, file name, vuln type]
        if c[2] and filepath.endswith(c[2]):
            if vulntype == c[3]:
                res.append(c)
            else:
                notequal.append(c)
    if not res:
        print(crashfilename)
        print(filepath, funcname, vulntype)
        if notequal:
            print("notequal:", notequal)
        else:
            print("cve_candidate", cve_candidate)
        print()
    return res

def parse_asan(err, progname):
    vulntype = get_vulntype(err)
    uniq = get_asanuniq(err)
    started = False
    full = []
    fullraw = []
    cve_candidate = None
    for line in err.split("\n"):
        if "FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART" in line:
            started = True
            location = line.split("LOCATIONSTARTLOCATIONSTARTLOCATIONSTART")[1].split("LOCATIONENDLOCATIONENDLOCATIONEND_")[0]
            function = line.split("FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART")[1].split("FUNCTIONENDFUNCTIONENDFUNCTIONEND_")[0]
            funcname = function.split("(")[0]
            #fullraw.append(function)
            fullraw.append(funcname)
            if not (location.startswith("/usr") or location.startswith("/lib") or location.startswith("/lib32") or location.startswith("/lib64") or location.startswith("/var") or location.startswith("/bin") or location=="<null>"):
                #full.append(function)
                full.append(funcname)
                filepath = location.split(":")[0]
                #if not cve_candidate:
                #    if funcname in funcname2cve[progname]:
                #        cve_candidate = funcname2cve[progname][funcname]
                #    elif funcname.split("::")[-1] in funcname2cve[progname]:
                #        cve_candidate = funcname2cve[progname][funcname.split("::")[-1]]
        elif line=="" and started:
            break # the first stack trace has ended
    bugid = getbugid(progname, str(full[:3]), vulntype)
    #if cve_candidate:
    #    print(progname, bugid, cve_candidate)
    return vulntype,str(full),str(fullraw),uniq,full[0] if len(full) else "",str(full[:2]),str(full[:3]),str(full[:4]),str(full[:5]), bugid

#init_cve()

sqlpending = []
t = 0

def run(fuzzer):
    global sql, sqlbase, t, sqlpending
    for _line in open(fuzzer+"/crasheslist.txt").readlines():
        if not _line:
            continue
        assert _line[:2] == "./"
        line = _line[2:-1]
        line0 = line.split("/")[0]
        line1 = line.split("/")[1]
        filepath = cwd + "/" + fuzzer + "/" + line
        progname = line.split("/")[0].split("_")[0]
        #if "." in progname:
        #    progname = progname.split(".")[1]
        assert progname in [i[1] for i in data], progname
        experiment = "_".join(line1.split("_")[:-1])
        dupN = line1.split("_")[-1]
        filesize = os.path.getsize(filepath)
        #starttime = getstarttime_real(fuzzer, line0, line1)
        #filetime = os.path.getmtime(filepath.replace("/c/work/general","/c/ori"))
        #assert filetime <= starttime+86400, str([fuzzer, line0, line1, starttime, starttime+86400, filetime, filepath.replace("/c/work/general","/c/ori"), ])
        #createtime = filetime-starttime
        createtime = "-1"
        stdoutfile = "/c/ASAN_OUTPUT/"+cwd[1:].replace("/","_")+"/"+fuzzer+"/"+line+".stderr"
        gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = "","","","","","","","","","-1"
        gdbvalidated,exploitable = "-1", "" #TODO
        cve,cvss_impact,cvss_exploitability = "", "-1", "-1"
        if os.path.exists(stdoutfile):
            timeouted = "0"
            stderrtext = open(stdoutfile, "rb").read().decode(errors="ignore")
            if "Sanitizer" in stderrtext:
                asanvalidated = "1"
                gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = parse_asan(stderrtext, progname)
            else:
                asanvalidated = "0"
        else:
            timeouted = "1"
            asanvalidated = "0"
        #continue
        sql += "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s),"
        sqlpending.extend([filepath,fuzzer,progname,experiment,dupN,filesize,createtime,timeouted,asanvalidated,gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5,gdbvalidated,exploitable,bugid,cve,cvss_impact,cvss_exploitability])
        if len(sqlpending) == 24*100:
            t += 1
            print(t)
            runsql(sql[:-1], *sqlpending)
            sqlpending = []
            sql = sqlbase


def main(TABLENAME, fuzzers):
    global sqlbase, sql
    sqlbase = "replace into "+TABLENAME+"(filepath,fuzzer,progname,experiment,dupN,filesize,createtime,timeouted,asanvalidated,gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5,gdbvalidated,exploitable,bugid,cve,cvss_v2,cvss_v3) values "
    sql = sqlbase
    for fuzzer in fuzzers:
        run(fuzzer)

    if sqlpending:
        runsql(sql[:-1], *sqlpending)

if __name__ == "__main__":
    #main("crash", ["afl_dockervsvm", "aflfast_dockervsvm", "honggfuzz", "angora", "tfuzz", "vuzzer", "qsym"])
    main("crash_new", ["afl", "aflfast", "qsym", "angora", "vuzzer", "mopt", "honggfuzz", "tfuzz"])