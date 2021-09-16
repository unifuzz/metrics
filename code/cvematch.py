import sys, os, shutil, subprocess, glob, shlex
from db_crash_init import parse_asan
os.environ["ASAN_OPTIONS"]='stack_trace_format="FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART%fFUNCTIONENDFUNCTIONENDFUNCTIONEND_LOCATIONSTARTLOCATIONSTARTLOCATIONSTART%SLOCATIONENDLOCATIONENDLOCATIONEND_FRAMESTARTFRAMESTARTFRAMESTART%nFRAMEENDFRAMEENDFRAMEEND"'

FULLDATA = [[0, None, None, None], [1, "exiv2", "@@", "jpg"],[2,"tiffsplit","@@","tiff"],[3,"mp3gain","@@","mp3"],[4,"wav2swf","-o output @@","wav"],[5,"pdftotext","@@","pdf"],[6,"infotocap","-o /dev/null @@","text"],[7,"mp42aac","@@ /dev/null","mp4"],[8,"flvmeta","@@","flv"],[9,"objdump","-S @@","obj"],[10,"uniq","@@","uniq"],[11,"base64","-d @@","base64"],[12,"md5sum","-c @@","md5sum"],[13,"who","@@","who"], [14, "tcpdump", "-e -vv -nr @@", "pcap"], [15, "ffmpeg", "-y -i @@ -c:v mpeg4 -c:a copy -f mp4 /dev/null", "avi"]]

PROGNAME = "ffmpeg"
ID, _, DEFAULT_PARAM, _ = [i for i in FULLDATA if i[1]==PROGNAME][0]

CMD = "/d/p/aflasan/{ID}.{PROGNAME} PARAM".format(**globals())
GDBCMD = "gdb -ex 'r PARAM' -ex 'exploitable' -ex 'bt' -ex 'quit' /d/p/justafl/{ID}.{PROGNAME}".format(**globals())
if PROGNAME=="infotocap":
    CMD = "/d/p/aflasan/{PROGNAME} PARAM".format(**globals())
    GDBCMD = "gdb -ex 'r PARAM' -ex 'exploitable' -ex 'bt' -ex 'quit' /d/p/justafl/{PROGNAME}".format(**globals())
DATA = []
TRACEDATA = []

def step0_loaddata():
    global DATA
    title = None
    for line in open("cvematch_"+PROGNAME+".txt"):
        l = line[:-1].split("\t")
        if title is None:
            title = l
        else:
            d = {}
            for i, v in enumerate(l):
                d[title[i]] = v.strip()
            #print(d)
            d['pocvalidated'] = int(d['pocvalidated'])
            if d['type'] == 'infinit-loop':
                d['type'] == "infinite loop"
            DATA.append(d)

os.makedirs("/c/ASAN_OUTPUT/cve",exist_ok=True)
os.makedirs("/c/GDB_OUTPUT/cve",exist_ok=True)

def uniq_trace(stack):
    res = []
    for item in stack:
        if not len(res):
            res.append(item)
        elif item!=res[-1]:
            res.append(item)
    return res

def extract_asan(cvefile, command, stderrfile, stdoutfile):
    assert(os.path.exists(cvefile)), cvefile
    id = os.path.basename(cvefile)
    tmpfile = "/tmp/cvematch_running_"+PROGNAME
    shutil.copy(cvefile, tmpfile)
    
    command = command.strip()
    if command:
        assert command.startswith(PROGNAME)
        thiscommand = command.replace(PROGNAME, "").strip()
        thisCMD = CMD.replace("PARAM", thiscommand)
    else:
        thisCMD = CMD.replace("PARAM", DEFAULT_PARAM)
    cmd = shlex.split(thisCMD.replace("@@", tmpfile))
    
    if not os.path.exists(stderrfile):
        try:
            x = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            print("[timeout]", id)
            return False
        with open(stdoutfile, "wb") as errfp:
            errfp.write(x.stdout)
        with open(stderrfile, "wb") as errfp:
            errfp.write(x.stderr)
        err = x.stderr.decode(errors="ignore")
    else:
        with open(stderrfile, "rb") as errfp:
            err = errfp.read().decode(errors="ignore")
    #print(err)
    assert "AddressSanitizer" in err, (err, cvefile, cmd)
    gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = parse_asan(err, PROGNAME)
    stack = [i for i in eval(gccasan_full) if i!="main"]
    if len(stack)>100:
        result = set()
        for item in set(stack):
            if stack.count(item)>10:
                result.add(item)
        stack = list(result)
    return gccasan_vulntype, uniq_trace(stack)

def cveid2what(id, func, command, prefix):
    cvefiles = glob.glob("/d1/cvepoc/"+PROGNAME+"/"+id+"*")
    assert len(cvefiles), "cvefile not exist:"+id
    result = []
    for f in cvefiles:
        stderrfile = prefix+os.path.basename(f)+".stderr"
        stdoutfile = prefix+os.path.basename(f)+".stdout"
        result.append(func(f, command, stderrfile, stdoutfile))
    return result

def cveid2asan(id, command):
    return cveid2what(id, extract_asan, command, "/c/ASAN_OUTPUT/cve/" )

import re
def _in_blacklist(name, filepos):
    if name in ("__kernel_vsyscall", "abort", "raise",
                "malloc", "free", "__GI_abort",
                "__GI_raise", "malloc_printerr",
                "__libc_message", "_int_malloc",
                "_int_free", "main", "___vsnprintf_chk",
                "___asprintf", "malloc_consolidate", "___sprintf_chk"):
        return True
    for word in ["std::", "__GI_", "_IO_","__memcpy_","__assert_", "___printf", "___vsprintf_chk"]:
        if name.startswith(word):
            return True
    if filepos.startswith("/usr") or "/libc" in filepos or "/libm" in filepos:
        return True
    return False

def extract_gdb(cvefile, command, stderrfile, stdoutfile):
    assert(os.path.exists(cvefile)), cvefile
    id = os.path.basename(cvefile)
    tmpfile = "/tmp/cvematch_runninggdb_"+PROGNAME
    shutil.copy(cvefile, tmpfile)
    
    command = command.strip()
    if command:
        assert command.startswith(PROGNAME)
        thiscommand = command.replace(PROGNAME, "").strip()
        thisCMD = GDBCMD.replace("PARAM", thiscommand)
    else:
        thisCMD = GDBCMD.replace("PARAM", DEFAULT_PARAM)
    cmd = shlex.split(thisCMD.replace("@@", tmpfile))
    if not os.path.exists(stderrfile):
        print(" ".join(["'"+i+"'" for i in cmd]))
        try:
            x = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        except subprocess.TimeoutExpired:
            print("[timeout]", id)
            raise
        with open(stdoutfile, "wb") as errfp:
            errfp.write(x.stdout)
        with open(stderrfile, "wb") as errfp:
            errfp.write(x.stderr)
        err = x.stderr.decode(errors="ignore")
        stdout = x.stdout.decode(errors="ignore")
    else:
        with open(stderrfile, "rb") as errfp:
            err = errfp.read().decode(errors="ignore")
        with open(stdoutfile, "rb") as fp:
            stdout = fp.read().decode(errors="ignore")
    assert "\n#0  " in stdout, cvefile
    gdb_stack = []
    for line in stdout.split("\n#0 ")[1].split("\n"):
        if not " (" in line:
            break
        func = line.split(" (")[0].split(" in ")[-1].strip()
        if func.startswith("#"):
            func = " ".join(func.split(" ")[1:])
        func = func.strip()
        if line.split(" ")[-2] in ["at", "from"]:
            filepos = line.split(" ")[-1].strip()
        else:
            filepos = ""
        #print(func, filepos, line)
        if _in_blacklist(func, filepos):
            continue
        if "(" in func:
            func = func.split("(")[0]
        gdb_stack.append(func)
    gdb_stacktrace3 = str(gdb_stack[:3])
    assert " received signal " in stdout
    type = stdout.split(" received signal ")[1].split(",")[0].strip()
    
    return type, uniq_trace(gdb_stack)

def cveid2gdb(id, command):
    return cveid2what(id, extract_gdb, command, "/c/GDB_OUTPUT/cve/" )

def translate_asan2gdb(type):
    t = {
        "excessive_memory_allocation": "SIGABRT",
        "FPE": "SIGFPE"
    }
    return t.get(type, "")

def step1_pocrun():
    global DATA, TRACEDATA
    for cve in DATA:
        filepos = [i.strip() for i in cve["file"].split(",")] if cve["file"].strip() else []
        
        if cve["pocvalidated"] == 1:
            for type, trace in cveid2asan(cve["id"], cve["command"]):
                TRACEDATA.append([cve["id"], cve["pocvalidated"], type, translate_asan2gdb(type), trace, filepos])
            continue
        elif cve["pocvalidated"] == 2:
            for type, trace in cveid2gdb(cve["id"], cve["command"]):
                TRACEDATA.append([cve["id"], cve["pocvalidated"], ("" if type!="SIGSEGV" else "SEGV"), type, trace, filepos])
            continue
        else:
            trace = cve["keywords"]
            if "，" in trace:
                trace = trace.split("，")
            else:
                trace = trace.split(",")
            trace = [t.strip() for t in trace]
            type, gdbtype = cve["type"], cve["gdbtype"]
            if type and not gdbtype:
                gdbtype = translate_asan2gdb(type)
            #print(cve["id"], type, trace)
            #trace = trace[:3] # TODO: delete me!!!
            TRACEDATA.append([cve["id"], cve["pocvalidated"], type, gdbtype, trace, filepos])
    _TRACEDATA = []
    for i in TRACEDATA:
        if len(i[4])>10:
            i[4] = i[4][:10]
        if i not in _TRACEDATA:
            _TRACEDATA.append(i)
    TRACEDATA = _TRACEDATA
    TRACEDATA.sort(key=lambda i:len(i[4]), reverse=True)

def ismatch(t1, t2, first=False):
    """
    return if t1 contains t2
    """
    len_t1, len_t2 = len(t1), len(t2)
    for i in range(0, len_t1-len_t2+1):
        if t1[i:i+len_t2] == t2:
            return True
        if first:
            break
    return False

def ismatchtype(cvetype, thistype):
    # return: 
    #    1 equal
    #    2 possible equal
    #    0 not equal
    if cvetype == thistype:
        return 1
    if "SEGV" in [cvetype, thistype] and "stack-overflow" not in [cvetype, thistype]:
        return 0
    return 0

def dprint(*args):
    sys.stderr.write(" ".join([str(i) for i in args])+"\n")

SAMECVES = []
LINENUMBERS = []
if os.path.exists("extrarules_"+PROGNAME+".txt"):
    for _line in open("extrarules_"+PROGNAME+".txt"):
        l = _line[:-1].split()
        if l[1]=="=":
            SAMECVES.append(set([l[0], l[2]]))
        elif l[1] == "linenumber":
            LINENUMBERS.append([l[0], l[2]])

def choose_matches(thistype, thistrace, cvematches, prefer):
    if set(cvematches) in SAMECVES:
        return cvematches
    myprint("choose_matches:", thistype, thistrace, cvematches, prefer)
    cves = sorted([i for i in TRACEDATA if i[0] in cvematches], key=lambda i:len(i[4]), reverse=True)
    
    thelen = len(cves[0][4])
    result = [i[0] for i in cves if len(i[4])==thelen]
    
    if len(result)>1:
        # after sorting by priority, we still have multiple choices
        # then we choose the equal one
        cves2 = [i for i in TRACEDATA if i[0] in result and i[4][0] == thistrace[0]]
        result = [i[0] for i in cves2]
    
    myprint([i[0] for i in cves], result, "\n")
    return result

def void(*args):
    pass

myprint=dprint

def match_asan(filename):
    global BPRINT_SHOULDPRINT
    stderrfile = filename.replace("/c/work/general","/c/ASAN_OUTPUT/c_work_general")+".stderr"
    stdoutfile = filename.replace("/c/work/general","/c/ASAN_OUTPUT/c_work_general")+".stdout"
    if not os.path.exists(stderrfile) or "AddressSanitizer" not in open(stderrfile, errors="ignore").read():
        myprint("[error] maybe no asan:", stderrfile)
        return []
    errtext = open(stderrfile, "r", errors="ignore").read()
    if "p" in sys.argv:
        print(errtext)
    gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = parse_asan(errtext, PROGNAME)
    trace = [i for i in eval(gccasan_full) if i!="main"]
    if len(trace)>100:
        result = set()
        for item in set(trace):
            if trace.count(item)>10:
                result.add(item)
        trace = list(result)
    trace = uniq_trace(trace)
    myprint(gccasan_vulntype, trace)
    flag = True
    matches = []
    matches3 = []
    if gccasan_vulntype == "stack-overflow":
        for id, src, type, gdbtype, t, filepos in TRACEDATA:
            if type != "stack-overflow":
                continue
            #print("is stack-overflow?", trace, t)
            if set(trace) == set(t):
                matches.append(id)
    else:
        for id, src, type, gdbtype, t, filepos in TRACEDATA:
            if type in ["infinite loop", "stack-overflow"]:
                continue
            if ismatch(trace, t, first=True): # we require first match, no sliding match
                typematched = ismatchtype(gccasan_vulntype, type)
                if typematched:
                    if typematched==2:
                        myprint("this is a possible match", gccasan_vulntype, type)
                    #print("match: ", id)
                    matches.append(id)
            if ismatch(trace, t[:3], first=True) and ismatchtype(gccasan_vulntype, type):
                matches3.append(id)
    if len(matches)>1:
        matches = choose_matches(gccasan_vulntype, trace, matches, prefer="asan")
    if matches:
        myprint("asan match:", matches[0] if len(matches)==1 else matches)
    else:
        myprint("asan no match!")
    myprint("asan matches3:", matches3)
    if not matches:
        BPRINT_SHOULDPRINT = True
    
    if 1: # delete me!
        if not matches and len(matches3)==1:
            return matches3
    return matches

def match_gdb(filename):
    global BPRINT_SHOULDPRINT
    stderrfile = filename.replace("/c/work/general","/c/GDB_OUTPUT/c_work_general")+".stderr"
    stdoutfile = filename.replace("/c/work/general","/c/GDB_OUTPUT/c_work_general")+".stdout"
    if not os.path.exists(stdoutfile) or "\n#0 " not in open(stdoutfile, errors="ignore").read():
        myprint("[error] maybe timeout gdb:", stdoutfile)
        return []
    thistype, trace = extract_gdb(filename, "", stderrfile, stdoutfile)
    myprint(thistype, trace)
    matches = []
    matches3 = []
    for id, src, type, gdbtype, t, filepos in TRACEDATA:
        if type == "infinite loop":
            continue
        if ismatch(trace, t, first=True) and thistype == gdbtype:
            myprint("gdb match: ", id, type, t)
            matches.append(id)
        if ismatch(trace, t[:3], first=True):
            matches3.append(id)
    if len(matches)>1:
        matches = choose_matches(thistype, trace, matches, prefer="gdb")
    if matches:
        myprint("gdb match:", matches[0] if len(matches)==1 else matches)
    else:
        myprint("gdb no match!")
    myprint("gdb matches3:", matches3)
    if not matches:
        BPRINT_SHOULDPRINT = True
    if not matches and len(matches3)==1:
        return matches3
    return matches

from bugid import runsql
from pprint import pprint

ENABLE_WRITE = False
if "writedb" in sys.argv:
    ENABLE_WRITE = True

def write_asan_cve(gccasan_full, gccasan_vulntype, cves):
    if not ENABLE_WRITE:
        return
    cve = ",".join(cves)
    cvssv2 = max([CVSSV2.get(i, 0) for i in cves])
    cvssv3 = max([CVSSV3.get(i, 0) for i in cves])
    sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='"+PROGNAME+"' and cve is null and gccasan_full=%s and gccasan_vulntype=%s"
    return runsql(sql, cve, cvssv2, cvssv3, gccasan_full, gccasan_vulntype)

def write_gdb_cve(exploitable_hash2, exploitable_class, cves):
    if not ENABLE_WRITE:
        return
    cve = ",".join(cves)
    cvssv2 = max([CVSSV2.get(i, 0) for i in cves])
    cvssv3 = max([CVSSV3.get(i, 0) for i in cves])
    sql = "update crash set cve=%s, cvss_v2=%s, cvss_v3=%s where progname='"+PROGNAME+"' and cve is null and exploitable_hash2=%s and exploitable_class=%s"
    return runsql(sql, cve, cvssv2, cvssv3, exploitable_hash2, exploitable_class)

CVSSV2 = {_line.split("\t")[0]:_line[:-1].split("\t")[1] for _line in open("cvssv2.txt")}
CVSSV3 = {_line.split("\t")[0]:_line[:-1].split("\t")[1] for _line in open("cvssv3.txt")}

BPRINT_BUFFER = []
BPRINT_SHOULDPRINT = False
def bprint(*args):
    global BPRINT_SHOULDPRINT, BPRINT_BUFFER
    BPRINT_BUFFER.append(" ".join([str(i) for i in args]))

def bprint_clear():
    global BPRINT_SHOULDPRINT, BPRINT_BUFFER
    if BPRINT_SHOULDPRINT and BPRINT_BUFFER:
        print("\n".join(BPRINT_BUFFER))
    BPRINT_SHOULDPRINT = False
    BPRINT_BUFFER = []

#myprint=bprint

def generate_tracefile():
    step0_loaddata()
    step1_pocrun()
    with open("tracedata_"+PROGNAME+".txt", "w") as fp:
        for item in TRACEDATA:
            fp.write("\t".join([str(i) for i in item])+"\n")
    exit()

if __name__ == "__main__":
    if not os.path.exists("tracedata_"+PROGNAME+".txt"):
        generate_tracefile()
    if len(sys.argv)==2: 
        if sys.argv[1]=="showtrace":
            for item in TRACEDATA:
                print("\t".join([str(i) for i in item]))
            exit()
        elif sys.argv[1] == "exit":
            exit()
        elif sys.argv[1] == "save":
            generate_tracefile()
    # load the dataset from our modified txt
    TRACEDATA = []
    for _line in open("tracedata_"+PROGNAME+".txt"):
        l = _line[:-1].split("\t")
        TRACEDATA.append([l[0], l[1], l[2], l[3], uniq_trace(eval(l[4])), eval(l[5])])
    for item in runsql("SELECT crash.gccasan_full,count(*)as cnt, filepath, gccasan_3, gccasan_vulntype FROM crash where crash.progname='%(P)s' and crash.asanvalidated>0 and crash.cve IS NULL group by gccasan_vulntype,gccasan_full"%({'P':PROGNAME})):
        filepath = item[2]
        myprint("\n>>>", filepath)
        myprint("bugcnt:", item[1], item[0], item[3], item[4])
        result = match_asan(filepath)
        if result:
            if len(result)>1:
                if set(result) not in SAMECVES:
                    # multiple match, should reconsider!
                    myprint("should reconsider:", result)
                else:
                    # matched same cve, nice match
                    myprint(result)
            else:
                # only one match, good!
                myprint(result)
            write_asan_cve(item[0], item[4], result)
        bprint_clear()
    for item in runsql("SELECT exploitable_hash2,count(*)as cnt, filepath, gdb_stacktrace3, exploitable_class FROM crash where crash.progname='%(P)s' and crash.gdbvalidated>0 and crash.cve IS NULL group by exploitable_hash2, exploitable_class"%({'P':PROGNAME})):
        filepath = item[2]
        myprint("\n>>>", filepath)
        myprint("gdbbugcnt:", item[1], item[0], item[3], item[4])
        #result = match_asan(filepath)
        #if not result:
        result = match_gdb(filepath)
        if result:
            if len(result)>1:
                if set(result) not in SAMECVES:
                    # multiple match, should reconsider!
                    myprint("should reconsider:", result)
                else:
                    # matched same cve, nice match
                    myprint(result)
            else:
                # only one match, good!
                myprint(result)
            write_gdb_cve(item[0], item[4], result)
        bprint_clear()
