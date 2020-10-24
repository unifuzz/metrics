#!/usr/bin/python3

"""
Assume that we have conducted experiments with 30 repetitions and the folder is like:
/c/work/general/afl/exiv2/1/crashes
/c/work/general/afl/exiv2/2/crashes
...
/c/work/general/afl/exiv2/30/crashes

We can run the crash to obtain ASAN output to folder /c/ASAN_OUTPUT/c_work_general/{fuzzername}/{progname}/{repetition}/
# cd /c/work/general/afl
# find -type f|grep crashes/|grep -v README.txt > crasheslist.txt
# cat crasheslist.txt|CMD="/d/p/aflasan/exiv2 @@" /nfs/scripts/crashrunner.py
"""

import sys
import subprocess
import re
import os
import time
import glob
import shlex
import shutil
import threading
from time import sleep
MAX_THREADS = 10
os.environ["ASAN_OPTIONS"]='stack_trace_format="FUNCTIONSTARTFUNCTIONSTARTFUNCTIONSTART%fFUNCTIONENDFUNCTIONENDFUNCTIONEND_LOCATIONSTARTLOCATIONSTARTLOCATIONSTART%SLOCATIONENDLOCATIONENDLOCATIONEND_FRAMESTARTFRAMESTARTFRAMESTART%nFRAMEENDFRAMEENDFRAMEEND"'

def dprint(*args):
    sys.stderr.write(" ".join([str(i) for i in args])+"\n")


def run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10):
    """
    Run certain file to get stdoutfile and stderrfile
    First, the file will be copied to tmpfile,
    then @@ in cmd will be replaced to tmpfile,
    output will be saved to stdoutfile and stderrfile
    if timedout, timeoutfile will be created
    
    Return: (nottimeout, runtime, outputtext)
    
    The caller should keep tmpfile only operated by current thread,
    stdoutfile folder should be present
    """
    shutil.copy(file, tmpfile)
    
    if "@@" in cmd:
        cmds = shlex.split(cmd.replace("@@", tmpfile))
        stdin = None
    else:
        cmds = shlex.split(cmd)
        stdin = open(tmpfile, "rb")
        
    nottimeout = True
    if os.path.exists(timeoutfile):
        os.unlink(timeoutfile)
    starttime = time.time()
    
    #dprint(cmds)
    try:
        x = subprocess.run(cmds, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        exitcode = x.returncode
    except subprocess.TimeoutExpired as e:
        x = e
        nottimeout = False
        with open(timeoutfile, "w") as tmp:
            tmp.write(file+"\n")
        exitcode = -15 #SIGTERM
    
    endtime = time.time()
    runtime = endtime - starttime
    outputtext = x.stdout.decode(errors="ignore")+"\n"+x.stderr.decode(errors="ignore")
    
    with open(stdoutfile, "wb") as fp:
        fp.write(x.stdout)
    with open(stderrfile, "wb") as fp:
        fp.write(x.stderr)
    with open(stdoutfile.replace(".stdout", ".returncode"), "w") as fp:
        fp.write(str(exitcode))
    
    return (nottimeout, exitcode, runtime, outputtext)

FINISHED = 0
RESULT = {}

from db_crash_init_new import parse_asan
def getbugid(text, progname):
    gccasan_vulntype,gccasan_full,gccasan_fullraw,gccasan_uniq,gccasan_1,gccasan_2,gccasan_3,gccasan_4,gccasan_5, bugid = parse_asan(text, progname)
    return bugid

def thread_main(files, cmd, threadid, myname):
    # in each thread, iteratively call run_one_file:
    #     run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10)
    # tmpfile is calculated using myname and threadid
    # pathname of other output files are generated using file pathname, 
    # appending ".stdout", ".stderr", ".timeout" suffix respectively
    
    global FINISHED, RESULT
    usecache = not os.environ.get("NOCACHE", False)
    pwd = os.getcwd()
    for file in files:
        # we will place output files to a folder under /c/ASAN_OUTPUT/
        # this folder is generated solely from file pathname
        # used as a cache folder, to speed up further analysis
        # we ignore certain keywords to shorten output_folder name
        
        #print(file)
        f = file.split("/")
        fname = f[-1]
        
        blacklist = ["", ".", "output", "d", "crashes", "data1", "data2", "data3"]
        if file.startswith(pwd):
            # absolute path
            prefix = "_".join([i for i in f[:-1] if i not in blacklist])
        else:
            # relative path
            prefix = "_".join([i for i in pwd.split("/") if i not in blacklist]) + "/" + "/".join([i for i in f[:-1] if i not in blacklist])

        #print(prefix)
        
        output_folder = "/c/ASAN_OUTPUT/"+prefix+"/"
        
        if not os.path.exists(output_folder):
            os.makedirs(output_folder, exist_ok=True)
        
        tmpfile = "/tmp/{myname}_{threadid}".format(**locals())
        stdoutfile = output_folder+fname+".stdout"
        stderrfile = output_folder+fname+".stderr"
        timeoutfile = output_folder+fname+".timeout"
        
        # res: (nottimeout, exitcode, runtime, outputtext)
        if not os.path.exists(stdoutfile) or not usecache:
            # do not read cache, run it!
            res = run_one_file(file, cmd, tmpfile, stdoutfile, stderrfile, timeoutfile, timeout=10)
        else:
            nottimeout = not os.path.exists(timeoutfile)
            exitcode = int(open(stdoutfile.replace(".stdout", ".returncode")).read())
            runtime = -1
            outputtext = open(stdoutfile, "r", errors="ignore").read()+"\n"+open(stderrfile, "r", errors="ignore").read()
            res = (nottimeout, exitcode, runtime, outputtext)
            
        RESULT[file] = res
        if "AddressSanitizer" in res[3]:
            print(file)
        
        FINISHED += 1


if __name__ == "__main__":

    FILES = [i for i in sys.stdin.read().split("\n") if i and os.path.isfile(i)]

    if not FILES:
        print("[Error] empty crash files? please check glob syntax!")
        exit(1)
    
    len_FILES = len(FILES)
    dprint("Total files:", len_FILES)
    
    cmd = os.environ.get("CMD", None)
    if not cmd:
        print("[Error] env CMD not given")
        exit(1)
    progpath = shlex.split(cmd)[0]
    progname = progpath.split("/")[-1]
    assert progname in ["base64", "exiv2", "ffmpeg", "flvmeta", "infotocap", "mp3gain", "mp42aac", "objdump", "pdftotext", "tcpdump", "tiffsplit", "uniq", "wav2swf", "who", "cflow", "gdk-pixbuf-pixdata", "imginfo", "jhead", "jq", "lame3.99.5", "mujs", "nm-new", "sqlite3"]
    assert os.access(progpath, os.X_OK), "CMD program not executable?"
    
    myname = "tmp_crashrunner_"+str(os.getpid())
    
    threadN = min(MAX_THREADS, len_FILES)
    for i in range(threadN):
        t = threading.Thread(target=thread_main, args=[FILES[i::threadN], cmd, i, myname])
        t.start()
    
    while FINISHED < len_FILES:
        #print("finished:", FINISHED, "/", len_FILES)
        sleep(1)
    
    foundbugids = set()
    for name, value in RESULT.items():
        text = value[3]
        if "AddressSanitizer" in text:
            foundbugids.add(getbugid(text, progname))
    print("bugids:", sorted(list(foundbugids)))
    
    for f in glob.glob("/tmp/"+myname+"*"):
        os.unlink(f)