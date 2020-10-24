import pymysql

__all__ = ["getbugid"]

from common import runsql

CACHE={}

def _querybugid(progname, stacktrace, vulntype):
    sql = "select id from bugid where progname=%s and stacktrace=%s and vulntype=%s"
    if (progname, stacktrace, vulntype) in CACHE:
        return CACHE[(progname, stacktrace, vulntype)]
    res = runsql(sql, progname, stacktrace, vulntype)
    if res:
        CACHE[(progname, stacktrace, vulntype)] = res[0][0]
        return res[0][0]
    else:
        return None

def _getfreeid(progname):
    sql = "select MAX(id) from bugid where progname=%s"
    res = runsql(sql, progname)
    if res and res[0][0]:
        return int(res[0][0])+1
    else:
        return 1

def _addbugid(progname, stacktrace, vulntype):
    id = _getfreeid(progname)
    print("[bugid] new bugid %d for prog %s"%(id, progname))
    sql = "insert into bugid(id, progname, stacktrace, vulntype) values(%s, %s, %s, %s)"
    res = runsql(sql, id, progname, stacktrace, vulntype)
    return id

def getbugid(progname, stacktrace, vulntype):
    assert isinstance(stacktrace, str)
    if vulntype == "???":
        return -1
    if progname == "mp3": 
        progname = "mp3gain"
    id = _querybugid(progname, stacktrace, vulntype)
    if not id:
        id = _addbugid(progname, stacktrace, vulntype)
    return id

if __name__ == "__main__":
    progname = "exiv3"
    stacktrace = set(['<null>', 'Exiv2::Image::printIFDStructure(Exiv2::BasicIo&, std::ostream&, Exiv2::PrintStructurexOption, unsigned int, bool, char, int)', 'Exiv2::Internal::stringFormat[abi:cxx11](char const*, ...)', '__interceptor_vsnprintf3'])
    vulntype = "stack-overflow"
    print(getbugid(progname, stacktrace, vulntype))
