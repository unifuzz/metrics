#!/usr/bin/python3
from common import runsql
import os,sys,glob,json
import datetime
import re
server = sys.argv[1]
if os.environ.get("P", None):
    os.chdir(os.environ["P"])
else:
    os.chdir("/var/lib/docker/containers")
sql = "replace into dockers(server, name, id, starttime, runningtime, memlimit, foldername) values "
sqlpending = []
t = 0
for i in glob.glob("*/"):
    if not os.path.exists(i+"hostname"):
        #print(i)
        continue
    j = open(i+"config.v2.json").read()
    data = json.loads(j)
    tmp = [i for i in set(re.findall(r"/d/output/([^/\"' ]+)", j)) if not (i.startswith("cov_") or i.endswith(".log") or i=="junk" or i.endswith(".start;"))]
    foldername = ""
    if len(tmp)>1:
        print(tmp)
        exit()
    elif len(tmp) == 1:
        foldername = tmp[0]
    name = data["Name"]
    starttime = data["State"]["StartedAt"]
    endtime = data["State"]["FinishedAt"]
    if endtime != "0001-01-01T00:00:00Z":
        runningtime = (datetime.datetime.strptime(endtime.split(".")[0], "%Y-%m-%dT%H:%M:%S") - datetime.datetime.strptime(starttime.split(".")[0], "%Y-%m-%dT%H:%M:%S")).total_seconds()
    else:
        runningtime = -1
    memlimit = int(json.load(open(i+"hostconfig.json"))["Memory"]/1024/1024)
    sqlpending.extend([server, name[1:], i[:-1], int(os.path.getmtime(i+"hostname")), runningtime, memlimit, foldername])
    sql += "(%s, %s, %s, %s, %s, %s, %s),"
#print(sqlpending)
runsql(sql[:-1], *sqlpending)
