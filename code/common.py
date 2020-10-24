from config import secret_mysql
# secret_mysql is the connect info to mysql database
#{"user":"unifuzz", "passwd":"password", "host":"localhost", "port": 3306, "db":"unifuzz"}
import pymysql
import threading
thread_data = threading.local()

def db():
    global thread_data
    conn = pymysql.connect(charset='utf8',init_command="set NAMES utf8mb4", use_unicode=True, **secret_mysql)
    thread_data.__dict__["conn"] = conn
    return conn

def runsql(sql, *args, onerror='raise', returnid=False, allow_retry=True):
    global thread_data
    conn = thread_data.__dict__.get("conn")
    if not conn:
        conn = db()
    if not conn.open:
        conn = db()
    cur = conn.cursor()
    try:
        conn.ping()
    except:
        print("conn.ping() failed, reconnect")
        conn = db()
    try:
        cur.execute(sql, args)
    except pymysql.err.OperationalError as e:
        if allow_retry and ("Lost connection to MySQL" in str(e) or "MySQL server has gone away" in str(e)):
            conn = db()
            return runsql(sql, *args, onerror=onerror, returnid=returnid, allow_retry=False)
        else:
            raise
    except:
        if onerror=="ignore":
            conn.commit()
            cur.close()
            return False
        else:
            raise
    if returnid:
        cur.execute("SELECT LAST_INSERT_ID();")
        result = list(cur)[0][0]
    else:
        result = list(cur)
    conn.commit()
    cur.close()
    return result


