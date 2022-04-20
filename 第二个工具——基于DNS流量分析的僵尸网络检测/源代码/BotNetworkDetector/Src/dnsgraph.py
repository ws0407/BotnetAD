import datetime
import sys

import matplotlib.pyplot as plt

plt.rcdefaults()
import numpy as np, matplotlib.pyplot as plt, csv
VERBOSE = 1
try:
    from gephistreamer import graph
    from gephistreamer import streamer
    stream = streamer.Streamer(streamer.GephiWS())
except:
    print ('gephi Not running')

g_filename = ''
g_i = 1
p = []
p2 = []

def circle(radius):
    """Bresenham complete circle algorithm in Python"""
    switch = 3 - 2 * radius
    points = []
    x = 0
    y = radius
    while x <= y:
        points.append((x, -y))
        points.append((y, -x))
        points.append((y, x))
        points.append((x, y))
        points.append((-x, y))
        points.append((-y, x))
        points.append((-y, -x))
        points.append((-x, -y))
        if switch < 0:
            switch = switch + 4 * x + 6
        else:
            switch = switch + 4 * (x - y) + 10
            y = y - 1
        x = x + 1

    return points


def GetUniqueIP():
    global stream
    try:
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        sql = 'select  distinct reqIP from bot.request;'
        if VERBOSE:
            print (sql)
        cursor.execute(sql)
        res = cursor.fetchall()
        i = 0
        results = cursor.rowcount
        while cursor:
            node_a = graph.Node(str(res[i]), size=10, x=10 * i, y=5 * i)
            stream.add_node(node_a)
            i += 1

        if results > 0:
            print ('Records Found')
            return 1
        return 0
    except:
        if VERBOSE:
            print (
             '\t', 'Error: GetUniqueIP (' + sql + ')', sys.exc_info()[0])
            return 0


def get_unique_Req_URL():
    """
    Create nodes of all ReqURL IPs in the db
    :return:
    """
    try:
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        sql = 'select  distinct reqURL from bot.request;'
        if VERBOSE:
            print (sql)
        cursor.execute(sql)
        res = cursor.fetchall()
        i = 0
        results = cursor.rowcount
        while cursor:
            node_a = graph.Node(str(res[i]), size=10, x=10 * i, y=5 * i)
            stream.add_node(node_a)
            i += 1

        if results > 0:
            print ('Records Found')
            return 1
        return 0
    except:
        if VERBOSE:
            print (
             '\t', 'Error: get_unique_Req_URL (' + sql + ')', sys.exc_info()[0])
            return 0


def get_edge_IP_URL():
    """
    Create nodes of all ReqURL IPs in the db
    :return:
    """
    try:
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        sql = 'select  reqIP,reqURL from bot.request '
        if VERBOSE:
            print (sql)
        cursor.execute(sql)
        res = cursor.fetchall()
        i = 0
        results = cursor.rowcount
        while cursor:
            node_a = graph.Node(str(res[i][0]), size=3, x=10, y=10 * i)
            node_b = graph.Node(str(res[i][1]), size=3, x=1000, y=10 * i)
            stream.add_node(node_a)
            stream.add_node(node_b)
            edge_ab = graph.Edge(node_a, node_b)
            stream.add_edge(edge_ab)
            i += 1

        if results > 0:
            print ('Records Found')
            return 1
        return 0
    except:
        if VERBOSE:
            print (
             '\t', 'Error: get_edge_IP_URL (' + sql + ')', sys.exc_info()[0])
            return 0


def get_edge_IP_URL_excel():
    """
    Create nodes of all ReqURL IPs in the db
    :return:
    """
    try:
        req_infile = open('E:\\PhD\\python\\traffic\\20160421_150521.pcap_req.csv', 'r')
        req_reader = csv.reader(req_infile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        i = 0
        for res in req_reader:
            node_a = graph.Node(str(res[1]), size=3, x=p[i][0], y=p[i][1])
            tmpstr = str(res[2])
            pt = tmpstr.split('.')
            if len(pt[(len(pt) - 1)]) == 2:
                node_b = graph.Node(pt[(len(pt) - 3)], size=10, x=p2[i][0], y=p2[i][1])
            else:
                node_b = graph.Node(pt[(len(pt) - 2)], size=10, x=p2[i][0], y=p2[i][1])
            stream.add_node(node_a)
            stream.add_node(node_b)
            edge_ab = graph.Edge(node_a, node_b)
            stream.add_edge(edge_ab)
            i += 1
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        results = cursor.rowcount
        if results > 0:
            print ('Records Found')
            return 1
        return 0
    except:
        if VERBOSE:
            print (
             '\t', 'Error: get_edge_IP_URL_Excel ', sys.exc_info())
            return 0


ds_reqCnt = {}
ds_tokenCnt = {}
ds_urlLength = {}

def plotReqCnt():
    global ds_reqCnt
    global g_filename
    fig = plt.figure()
    plt.bar(range(len(ds_reqCnt)), ds_reqCnt.values(), align='center')
    plt.ylabel('# of DNS Request')
    plt.xlabel('# of Hosts')
    plt.title('DNS Traffic')
    plt.savefig(g_filename + '_1.png', dpi=fig.dpi)
    plt.close()


def plotUrlTokenCount():
    global ds_tokenCnt
    newkey = []
    newvalues = []
    i = 0
    for key, values in sorted(ds_tokenCnt.items()):
        newkey.append(key)
        newvalues.append(values)
        i = i + 1

    fig = plt.figure()
    plt.bar(range(len(newkey)), newvalues, align='center')
    plt.xticks(range(len(newkey)), newkey)
    plt.ylabel('# of DNS Request')
    plt.xlabel(' # of Domain Tokens in DNS Request ')
    plt.title('DNS Traffic')
    plt.savefig(g_filename + '_2.png', dpi=fig.dpi)
    plt.close()


def plotUrlLengthCount():
    global ds_urlLength
    newkey = []
    newvalues = []
    i = 0
    for key, values in sorted(ds_urlLength.items()):
        newkey.append(key)
        newvalues.append(values)
        i = i + 1

    fig = plt.figure()
    X = range(int(len(newkey) / 4))
    plt.bar(range(len(newkey)), newvalues, align='center', width=0.2)
    x = np.array([5, 10, 20, 50, 100, 150])
    plt.xticks(range(len(newkey)), newkey, rotation='75', size='xx-small')
    plt.margins(0.1)
    plt.subplots_adjust(bottom=0.1)
    plt.ylabel('# of DNS Request')
    plt.xlabel('Length of FQDN')
    plt.title('DNS Traffic')
    plt.savefig(g_filename + '_3.png', dpi=fig.dpi)
    plt.close()


def get_stats(filename):
    """
    Create nodes of all ReqURL IPs in the db
    :return:
    """
    try:
        req_infile = open(filename, 'r')
        req_reader = csv.reader(req_infile, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        i = 0
        for res in req_reader:
            try:
                if str(res[1]) in ds_reqCnt:
                    ds_reqCnt[str(res[1])] = ds_reqCnt[str(res[1])] + 1
                else:
                    ds_reqCnt[str(res[1])] = 1
                if int(res[3]) in ds_tokenCnt:
                    ds_tokenCnt[int(res[3])] = ds_tokenCnt[int(res[3])] + 1
                else:
                    ds_tokenCnt[int(res[3])] = 1
                if int(res[5]) in ds_urlLength:
                    ds_urlLength[int(res[5])] = ds_urlLength[int(res[5])] + 1
                else:
                    ds_urlLength[int(res[5])] = 1
                i = i + 1
            except:
                print (
                 'Error: get_stats:  ', sys.exc_info())
                continue

        plotReqCnt()
        plotUrlTokenCount()
        plotUrlLengthCount()
    except:
        if VERBOSE:
            print (
             '\t', 'Error: get_edge_IP_URL_Excel ', sys.exc_info())
            return 0


def push_query_helper(regIP):
    global g_i
    try:
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        sql = 'select reqUrl from bot.request where reqIp = ' + str(regIP) + ''
        if VERBOSE:
            print (sql)
        cursor.execute(sql)
        res = cursor.fetchall()
        j = 0
        tmp = ''
        while cursor:
            if j == 0:
                tmp = res[j][0]
            else:
                if tmp == res[j][0]:
                    j += 1
                    continue
                fo = open('foo.csv', 'ab')
                tmprow = tmp + ',' + res[j][0] + '\n'
                print (tmprow)
                fo.writelines(tmprow)
                fo.close()
                tmp = res[j][0]
                g_i += 1
            j += 1

    except:
        if VERBOSE:
            print (
             '\t', 'Error: checkRequest (' + sql + ')', sys.exc_info())
            return 0


def push_query_seq():
    """
    Create nodes and display sequence edges of all ReqURL per IPs in the db
    :return:
    """
    try:
        cnx = mysql.connector.connect(user='root', password='mysql', host='127.0.0.1', database='bot')
        cursor = cnx.cursor()
        sql = 'SELECT  reqIP,count(reqIP) FROM bot.request group by reqip order by count(reqip) desc'
        if VERBOSE:
            print (sql)
        cursor.execute(sql)
        res = cursor.fetchall()
        i = 0
        results = cursor.rowcount
        while cursor:
            try:
                print (
                 res[i][0], res[i][1])
                if res[i][1] > 1:
                    push_query_helper(res[i][0])
                i += 1
            except:
                continue

        if results > 0:
            print ('Records Found')
            return 1
        return 0
    except:
        if VERBOSE:
            print (
             '\t', 'Error: checkRequest (' + sql + ')')
            return 0


def AnalyseData(filename):
    global g_filename
    g_filename = filename
    dns_analyser_start = datetime.datetime.now()
    print ('===============DNS Analyzer Started at  ' + str(dns_analyser_start) + '===============')
    get_stats(filename)
    print ('===============DNS Analyzer Completed at  ' + str(datetime.datetime.now()) + '===============')