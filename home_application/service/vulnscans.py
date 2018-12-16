# -*- coding: utf8 -*-
import base64
import bks
import HTMLParser
import os
import SOCconnect
import sys
import time
import zipfile
target_path = r'/usr/local/gse/agent/bin'


def is_ip(ip):
    # 判断IP是否为IPV4格式，输入为IP字符串，是IP输出1，否输出0
    ip = ip.split(".")
    if len(ip) != 4:
        return 0
    else:
        ok = 0
        for i in ip:
            if i.isdigit() and int(i) in range(0, 256):
                ok = ok + 1
        if ok == 4:
            return 1
        else:
            return 0


def vulnscans(iplist):
    # 执行漏洞扫描，输入为IP列表（换行分隔），调用SOC接口，输出为扫描结果
    iplist = iplist.split('\n')
    scantarget = ''
    for i in iplist:
        if is_ip(i):
            scantarget = scantarget + i + ','
    scantarget = scantarget[:-1]
    try:
        if scantarget:
            scantime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            result = SOCconnect.vuln_scan(scantarget, scantime)
            return result
        else:
            return 0
    except Exception, e:
        print 'vulnscan error'
        print e



def uploadtxts(uploadfile):
    result = "只允许上传txt文件"
    iplist = ''
    ipsuccess = 0
    iperror = ''
    if uploadfile.name.split('.')[-1] in ['txt']:
        u = uploadfile.read().split('\n')
        for fread in u:
            fread = fread.strip()
            if is_ip(fread):
                ipsuccess = ipsuccess + 1
                iplist = iplist + fread + '\n'
            else:
                iperror = iperror + fread + ';'
        result = '成功导入' + str(ipsuccess) + '条; 失败记录：' + iperror
    return [result, iplist]


def push_basefile(i, request):
        src_file = os.path.abspath(sys.argv[0]).replace(r'/uwsgi', '') + r'/static/files/check_server_linux.sh'
        bks.push_file(src_file, target_path, i, request)
        src_file = os.path.abspath(sys.argv[0]).replace(r'/uwsgi', '') + r'/static/files/check_server_linux.pl'
        bks.push_file(src_file, target_path, i, request)
        time.sleep(5)


def exc_checkbase(i, request):
    cmd = base64.encodestring('chmod 777 ' + target_path + '/check_server_linux.sh')
    bks.exc_cmd(i, cmd, request)
    cmd = base64.encodestring(target_path + '/check_server_linux.sh' + ' ' + i)
    bks.exc_cmd(i, cmd, request)
    time.sleep(3)


def parse_result(i):
    i = i.replace('\\\\', '\\')
    i = i.replace('\\\"', '\"')
    i = i.replace('\\t', '\t')
    return i


def save_checkresult(i, request):
    cmd = base64.encodestring('cat /tmp/' + i + '_linux_chk.xml')
    fopen = open('/home/ming/' + i + '_linux_chk.xml', 'w')
    result = bks.exc_cmd(i, cmd, request)
    resultxml = ''
    h = HTMLParser.HTMLParser()
    print result
    for j in result:
        r = h.unescape(str(j))
        r = parse_result(r)
        resultxml = resultxml + r
    fopen.write(resultxml)
    fopen.close()


def compress(get_files_path, set_files_path):
    f = zipfile.ZipFile(set_files_path, 'w', zipfile.ZIP_DEFLATED)
    for dirpath, dirnames, filenames in os.walk(get_files_path):
        fpath = dirpath.replace(get_files_path, '')
        fpath = fpath and fpath + os.sep or ''
        for filename in filenames:
            f.write(os.path.join(dirpath, filename), fpath + filename)
            os.remove(os.path.join(dirpath, filename))
    f.close()


def basechecks(ip, request):
    try:
        ip = ip.split(';')
        print ip
        for i in ip:
            if i != '':
                push_basefile(i, request)
                exc_checkbase(i, request)
                save_checkresult(i, request)
        compress('/home/ming/', os.path.abspath(sys.argv[0]).replace(r'/uwsgi', '') + r'/static/files/result.zip')
    except Exception, e:
        print 'basecheck error'
        print e


def pushfiles(ip, request):
    try:
        ip = ip.split(';')
        for i in ip:
                if i != '':
                        a = r'/static/files/check_server_linux.sh'
                        src_file = os.path.abspath(sys.argv[0]).replace(r'/uwsgi', '') + a
                        bks.push_file(src_file, target_path, i, request)
                        a = r'/static/files/check_server_linux.pl'
                        src_file = os.path.abspath(sys.argv[0]).replace(r'/uwsgi', '') + a
                        bks.push_file(src_file, target_path, i, request)
    except Exception, e:
            print 'pushfile error'
            print e
