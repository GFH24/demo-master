# -*- coding: utf8 -*-
import requests
import json
import sys
import os
import time
import xlwt
reload(sys)
sys.setdefaultencoding('utf8')


def get_third_session_id(): 
    # 获取登录会话token，输入为空，成功返回值为字符串（token），失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "8",
            "requestMsg": json.dumps({
                    "username": "yjswls",
                    "password": "yjswls123456!@#"
                })
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['value']
        third_session_id = jsondata['third_session_id']
        if maincode == 1 and jsoncode == '1': 
            return third_session_id
        else: 
            print 'get_third_session_id fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'get_third_session_id error: '
        print e


def close_session(third_session_id): 
    # 关闭会话（回收token），输入为token值，成功返回1，失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "9",
            "requestMsg": json.dumps({
                    "third_session_id": third_session_id
                })
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['value']
        if maincode == 1 and jsoncode == '1':
            print 'close session success!' 
            return 1
        else: 
            print 'close_session fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'close_session error: '
        print e


def get_policyid(third_session_id): 
    # policyid: 4028fe023121e14a013146c3dd915b7f;policyName: 常规安全扫描;policyDesc: 
    # 此策略主要扫描"缓冲区溢出和拒绝服务攻击类"除外的全部漏洞。;policyType: 0;
    # 获取策略，暂时只用上面的常规扫描，所以该方法打印了全部策略（通过policyid控制，不填则返回全部），失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "3",
            "requestMsg": json.dumps({
                    "third_session_id": third_session_id,
                    "policyid": "",
                    "policyName": "",
                    "policyDesc": "",
                    "policyType": ""
                })
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['value']
        if maincode == 1 and jsoncode == '1': 
            for i in jsondata['policyList']: 
                print 'policyid: '+i['policyid']+';policyName: '+i['policyName']+';policyDesc: '+i['policyDesc'] + \
                      ';policyType: '+i['policyType']+';'
        else: 
            print 'get_policyid fail: code['+str(maincode)+','+jsoncode+']'

    except Exception, e:
        print 'get_policyid error: '
        print e


def get_vulnerability(third_session_id, vulnid):
    # 获取漏洞详情，输入为token和漏洞ID，输出为漏洞详情json返回值，失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "10",
            "requestMsg": json.dumps({
                    "third_session_id": third_session_id,
                    "nodeName": "",
                    "shortDesc": "",
                    "repairAdvice": "",
                    "cveTag": "",
                    "cncveTag": "",
                    "riskLevel": "",
                    "vulnId": vulnid
                })
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['value']
        if maincode == 1 and jsoncode == '1': 
            # 这里的for循环是为了输入多个vulnid的时候设置，目前指定了单个vulnid，所以效果相当于i=jsondata['vulnerAbility'][0]
            for i in jsondata['vulnerAbility']: 
                try: 
                    # result = "vulnid: "+i['vulnid']+"; nodeName: "+i['nodeName']+"; shortDesc: "+i['shortDesc']+
                    # "; fullDesc: "+i['fullDesc']+"; repairAdvice: "+i['repairAdvice']+"; riskLevel: "+i['riskLevel']+
                    # "; platforms: "+i['platforms']+"; cncveTag: "+i['cncveTag']+"; cveTag: "+i['cveTag']+
                    # "; cnnvdTag: "+i['cnnvdTag']+"; cvssScore: "+str(i['cvssScore'])+"; bugTraqTag"+i['bugTraqTag']
                    return i
                    # file.write(result+'\n')
                except Exception, e: 
                    print e
            return jsondata
        else: 
            print 'get_vulnerability fail: code['+str(maincode)+','+jsoncode+']'

    except Exception, e: 
        print 'get_vulnerability error: '
        print e


def create_task(third_session_id, task_name, excludetarget, scantarget, ipv6, policyid):
    # ff808081659edcf7016629cba2122ddd
    # 创建任务（也会启动扫描），输入为token，任务名，排除IP，扫描IP，是否IPV6，使用策略。输出为扫描任务ID
    # （后续查询该任务的状态和结果以及删除任务都靠这个ID），失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "1",
            "requestMsg": json.dumps({
                    "third_session_id": third_session_id,
                    "task_Name": task_name,
                    "excludeTarget": excludetarget,
                    "scanTarget": scantarget,
                    "ipv6": ipv6,
                    "policyID": policyid
                })
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1':
            print 'create_task success!'+jsondata['resultId'] 
            return jsondata['resultId']
        else: 
            print 'create_task fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'create_task error: '
        print e
        

def restart_task(third_session_id, resultid):
    # 重启任务，输入为token、任务ID。正常返回1，失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "11",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1': 
            return 1
        else: 
            print 'restart_task fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'restart_task error: '
        print e


def stop_task(third_session_id, resultid):
    # 停止任务，输入为token、任务ID。正常返回1，失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "12",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1': 
            return 1
        else: 
            print 'stop_task fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'stop_task error: '
        print e


def delete_task(third_session_id, resultid):
    # 删除任务，输入为token、任务ID。正常返回1，失败抛异常
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "7",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1': 
            print "delete task success!"
            return 1
        else: 
            print 'delete_task fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'delete_task error: '
        print e


def get_task_status(third_session_id, resultid):
    # 任务状态: 1 等待，2 执行，3 暂停，4 停止，5 完成，6 失败
    # 查看任务状态，输入为token、任务ID。正常返回任务状态值（上面是对应意义），失败抛异常。
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "4",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1':
            status_code = jsondata['taskstatus']
            if status_code == '1':
                status = u'等待'
            elif status_code == '2':
                status = u'正在扫描'
            elif status_code == '3':
                status = u'暂停'
            elif status_code == '4':
                status = u'停止'
            elif status_code == '5':
                status = u'完成'
            elif status_code == '6':
                status = u'失败'
            elif status_code == '10':
                status = u'断点续扫'
            else:
                status = u'未知'
            return status_code,status
        else: 
            print 'get_task_status fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'get_task_status error: '
        print e


def get_task_progress(third_session_id, resultid):
    # 获取执行百分比，输入为token、任务ID。正常返回百分比（0-100），失败抛异常。
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "5",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1':
            print jsondata['taskprogress'] 
            return jsondata['taskprogress']
        else: 
            print 'get_task_progress fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'get_task_progress error: '
        print e


def get_task_result(third_session_id, resultid):
    # 获取任务执行报告。输入为token、任务ID。正常返回执行报告的json值，失败抛异常。
    try: 
        head_data = {'Content-Type': 'application/json'}
        session = requests.session()
        purl = 'http://132.122.63.162:8080/services/api/holeUniform/doHoleScanner'
        post_data = json.dumps({
            "username": "yjswls",
            "password": "yjswls123456!@#",
            "version": "6070",
            "supplier": "1",
            "operationType": "6",
            "requestMsg": "{\"third_session_id\":\""+third_session_id+"\",\"resultId\":\""+resultid+"\"}"
            })
        response = session.post(purl, data=post_data, headers=head_data)
        result = response.json()
        maincode = result['code']
        jsondata = json.loads(result['jsonData'])
        jsoncode = jsondata['code']
        if maincode == 1 and jsoncode == '1': 
            return jsondata['resultHost']
        else: 
            print 'get_task_result fail: code['+str(maincode)+','+jsoncode+']'
        
    except Exception, e: 
        print 'get_task_result error: '
        print e


def gen_report(third_session_id, resultid, fpath, scantime):
    # 生成任务执行报告。输入为token、任务ID，文件保存路径，扫描时间（这个得在执行扫描时自行记录）。
    # 正常返回漏洞报告xls文件，失败抛异常。
    try: 
        workbook = xlwt.Workbook(encoding='utf8')
        vuln_sum = workbook.add_sheet('VULN_SUM')
        vuln_sum.write(0, 0, label='IP_ADDR')
        vuln_sum.write(0, 1, label='SUM')
        vuln_sum.write(0, 2, label='HIGH')
        vuln_sum.write(0, 3, label='MIDDLE')
        vuln_sum.write(0, 4, label='LOW')
        vuln_sum.write(0, 5, label='INFO')
        vuln_list = workbook.add_sheet('VULN_LIST')
        vuln_list.write(0, 0, label='IP_ADDR')
        vuln_list.write(0, 1, label='VULN_LEVEL')
        vuln_list.write(0, 2, label='VULN_NAME')
        vuln_list.write(0, 3, label='VULN_PORT')
        vuln_list.write(0, 4, label='SERVICE_NAME')
        vuln_list.write(0, 5, label='SCAN_TIME')
        vuln_list.write(0, 6, label='SUGGUESTION')
        vulnlist = get_task_result(third_session_id, resultid)
        sum_row = 1
        list_row = 1
        for i in vulnlist: 
            high = 0
            middle = 0
            low = 0
            info = 0
            for j in i['resultVuln']: 
                # protocol = j['protocol']
                vuln_list.write(list_row, 0, label=i['hostIPStr'])
                vulnlist = get_vulnerability(third_session_id, j['vulnID'])
                if vulnlist['riskLevel'] == '1': 
                    vuln_list.write(list_row, 1, label='low')
                    low = low + 1
                if vulnlist['riskLevel'] == '2': 
                    vuln_list.write(list_row, 1, label='middle')
                    middle = middle + 1
                if vulnlist['riskLevel'] == '3': 
                    vuln_list.write(list_row, 1, label='high')
                    high = high + 1
                if vulnlist['riskLevel'] == '4': 
                    vuln_list.write(list_row, 1, label='info')
                    info = info + 1
                vuln_list.write(list_row, 2, label=vulnlist['nodeName'])
                vuln_list.write(list_row, 3, label=j['port'])
                if j['port']: 
                    for k in i['resultPort']: 
                        if j['port'] == k['servicePort']: 
                            vuln_list.write(list_row, 4, label=k['serviceName'])
                vuln_list.write(list_row, 5, label=scantime)
                vuln_list.write(list_row, 6, label=vulnlist['repairAdvice'])
                list_row = list_row + 1
            vuln_sum.write(sum_row, 0, label=i['hostIPStr'])
            vuln_sum.write(sum_row, 1, label=low+middle+high+info)
            vuln_sum.write(sum_row, 2, label=high)
            vuln_sum.write(sum_row, 3, label=middle)
            vuln_sum.write(sum_row, 4, label=low)
            vuln_sum.write(sum_row, 5, label=info)
            sum_row = sum_row + 1
        workbook.save(fpath)
        return 1
        
    except Exception, e: 
        print 'gen_report error: '
        print e


def vuln_scan(scantarget, scantime):
    # 漏洞扫描整体过程，输入为ip清单（换行分隔）和扫描时间，成功返回1，失败抛异常
    try: 
        task_name = "ming-test-3"
        third_session_id = get_third_session_id()
        excludetarget = ""
        ipv6 = "0"
        policyid = "4028fe023121e14a013146c3dd915b7f"
        resultid = create_task(third_session_id, task_name, excludetarget, scantarget, ipv6, policyid)
        print resultid
        #fpath = os.path.abspath(sys.argv[0]).replace(r'/uwsgi','')+r'/static/files/result.xls'
        fpath = 'C:\\bk\\demo\\static\\files\\result.xls'
        #fpath = os.path +'files\\result.xls'
        if os.path.exists(fpath):
            os.remove(fpath)
        stat = 0
        while stat not in ['5', '6']:
            stat = get_task_status(third_session_id, resultid)
            progress = get_task_progress(third_session_id, resultid)
            print 'STEP:' + str(stat) + '  PROGRESS:' + progress + '%'
            time.sleep(1)
        result = gen_report(third_session_id, resultid, fpath, scantime)
        delete_task(third_session_id, resultid)
        close_session(third_session_id)
        return result
    
    except Exception, e: 
        print 'vuln_scan error: '
        print e
        print delete_task(third_session_id, resultid)
        print close_session(third_session_id)


# 下面是vuln_scan执行样例，测试用
'''       
scantarget = '172.40.30.115,172.40.15.177'
scantime = '2018/10/18 09: 48: 22'
print vuln_scan(scantarget,scantime)
'''


# 下面是单个方法执行样例，测试用。
# third_session_id = get_third_session_id()
# get_policyid(third_session_id)
        
'''
task_name = "ming-test-0"
excludetarget = ""
scantarget = "172.40.30.115"
ipv6 = "0"
policyid = "4028fe023121e14a013146c3dd915b7f"
print create_task(third_session_id,task_name, excludetarget,scantarget,ipv6,policyid)
'''

# resultid = "ff808081659edcf7016657a64fb915f8"
# print get_task_status(third_session_id, resultid)
# print get_task_progress(third_session_id, resultid)
# print get_task_result(third_session_id, resultid)
# get_vulnerability(third_session_id,vulnid)

'''
fpath = 'C:\\Users\\gdtel-ming\\Desktop\\ming\\soc-interface\\result.xls'
scantime = "2018-10-12 10: 18: 22"
gen_report(third_session_id, resultid,fpath,scantime)
'''

# print restart_task(third_session_id, resultid)
# print delete_task(third_session_id, resultid)
# print close_session(third_session_id)
