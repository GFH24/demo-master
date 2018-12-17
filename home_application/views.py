# -*- coding: utf-8 -*-
from common.mymako import render_mako_context, render_json
from django.http import HttpResponse
from home_application.models import ExcRecord, UserInfo, LoginInfo,VulnScanTasks
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from blueking.component.shortcuts import get_client_by_request
from home_application.models import Logs
from home_application.utils import get_job_instance_id,get_job_result,get_hosts
from django.db.models import Q,F
import base64
import json
import sys
import time
import get_client_by_request
sys.path.append('home_application/service/')
import bks
import vulnscans
import SOCconnect

# page_request_start


def home(request):
    """
    首页
    """
    username = bks.get_user(request)
    date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    if username == "admin":
        rolename = "管理员"
    else:
        rolename = UserInfo.objects.filter(username=username).values("rolename")[0]["rolename"]
    if rolename == "管理员" or rolename == "用户":
        bk_token = bks.get_bk_token(request)[0]
        login = LoginInfo(username=username, date=date, bk_token=bk_token)
        login.save()
        logininfo = validate_user(request)[1]
        ctx = {
                'logininfo': logininfo
        }
        return render_mako_context(request, '/home_application/developing.html', ctx)
    else:
        return render_mako_context(request, '/403.html')


#######################
# 调用配置平台API获取所有业务
#######################
def get_biz_list(request):
    biz_list = []
    client = get_client_by_request(request)
    kwargs = {
        'fields': ['bk_biz_id', 'bk_biz_name']
    }
    resp = client.cc.search_business(**kwargs)

    if resp.get('result'):
        data = resp.get('data', {}).get('info', {})
        for _d in data:
            biz_list.append({
                'name': _d.get('bk_biz_name'),
                'id': _d.get('bk_biz_id'),
            })

    result = {'result': resp.get('result'), 'data': biz_list}
    return render_json(result)


#######################
# 前端传入biz_id和IP参数，调用API获取主机信息
#######################
def get_host_list(request):
    biz_id = int(request.GET.get('biz_id'))
    ip_list = [request.GET.get("ip")]
    client = get_client_by_request(request)
    host_list = get_hosts(client, biz_id, ip_list)

    result = {'result': True, 'data': host_list}

    return render_json(result)


# ------------------------------------
# 执行作业，获取主机资源利用率数据
# ------------------------------------
def execute_job(request):
    """
    执行主机资源利用率查询作业
    """
    biz_id = request.GET.get('biz_id')
    ip = request.GET.get('ip')
    command = request.GET.get('command')
    # 调用作业平台API，获取作业执行实例ID
    client = get_client_by_request(request)
    result, job_instance_id = get_job_instance_id(client, biz_id, ip, command)

    result = {'result': result, 'data': job_instance_id}
    return render_json(result)


def get_result(request):
    """
    获取作业执行结果，并解析执行结果展示
    """
    job_instance_id = request.GET.get('job_instance_id')
    biz_id = request.GET.get('biz_id')
    ip = request.GET.get('ip')
    operation = request.GET.get('command')

    # 调用作业平台API，获取作业执行详情，解析获取主机资源利用率数据
    client = get_client_by_request(request)
    # time.sleep(5)
    is_finish, result_data = get_job_result(client, biz_id, job_instance_id, ip)

    # 保存操作记录
    user = request.user.username
    if is_finish:
        log = [ip, user, operation, True]
    else:
        log = [ip, user, operation, False]
    Logs.objects.save_data(log)

    return render_json({'code': 0, 'message': 'success', 'data': result_data})


# ------------------------------------
# 获取历史操作记录数据
# ------------------------------------
def get_operate_logs(request):
    logs = Logs.objects.all()
    all_logs = []

    # 组装历史操作记录参数，返回给前端dataTable处理。
    for k in logs:
        v = {
            "id": k.id,
            "ip": k.ip,
            "operator": k.operator,
            "operation": k.operation,
            "operate_time": str(k.operate_time),
            "operate_result": k.operate_result,
        }
        all_logs.append(v)
    return render_json(all_logs)

 def all_check_page(request):

    return render_mako_context(request, '/home_application/all_check.html')



def create_vulnscan_page(request):

    return render_mako_context(request, '/home_application/create_vulnscan.html')

#创建漏扫任务
def create_vulnscan_task(request):
    vulnscan_taskname = request.GET.get('vulnscan_taskname')
    supplierid = request.GET.get('supplier')
    iplist = request.GET.get('iplist')
    creator = request.user.username
    create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    rename = time.strftime('%Y%m%d%H%M', time.localtime(time.time()))
    soc_task_name = vulnscan_taskname + str(rename)

    if supplierid == '1':
        supplier = u'启明天镜'
    else:
        supplier = u'绿盟AAS'

    iplist = iplist.split('\n')
    scantarget = ''
    for i in iplist:
        if vulnscans.is_ip(i):
            scantarget = scantarget + i + ','
    scantarget = scantarget[:-1]

    excludetarget = ""
    ipv6 = "0"
    policyid = "4028fe023121e14a013146c3dd915b7f"
    resultid=''
    if scantarget:
        try:
            third_session_id = SOCconnect.get_third_session_id()            
            resultid = SOCconnect.create_task(third_session_id, soc_task_name, excludetarget, scantarget, ipv6, policyid)
            print resultid
            #time.sleep(5)
            soc_task_status_code,soc_task_status = SOCconnect.get_task_status(third_session_id, resultid)
            print soc_task_status_code,soc_task_status
            soc_task_progress = SOCconnect.get_task_progress(third_session_id, resultid) + u'%'
            print soc_task_progress
            #SOCconnect.delete_task(third_session_id, resultid)
            SOCconnect.close_session(third_session_id)
        except Exception,e:
            print "Creat VulnScan Task Failed!"
            print e
    
    if resultid:
        VulnScanTasks.objects.create(vulnscan_taskname=vulnscan_taskname,version=u'天镜6070',supplier=supplier,iplist=scantarget,\
        creator=creator,create_time=create_time,soc_task_name=soc_task_name,soc_task_resultid=resultid,\
        soc_task_status=soc_task_status,soc_task_progress=soc_task_progress)
        return render_json({'result': '创建任务成功！'})
    else:
        return render_json({'result': '创建任务失败！'}) 

def all_vulnscan_page(request):

    return render_mako_context(request, '/home_application/all_vulnscan.html')

def vulnscan_report_page(request):
    name = request.GET.get('name')
    resultid = request.GET.get('resultid')
    report = request.GET.get('report')
    
    if report=='false':
        try:
            third_session_id = SOCconnect.get_third_session_id()
            resultHost = SOCconnect.get_task_result(third_session_id, resultid)
            #VulnScanTasks.objects.filter(soc_task_resultid=ut.soc_task_resultid).update(soc_task_status=soc_task_status,soc_task_progress=soc_task_progress)
            SOCconnect.close_session(third_session_id)
        except Exception,e:
            print "Update VulnScan Tasks Status Failed!"
            print e
        print resultHost

    ctx = {'name':name,'resultid':resultid,}

    return render_mako_context(request, '/home_application/vulnscan_report.html',ctx)

#呈现漏扫任务清单
def get_vulnscan_tasks(request):   
    #更新任务状态和进度
    unfinish_tasks= VulnScanTasks.objects.exclude(Q(soc_task_status='完成')|Q(soc_task_status='失败')).all()
    if unfinish_tasks.exists():
        try:
            third_session_id = SOCconnect.get_third_session_id()
            for ut in unfinish_tasks:
                print ut.soc_task_resultid
                soc_task_status_code,soc_task_status = SOCconnect.get_task_status(third_session_id, ut.soc_task_resultid)
                soc_task_progress = SOCconnect.get_task_progress(third_session_id, ut.soc_task_resultid) + u'%'
                VulnScanTasks.objects.filter(soc_task_resultid=ut.soc_task_resultid).update(soc_task_status=soc_task_status,soc_task_progress=soc_task_progress)
            SOCconnect.close_session(third_session_id)
        except Exception,e:
            print "Update VulnScan Tasks Status Failed!"
            print e 
    #获取漏扫任务记录清单
    tasks = VulnScanTasks.objects.all()
    all_tasks=[]
    print tasks
    #组装漏扫任务记录参数，返回给前端dataTable处理。
    for k in tasks:
        v = {
            "ID":k.id,
            "vulnscan_taskname":k.vulnscan_taskname,
            "version":k.version,
            "supplier":k.supplier,
            "iplist":k.iplist,
            "creator":k.creator,
            "create_time":str(k.create_time),
            #"finish_time":str(k.finish_time),
            "soc_task_name":k.soc_task_name,
            "soc_task_resultid":k.soc_task_resultid,
            "soc_task_status":k.soc_task_status,
            "soc_task_progress":float(k.soc_task_progress.strip('%')),
            "has_report":k.has_report,
            }
        all_tasks.append(v)
    return render_json(all_tasks)

def base_check(request):
    host = bks.get_device(request)
    logininfo = validate_user(request)[1]
    ctx = {
            'host': host,
            'logininfo': logininfo
    }
    return render_mako_context(request, '/home_application/base_check.html', ctx)


def cmdexecute(request):
    all_record = ExcRecord.objects.all()
    all_record = all_record[::-1]
    logininfo = validate_user(request)[1]
    ctx = {
            'all_record': all_record,
            'logininfo': logininfo
    }
    return render_mako_context(request, '/home_application/cmd_execution.html', ctx)


def filedistrib(request):
    logininfo = validate_user(request)[1]
    ctx = {
            'logininfo': logininfo
    }
    return render_mako_context(request, '/home_application/file_distribution.html', ctx)


def user_manage(request):
    rolename = validate_user(request)[2]
    if rolename == "管理员":
        userinfo = UserInfo.objects.all().values("username")
        all_users = []
        for i in userinfo:
            all_users.append(i['username'])
        new_users = bks.syn_users(all_users, request)[0]
        del_users = bks.syn_users(all_users, request)[1]
        for i in new_users:
            newuser = UserInfo(username=i, cname=i, rolename='not specified')
            newuser.save()
        for i in del_users:
            deluser = UserInfo.objects.filter(username=i)
            deluser.delete()
        all_users = UserInfo.objects.all()
        logininfo = validate_user(request)[1]
        all_record = LoginInfo.objects.all()
        all_record = all_record[::-1]
        paginator = Paginator(all_record, 10)
        page = request.GET.get('page')
        try:
            contacts = paginator.page(page)
        except PageNotAnInteger:
            # If page is not an integer, deliver first page.
            contacts = paginator.page(1)
        except EmptyPage:
            # If page is out of range (e.g. 9999), deliver last page of results.
            contacts = paginator.page(paginator.num_pages)
        ctx = {
            'all_users': all_users,
            'all_record': contacts,
            'logininfo': logininfo
        }
        return render_mako_context(request, '/home_application/user_manage.html', ctx)
    else:
        return render_mako_context(request, '/403.html')

# page_request_end

# vuln_scan_function_start


def uploadtxt(request):
        uploadfile = request.FILES.get('uploadfile')
        r = vulnscans.uploadtxts(uploadfile)
        result = r[0]
        iplist = r[1]
        data = {'result': result, 'iplist': iplist}
        return HttpResponse(json.dumps(data), content_type='application/json')


def vulnscan(request):
        iplist = request.POST.get('iplist')
        result = vulnscans.vulnscans(iplist)
        if result:
                return render_json({'result': '扫描完成'})
        else:
                return render_json({'result': '扫描失败'})


# vuln_scan_function_end


# base_check_function_start


def basecheck(request):
        ip = request.POST.get('ip')
        vulnscans.basechecks(ip, request)
        return render_json({'result': True})

                
# base_check_function_end


# user_manage_start


def update_user(request):
    username = request.POST.get('username')
    cname = request.POST.get('cname')
    rolename = request.POST.get('rolename')
    UserInfo.objects.filter(username=username).update(cname=cname, rolename=rolename)
    return render_json({'result': True})


def validate_user(request):
    date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    bk_token = bks.get_bk_token(request)[0]
    username = LoginInfo.objects.filter(bk_token=bk_token).values("username")[0]["username"]
    if username == 'admin':
        cname = '超级'
        rolename = '管理员'
    else:
        cname = UserInfo.objects.filter(username=username).values("cname")[0]["cname"]
        rolename = UserInfo.objects.filter(username=username).values("rolename")[0]["rolename"]
    logininfo = "你好 ! " + cname + rolename + " , " + date
    if username:
        return username, logininfo, rolename
    else:
        return 0


# user_manage_end


def exccmd(request):
    ip = request.POST.get('ip')
    cmd = request.POST.get('cmd')
    result = bks.exc_cmd(ip, cmd, request)
    if result != 'cmd_exc_timeout':
            r = True
    else:
            r = False
    cmd = base64.decodestring(cmd)
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
    exc_record = ExcRecord(ip=ip, cmd=cmd, result=r, exctime=current_time)
    exc_record.save()
    return render_json({'result': r, 'excresult': result})


def pushfile(request):
    ip = request.POST.get('ip')
    vulnscans.pushfiles(ip, request)
    return render_json({'result': True})
