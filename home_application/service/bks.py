# -*- coding: utf8 -*-
from blueking.component.shortcuts import get_client_by_request
import requests
import json
import time

head_data = {'Content-Type': 'application/x-www-form-urlencoded'}
retrytimes = 50
pausetime = 1


def get_bk_token(request):
    """
    获取当前登录用户token（蓝鲸）
    """
    client = get_client_by_request(request)
    app_code = client.app_code
    app_secret = client.app_secret
    bk_token = client.common_args['bk_token']
    return bk_token, app_code, app_secret


def get_user(request):
    """
    获取当前登录用户信息（蓝鲸）
    """
    app_code = get_bk_token(request)[1]
    app_secret = get_bk_token(request)[2]
    bk_token = get_bk_token(request)[0]
    try:
        purl = 'http://paas.bk.com/api/c/compapi/v2/bk_login/get_user/'
        post_data = json.dumps(
            {
                "bk_app_code": app_code,
                "bk_app_secret": app_secret,
                "bk_token": bk_token,
            }
        )
        response = requests.post(purl, data=post_data, headers=head_data)
        result = response.json()
        result = result['data']['bk_username']
        return result
    except Exception, e:
        print 'get_user error:'
        print e


def get_user_list(request):
    """
    获取所有用户列表（蓝鲸），同步至用户管理页
    """
    app_code = get_bk_token(request)[1]
    app_secret = get_bk_token(request)[2]
    bk_token = get_bk_token(request)[0]
    try:
        purl = 'http://paas.bk.com/api/c/compapi/v2/bk_login/get_all_users/'
        post_data = json.dumps(
            {
                "bk_app_code": app_code,
                "bk_app_secret": app_secret,
                "bk_token": bk_token,
                "bk_role": 0
            }
        )
        response = requests.post(purl, data=post_data, headers=head_data)
        response = response.json()
        result = []
        for i in response['data']:
            if i['bk_username']:
                result.append(i['bk_username'])
        return result
    except Exception, e:
        print 'get_user_list error:'
        print e


def get_device(request):
    """
    获取设备信息（蓝鲸）
    """
    app_code = get_bk_token(request)[1]
    app_secret = get_bk_token(request)[2]
    bk_token = get_bk_token(request)[0]
    try:
            purl = 'http://paas.bk.com/api/c/compapi/v2/cc/search_host/'
            post_data = json.dumps(
                {
                    "bk_app_code": app_code,
                    "bk_app_secret": app_secret,
                    "bk_token": bk_token,
                }
            )
            response = requests.post(purl, data=post_data, headers=head_data)
            result = response.json()
            return result['data']['info']
    
    except Exception, e:
            print 'get_device error:'
            print e


def exc_cmd(ip, cmd, request):
    """
    执行命令（蓝鲸）
    """
    app_code = get_bk_token(request)[1]
    app_secret = get_bk_token(request)[2]
    bk_token = get_bk_token(request)[0]
    try:
        purl = 'http://paas.bk.com/api/c/compapi/v2/job/fast_execute_script/'
        post_data = json.dumps(
            {
                "bk_app_code": app_code,
                "bk_app_secret": app_secret,
                "bk_token": bk_token,
                "bk_supplier_id": 0,
                "bk_biz_id": 2,
                "script_content": cmd,
                "script_timeout": 1000,
                "account": "root",
                "is_param_sensitive": 0,
                "script_type": 1,
                "ip_list": [
                    {
                        "bk_cloud_id": 0,
                        "ip": ip
                    }
                ]
            }
        )
        response = requests.post(purl, data=post_data, headers=head_data)
        result = str(response.content)
        job_instance_id = result.split('"job_instance_id": ')[1].split(',')[0]

        purl = 'http://paas.bk.com/api/c/compapi/v2/job/get_job_instance_log/'
        post_data = json.dumps(
            {
                "bk_app_code": app_code,
                "bk_app_secret": app_secret,
                "bk_token": bk_token,
                "bk_biz_id": 2,
                "job_instance_id": job_instance_id
            }
        )
        isfinished = 0
        for i in range(0, retrytimes):
            response = requests.post(purl, data=post_data, headers=head_data)
            result = str(response.content)
            status = result.split('"status": ')[1].split(',')[0]
            if status == '3':
                isfinished = 1
                result = result.split('"log_content": "')[1].split('", "exit_code"')[0].split(r'\n')
                return result
            else:
                time.sleep(pausetime)
        if isfinished == 0:
            return 'cmd_exc_timeout'
    
    except Exception, e:
        print 'exc_cmd error:'
        print e
    
        
def push_file(src_file, target_path, ip, request):
    """
    分发文件（蓝鲸）
    """
    app_code = get_bk_token(request)[1]
    app_secret = get_bk_token(request)[2]
    bk_token = get_bk_token(request)[0]
    try:
        purl = 'http://paas.bk.com/api/c/compapi/v2/job/fast_push_file/'
        post_data = json.dumps(
            {
                "bk_app_code": app_code,
                "bk_app_secret": app_secret,
                "bk_token": bk_token,
                "bk_biz_id": 2,
                "file_target_path": target_path,
                "file_source": [
                    {
                        "files": [
                            src_file
                        ],
                        "account": "root",
                        "ip_list": [
                            {
                                "bk_cloud_id": 0,
                                "ip": "172.50.20.21"
                            }
                        ]
                    }
                ],
                "ip_list": [
                    {
                        "bk_cloud_id": 0,
                        "ip": ip
                    }
                ],
                "account": "root",
            }
        )
        response = requests.post(purl, data=post_data, headers=head_data)
        result = str(response.content)
        return result
        
    except Exception, e:
        print 'push_file error:'
        print e


def syn_users(all_users, request):
    """
    同步用户信息（蓝鲸）
    """
    user_list = get_user_list(request)
    new_user = []
    del_user = []
    for i in user_list:
        if i not in all_users:
            new_user.append(i)
    for i in all_users:
        if i not in user_list:
            del_user.append(i)
    return new_user, del_user
