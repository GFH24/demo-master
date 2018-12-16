# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云(BlueKing) available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
"""

from django.db import models
import time
from common.log import logger


class ExcRecord(models.Model):
	ip = models.CharField(u"IP", max_length=20)
	cmd = models.CharField(u"CMD", max_length=100)
	result = models.CharField(u"RESULT", max_length=10)
	exctime = models.CharField(u"EXCTIME", max_length=50)


class UserInfo(models.Model):
	username = models.CharField(u'UserName', max_length=30)
	cname = models.CharField(u'UserName', max_length=30)
	rolename = models.CharField(u'RoleName', max_length=20)


class LoginInfo(models.Model):
	username = models.CharField(u'UserName', max_length=30)
	date = models.CharField(u'Date', max_length=30)
	bk_token = models.CharField(u'Date', max_length=100)


#存储漏扫任务数据
class VulnScanTasks(models.Model):
    vulnscan_taskname = models.CharField(u'漏扫任务名称',max_length=50)
    version = models.CharField(u'工具版本',max_length=10)
    supplier = models.CharField(u'扫描工具',max_length=20)
    iplist = models.CharField(u'扫描目标',max_length=1000)
    creator = models.CharField(u'创建人',max_length=20)
    create_time = models.DateTimeField(u'创建时间')
    #finish_time = models.DateTimeField(u'结束时间')
    soc_task_name = models.CharField(u'SOC漏扫任务名称',max_length=50)
    soc_task_resultid = models.CharField(u'SOC任务ID',max_length=50)
    soc_task_status = models.CharField(u'SOC任务状态',max_length=10)
    soc_task_progress = models.CharField(u'SOC任务进度',max_length=10)
    has_report = models.BooleanField(u"是否已出报告", default=False)
    
    def __unicode__(self):
        return self.vulnscan_taskname

    class Meta:
        verbose_name = u"漏扫任务"

class LogsManager(models.Manager):
    def save_data(self, data):
        """
        保存操作记录数据
        """
        try:
            Logs.objects.create(
                ip=data[0],
                operator=data[1],
                operation=data[2],
                operate_result=data[3],
                operate_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            )
            result = {'result': True, 'message': u"保存成功"}
        except Exception, e:
            logger.error(u"save_data %s" % e)
            result = {'result': False, 'message': u"保存失败, %s" % e}
        return result


class Logs(models.Model):
    """
    存储历史操作记录数据
    """
    ip = models.CharField('ip', max_length=64, blank=True, null=True)
    operator = models.CharField(u'操作人', max_length=64)
    operation = models.CharField(u'执行命令', max_length=64)
    operate_result = models.BooleanField(u'执行结果')
    operate_time =  models.DateTimeField(u"执行时间")
    objects = LogsManager()

    def __unicode__(self):
        return self.ip

    class Meta:
        verbose_name = u"历史操作记录"
