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

from django.conf.urls import patterns

urlpatterns = patterns(
    'home_application.views',
    (r'^$', 'home'),
    (r'^all_check/$', 'all_check_page'),
    (r'^all_vulnscan/$', 'all_vulnscan_page'),
    (r'^create_vulnscan/$', 'create_vulnscan_page'),
    (r'^vulnscan_report/$', 'vulnscan_report_page'),
    (r'^create_vulnscan_task/$', 'create_vulnscan_task'),
    (r'^get_vulnscan_tasks/$', 'get_vulnscan_tasks'),
    (r'^cmdexecute/$', 'cmdexecute'),
    (r'^pushfile/$', 'pushfile'),
    (r'^user_manage/$', 'user_manage'),
    (r'^update_user/$', 'update_user'),

    (r'^basecheck/$', 'basecheck'),
    (r'^exccmd/$', 'exccmd'),
    (r'^filedistrib/$', 'filedistrib'),
    (r'^uploadtxt/$', 'uploadtxt'),
    (r'^vulnscan/$', 'vulnscan'),

    #基线各项操作的链接映射关系
    (r'^base_check/$', 'base_check'),
    (r'^get_biz_list/$', 'get_biz_list'),
    (r'^get_host_list/$', 'get_host_list'),
    (r'^execute_job/$', 'execute_job'),
    (r'^get_result/$', 'get_result'),

    #基线操作记录页获取历史操作记录的链接
    (r'^all_check/$', 'all_check_page'),
    (r'^get_operate_logs/$', 'get_operate_logs'),
)


