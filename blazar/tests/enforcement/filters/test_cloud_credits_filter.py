# Copyright (c) 2021 StackHPC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime

import ddt

from blazar import context
from blazar import enforcement
from blazar.enforcement import filters
from blazar import tests

from oslo_config import cfg


def get_fake_host(host_id):
    return {
        'id': host_id,
        'hypervisor_hostname': 'hypvsr1',
        'service_name': 'compute1',
        'vcpus': 4,
        'cpu_info': 'foo',
        'hypervisor_type': 'xen',
        'hypervisor_version': 1,
        'memory_mb': 8192,
        'local_gb': 10,
    }


def get_fake_lease(**kwargs):
    fake_lease = {
        'id': '1',
        'name': 'lease_test',
        'start_date': datetime.datetime(2014, 1, 1, 1, 23),
        'end_date': datetime.datetime(2014, 1, 1, 2, 23),
        'user_id': '111',
        'project_id': '222',
        'trust_id': '35b17138b3644e6aa1318f3099c5be68',
        'reservations': [{'resource_id': '1234',
                          'resource_type': 'physical:host'}],
        'events': [],
        'before_end_date': datetime.datetime(2014, 1, 1, 1, 53),
        'action': None,
        'status': None,
        'status_reason': None}

    if kwargs:
        fake_lease.update(kwargs)

    return fake_lease


@ddt.ddt
class CloudCreditsTestCase(tests.TestCase):
    def setUp(self):
        super(CloudCreditsTestCase, self).setUp()

        self.cfg = cfg
        self.region = 'RegionOne'
        filters.all_filters = ['CloudCreditsFilter']

        self.enforcement = enforcement.UsageEnforcement()

        cfg.CONF.set_override(
            'enabled_filters', filters.all_filters, group='enforcement')
        cfg.CONF.set_override('os_region_name', self.region)

        self.enforcement.load_filters()
        cfg.CONF.set_override('initial_allocation', 5, group='enforcement')
        self.fake_service_catalog = [
            dict(
                type='identity', endpoints=[
                    dict(
                        interface='public', region=self.region,
                        url='https://fakeauth.com')
                ]
            )
        ]

        self.ctx = context.BlazarContext(
            user_id='111', project_id='222',
            service_catalog=self.fake_service_catalog)
        self.set_context(self.ctx)

        self.fake_host_id = '1'
        self.fake_host = {
            'id': self.fake_host_id,
            'hypervisor_hostname': 'hypvsr1',
            'service_name': 'compute1',
            'vcpus': 4,
            'cpu_info': 'foo',
            'hypervisor_type': 'xen',
            'hypervisor_version': 1,
            'memory_mb': 8192,
            'local_gb': 10,
        }

        self.addCleanup(self.cfg.CONF.clear_override, 'enabled_filters',
                        group='enforcement')
        self.addCleanup(self.cfg.CONF.clear_override, 'initial_allocation',
                        group='enforcement')
        self.addCleanup(self.cfg.CONF.clear_override, 'os_region_name')

    def tearDown(self):
        super(CloudCreditsTestCase, self).tearDown()
