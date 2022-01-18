# Copyright (c) 2021 StackHPC Ltd.
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

from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client

from blazar.enforcement import exceptions
from blazar.enforcement.filters import base_filter
from blazar.utils.openstack import base

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class CloudCreditsFilter(base_filter.BaseFilter):

    enforcement_opts = [
        cfg.FloatOpt(
            'initial_allocation',
            default=0,
            help='Initial allocation amount if absent from Keystone.'),
        cfg.ListOpt(
            'cloud_credits_exempt_project_ids',
            default=[],
            help='List of project IDs exempt from cloud credit limits')
    ]

    def _create_client(self, **kwargs):
        """Create the HTTP session accessing the identity service."""
        username = kwargs.pop('username',
                              self.conf.os_admin_username)
        user_domain_name = kwargs.pop('user_domain_name',
                                      self.conf.os_admin_user_domain_name)
        project_name = kwargs.pop('project_name',
                                  self.conf.os_admin_project_name)
        password = kwargs.pop('password',
                              self.conf.os_admin_password)

        project_domain_name = kwargs.pop(
            'project_domain_name', self.conf.os_admin_project_domain_name)
        auth_url = kwargs.pop('auth_url', None)
        region_name = kwargs.pop('region_name', self.conf.os_region_name)

        if auth_url is None:
            auth_url = "%s://%s:%s" % (self.conf.os_auth_protocol,
                                       base.get_os_auth_host(self.conf),
                                       self.conf.os_auth_port)
            if self.conf.os_auth_prefix:
                auth_url += "/%s" % self.conf.os_auth_prefix
            if self.conf.os_auth_version:
                auth_url += "/%s" % self.conf.os_auth_version

        auth = v3.Password(auth_url=auth_url,
                           username=username,
                           password=password,
                           project_name=project_name,
                           user_domain_name=user_domain_name,
                           project_domain_name=project_domain_name)
        sess = session.Session(auth=auth)
        kwargs.setdefault('session', sess)
        kwargs.setdefault('region_name', region_name)
        return client.Client(**kwargs)

    def __init__(self, conf=None):
        super(CloudCreditsFilter, self).__init__(conf=conf)
        self.keystone = self._create_client()

    def _exempt(self, context):
        return (context['project_id'] in
                self.conf.enforcement.cloud_credits_exempt_project_ids)

    def get_usage(self, context):
        project_id = context['project_id']
        project = self.keystone.projects.get(project_id)
        try:
            allocation = float(project.allocation)
            used = float(project.used)
        except Exception:
            allocation = self.conf.enforcement.initial_allocation
            used = 0.0
            self.keystone.projects.update(
                project=project, allocation=allocation, used=used)
        balance = allocation - used
        LOG.debug("Balance for project %s = %f", project_id, balance)
        LOG.debug("Used for project %s = %f", project_id, used)
        return balance, used

    def update_used(self, context, used):
        project_id = context['project_id']
        project = self.keystone.projects.get(project_id)
        self.keystone.projects.update(
            project=project, used=used)
        LOG.debug("Used for project %s = %f", project_id, used)

    def lease_cost(self, lease_values, start=None):
        num_hosts = 0
        for reservation in lease_values['reservations']:
            if reservation.get('resource_type') == 'physical:host':
                allocations = reservation['allocations']
                num_hosts += len(allocations)

        start_date = start or lease_values['start_date']
        end_date = lease_values['end_date']
        lease_duration = (end_date - start_date).total_seconds()
        return (num_hosts * lease_duration / 3600.0)

    def check_for_credit_violation(self, context, node_hours):
        balance, used = self.get_usage(context)
        if balance < node_hours:
            raise exceptions.CloudCreditsException(balance=balance,
                                                   requested=node_hours)

        self.update_used(context, used + node_hours)

    def check_create(self, context, lease_values):
        if self._exempt(context):
            return

        node_hours = self.lease_cost(lease_values)
        self.check_for_credit_violation(context, node_hours)

    def check_update(self, context, current_lease_values, new_lease_values):
        if self._exempt(context):
            return

        diff = (self.lease_cost(new_lease_values) -
                self.lease_cost(current_lease_values))

        self.check_for_credit_violation(context, diff)

    def on_end(self, context, lease_values):
        if self._exempt(context):
            return

        start_date = lease_values['start_date']
        end_date = lease_values['end_date']
        _, used = self.get_usage(context)
        # TODO(priteau): Check start_lease event, in case lease failed to start
        if start_date > datetime.datetime.utcnow():
            # Refund lease in full
            node_hours = self.lease_cost(lease_values)
            self.update_used(context, used - node_hours)
        elif end_date > datetime.datetime.utcnow():
            # Calculate unused amount
            unused = self.lease_cost(
                lease_values, start=datetime.datetime.utcnow())
            self.update_used(context, used - unused)
