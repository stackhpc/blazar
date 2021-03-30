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

from oslo_utils import timeutils

from blazar.enforcement import exceptions
from blazar.enforcement.filters import base_filter

from oslo_config import cfg
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class DateFilter(base_filter.BaseFilter):
    enforcement_opts = [
        cfg.StrOpt('max_end_date',
                   help='Maximum end date allowed for leases.'),
        cfg.StrOpt('min_start_date',
                   help='Minimum start date allowed for leases.'),
    ]

    def __init__(self, conf=None):
        super(DateFilter, self).__init__(conf=conf)
        self.min_start_date = self.conf.enforcement.min_start_date
        self.max_end_date = self.conf.enforcement.max_end_date

        if self.min_start_date:
            self.parse_date_constraint(self.min_start_date)
        if self.max_end_date:
            self.parse_date_constraint(self.max_end_date)

    def parse_date_constraint(self, datestr):
        if datestr.startswith('+'):
            now = datetime.datetime.utcnow()
            try:
                offset = datetime.timedelta(seconds=int(datestr[1:]))
            except ValueError:
                raise exceptions.DateConfigException()
            date = now + offset
        else:
            date = timeutils.parse_isotime(datestr).replace(tzinfo=None)
        return date

    def check_for_date_violation(self, context, lease_values):
        start_date = lease_values['start_date']
        end_date = lease_values['end_date']

        if self.min_start_date:
            min_start_date = self.parse_date_constraint(self.min_start_date)
            LOG.debug("min_start_date = %s", str(min_start_date))
            if start_date < min_start_date:
                raise exceptions.StartDateException(
                    start_date=str(start_date),
                    min_start_date=str(min_start_date))

        if self.max_end_date:
            max_end_date = self.parse_date_constraint(self.max_end_date)
            LOG.debug("max_end_date = %s", str(max_end_date))
            if end_date > max_end_date:
                raise exceptions.EndDateException(
                    end_date=str(end_date), max_end_date=str(max_end_date))

    def check_create(self, context, lease_values):
        self.check_for_date_violation(context, lease_values)

    def check_update(self, context, current_lease_values, new_lease_values):
        self.check_for_date_violation(context, new_lease_values)

    def on_end(self, context, lease_values):
        pass
