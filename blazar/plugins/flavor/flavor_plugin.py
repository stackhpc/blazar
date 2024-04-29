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

from blazar.plugins import base
from blazar.plugins import flavor as plugin

QUERY_TYPE_ALLOCATION = 'allocation'


class FlavorPlugin(base.BasePlugin):
    """Plugin for nova flavor based servers."""

    resource_type = plugin.RESOURCE_TYPE
    title = 'Plugin for nova flavor based server reservations'
    description = 'Reserve resources modeled by Nova flavors.'
    title = 'Virtual Instance Plugin'
    query_options = {
        QUERY_TYPE_ALLOCATION: ['lease_id', 'reservation_id']
    }

    def get(self, resource_id):
        return None

    def reserve_resource(self, reservation_id, values):
        return None

    def list_allocations(self, query, detail=False):
        pass

    def query_allocations(self, resource_id_list, lease_id=None,
                          reservation_id=None):
        return None

    def allocation_candidates(self, lease_values):
        return None

    def update_reservation(self, reservation_id, values):
        return None

    def on_start(self, resource_id):
        return None

    def on_end(self, resource_id):
        return None
