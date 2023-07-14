# Copyright (c) 2017 NTT.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import collections
import datetime
import json
import retrying

from novaclient import exceptions as nova_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils.strutils import bool_from_string

from blazar import context
from blazar.db import api as db_api
from blazar.db import utils as db_utils
from blazar.manager import exceptions as mgr_exceptions
from blazar.plugins import base
from blazar.plugins import instances as plugin
from blazar.plugins import oshosts
from blazar import status
from blazar.utils.openstack import exceptions as openstack_ex
from blazar.utils.openstack import nova
from blazar.utils.openstack import placement
from blazar.utils import plugins as plugins_utils

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

RESERVATION_PREFIX = 'reservation'
FLAVOR_EXTRA_SPEC = "aggregate_instance_extra_specs:" + RESERVATION_PREFIX
INSTANCE_DELETION_TIMEOUT = 10 * 60 * 1000  # 10 minutes

NONE_VALUES = ('None', 'none', None)
QUERY_TYPE_ALLOCATION = 'allocation'


class VirtualInstancePlugin(base.BasePlugin, nova.NovaClientWrapper):
    """Plugin for virtual instance resources."""

    resource_type = plugin.RESOURCE_TYPE
    title = 'Virtual Instance Plugin'
    query_options = {
        QUERY_TYPE_ALLOCATION: ['lease_id', 'reservation_id']
    }

    def __init__(self):
        super(VirtualInstancePlugin, self).__init__(
            username=CONF.os_admin_username,
            password=CONF.os_admin_password,
            user_domain_name=CONF.os_admin_user_domain_name,
            project_name=CONF.os_admin_project_name,
            project_domain_name=CONF.os_admin_project_domain_name)

        self.freepool_name = CONF.nova.aggregate_freepool_name
        self.monitor = oshosts.host_plugin.PhysicalHostMonitorPlugin()
        self.monitor.register_healing_handler(self.heal_reservations)
        self.placement_client = placement.BlazarPlacementClient()

    def filter_hosts_by_reservation(self, hosts, start_date, end_date,
                                    excludes):
        free = []
        non_free = []

        for host in hosts:
            reservations = db_utils.get_reservations_by_host_id(host['id'],
                                                                start_date,
                                                                end_date)

            if excludes:
                reservations = [r for r in reservations
                                if r['id'] not in excludes]

            if reservations == []:
                free.append({'host': host, 'reservations': []})
            elif not [r for r in reservations
                      if r['resource_type'] == oshosts.RESOURCE_TYPE]:
                non_free.append({'host': host, 'reservations': reservations})

        return free, non_free

    def _max_usages(self, reservations):
        def resource_usage_by_event(event):
            instance_reservation = event['reservation']['instance_reservation']
            resource_inventory = instance_reservation['resource_inventory']
            if resource_inventory:
                resource_inventory = json.loads(resource_inventory)
            if not resource_inventory:
                # backwards compatible with older reservations
                # that do not have a resource_inventory populated
                resource_inventory = {
                    "VCPU": instance_reservation['vcpus'],
                    "MEMORY_MB": instance_reservation['memory_mb'],
                    "DISK_GB": instance_reservation['disk_gb'],
                }
            return resource_inventory

        # Get sorted list of events for all reservations
        # that exist in the target time window
        events_list = []
        for r in reservations:
            fetched_events = db_api.event_get_all_sorted_by_filters(
                sort_key='time', sort_dir='asc',
                filters={'lease_id': r['lease_id']})
            events_list.extend([{'event': e, 'reservation': r}
                                for e in fetched_events])
        events_list.sort(key=lambda x: x['event']['time'])

        current_usage = collections.defaultdict(int)
        max_usage = collections.defaultdict(int)
        for event in events_list:
            usage = resource_usage_by_event(event)

            if event['event']['event_type'] == 'start_lease':
                LOG.debug(f"found start{event} with {usage}")
                for rc, usage_amount in usage.items():
                    current_usage[rc] += usage_amount
                    # TODO(johngarbutt) what if the max usage is
                    # actually outside the target time window?
                    if max_usage[rc] < current_usage[rc]:
                        max_usage[rc] = current_usage[rc]

            elif event['event']['event_type'] == 'end_lease':
                for rc, usage_amount in usage.items():
                    current_usage[rc] -= usage_amount

            LOG.debug(f"after {event}\nusage is: {current_usage}\n"
                      f"max is: {max_usage}")

        return max_usage

    def _get_hosts_list(self, host_info, resource_request):
        # For each host, look how many slots are available,
        # given the current list of reservations within the
        # target time window for this host

        # get high water mark of usage during all reservations
        max_usage = self._max_usages(host_info['reservations'])
        LOG.debug(f"Max usage {host_info['host']['hypervisor_hostname']} "
                  f"is {max_usage}")

        host = host_info['host']
        host_crs = db_api.host_custom_resource_get_all_per_host(host['id'])
        host_inventory = {cr['resource_class']: cr for cr in host_crs}
        if not host_inventory:
            # backwards compat for hosts added before we
            # get info from placement
            host_inventory = {
                "VCPU": dict(total=host['vcpus'],
                             allocation_ration=1.0),
                "MEMORY_MB": dict(total=host['memory_mb'],
                                  allocation_ration=1.0),
                "DISK_GB": dict(total=host['local_gb'],
                                allocation_ration=1.0),
            }
        LOG.debug(f"Inventory for {host_info['host']['hypervisor_hostname']} "
                  f"is {host_inventory}")

        # see how much room for slots we have
        hosts_list = []
        current_usage = max_usage.copy()

        def has_free_slot():
            for rc, requested in resource_request.items():
                if not requested:
                    # skip things like requests for 0 vcpus
                    continue

                host_details = host_inventory.get(rc)
                if not host_details:
                    # host doesn't have this sort of resource
                    LOG.debug(f"resource not found for {rc} for "
                              f"{host_info['host']['hypervisor_hostname']}")
                    return False
                usage = current_usage[rc]

                if requested > host_details["max_unit"]:
                    # requested more than the max allowed by this host
                    LOG.debug(f"resource not found for {rc} for "
                              f"{host_info['host']['hypervisor_hostname']}")
                    return False

                capacity = ((host_details["total"] - host_details["reserved"])
                            * host_details["allocation_ratio"])
                LOG.debug(f"Capacity is {capacity} for {rc} for "
                          f"{host_info['host']['hypervisor_hostname']}")
                return (usage + requested) <= capacity

        while (has_free_slot()):
            hosts_list.append(host)
            for rc, requested in resource_request.items():
                current_usage[rc] += requested

        LOG.debug(f"For host {host_info['host']['hypervisor_hostname']} "
                  f"we have {len(hosts_list)} slots.")
        return hosts_list

    def allocation_candidates(self, reservation):
        self._populate_values_with_flavor_info(reservation)
        return self.pickup_hosts(None, reservation)['added']

    def list_allocations(self, query):
        hosts_id_list = [h['id'] for h in db_api.host_list()]
        options = self.get_query_options(query, QUERY_TYPE_ALLOCATION)

        hosts_allocations = self.query_allocations(hosts_id_list, **options)
        return [{"resource_id": host, "reservations": allocs}
                for host, allocs in hosts_allocations.items()]

    def query_allocations(self, hosts, lease_id=None, reservation_id=None):
        """Return dict of host and its allocations.

        The list element forms
        {
          'host-id': [
                       {
                         'lease_id': lease_id,
                         'id': reservation_id
                         'start_date': lease_start_date,
                         'end_date': lease_end_date,
                       },
                     ]
        }.
        """
        start = datetime.datetime.utcnow()
        end = datetime.date.max

        # To reduce overhead, this method only executes one query
        # to get the allocation information
        reservations = db_utils.get_reservation_allocations_by_host_ids(
            hosts, start, end, lease_id, reservation_id)
        host_allocs = {h: [] for h in hosts}
        attributes_to_copy = ["id", "lease_id", "start_date", "end_date"]
        for reservation in reservations:
            for host_id in reservation['host_ids']:
                if host_id in host_allocs.keys():
                    host_allocs[host_id].append({
                        k: v for k, v in reservation.items()
                        if k in attributes_to_copy})
        return host_allocs

    def query_available_hosts(self, cpus=None, memory=None, disk=None,
                              resource_properties=None,
                              resource_inventory=None,
                              resource_traits=None,
                              start_date=None, end_date=None,
                              excludes_res=None):
        """Returns a list of available hosts for a reservation.

        The list is in the order of reserved hosts to free hosts.

        1. filter hosts that have a spec enough to accommodate the flavor
        2. categorize hosts into hosts with and without allocation
           at the reservation time frame
        3. filter out hosts used by physical host reservation from
           allocate_host
        4. filter out hosts that can't accommodate the flavor at the
           time frame because of other reservations
        """
        flavor_definitions = [
            'and',
            [">=", "$vcpus", str(cpus)],
            [">=", "$memory_mb", str(memory)],
            [">=", "$local_gb", str(disk)],
            ]

        filters = plugins_utils.convert_requirements(flavor_definitions)

        if resource_properties:
            filters += plugins_utils.convert_requirements(resource_properties)

        LOG.debug(f"Filters are: {filters}")
        hosts = db_api.reservable_host_get_all_by_queries(filters)

        LOG.debug(f"Found some hosts from db: {hosts}")

        # Remove hosts without the required custom resources
        resource_extras = resource_inventory.copy()
        # TODO(johngarbutt) can we remove vcpus,disk,etc as a special case?
        del resource_extras["VCPU"]
        del resource_extras["MEMORY_MB"]
        del resource_extras["DISK_GB"]
        if resource_extras:
            cr_hosts = []
            for host in hosts:
                host_crs = db_api.host_custom_resource_get_all_per_host(
                        host['id'])
                host_inventory = {cr['resource_class']: cr for cr in host_crs}
                host_is_ok = False
                for rc, request in resource_extras.items():
                    host_inventory = host_inventory[rc]
                    host_max = host_inventory['max_unit']
                    if request <= host_max:
                        host_is_ok = True
                    else:
                        host_is_ok = False
                        LOG.debug(f"Filter out becase of {rc} for {host}")
                        break
                if host_is_ok:
                    cr_hosts.append(host)
            hosts = cr_hosts

        LOG.debug(f"Filtered hosts by resource classes: {hosts}")

        if resource_traits:
            # TODO(johngarbutt): filter resource traits!
            pass

        # Look for all reservations that match our time window
        # and group that by host
        free_hosts, reserved_hosts = self.filter_hosts_by_reservation(
            hosts,
            start_date - datetime.timedelta(minutes=CONF.cleaning_time),
            end_date + datetime.timedelta(minutes=CONF.cleaning_time),
            excludes_res)

        # See how many free slots available per host
        available_hosts = []
        for host_info in (reserved_hosts + free_hosts):
            hosts_list = self._get_hosts_list(host_info, resource_inventory)
            available_hosts.extend(hosts_list)

        return available_hosts

    def pickup_hosts(self, reservation_id, values):
        """Returns lists of host ids to add/remove.

        This function picks up available hosts, calculates the difference from
        old reservations and returns a dict of a list of host ids to add
        and remove keyed by "added" or "removed".

        Note that the lists allow duplicated host ids for `affinity=True`
        cases.

        :raises: NotEnoughHostsAvailable exception if there are not enough
                 hosts available for the request
        """
        req_amount = values['amount']
        affinity = bool_from_string(values['affinity'], default=None)

        # TODO need to check for custom resource requests!
        resource_inventory = json.loads(values['resource_inventory'])
        # TODO need to check traits as well!

        query_params = {
            'cpus': resource_inventory['VCPU'],
            'memory': resource_inventory['MEMORY_MB'],
            'disk': resource_inventory['DISK_GB'],
            'resource_properties': values['resource_properties'],
            'resource_inventory': resource_inventory,
            'start_date': values['start_date'],
            'end_date': values['end_date']
            }

        old_allocs = db_api.host_allocation_get_all_by_values(
            reservation_id=reservation_id)
        if old_allocs:
            # This is a path for *update* reservation. Add the specific
            # query param not to consider resources reserved by existing
            # reservations to update
            query_params['excludes_res'] = [reservation_id]

        new_hosts = self.query_available_hosts(**query_params)

        old_host_id_list = [h['compute_host_id'] for h in old_allocs]
        candidate_id_list = [h['id'] for h in new_hosts]

        # Build `new_host_id_list`. Note that we'd like to pick up hosts in
        # the following order of priority:
        #  1. hosts reserved by the reservation to update
        #  2. hosts with reservations followed by hosts without reservations
        # Note that the `candidate_id_list` has already been ordered
        # satisfying the second requirement.
        LOG.debug(f"Old hosts: {candidate_id_list}")
        LOG.debug(f"Found candidates: {candidate_id_list}")
        if affinity:
            host_id_map = collections.Counter(candidate_id_list)
            available = {k for k, v in host_id_map.items() if v >= req_amount}
            if not available:
                raise mgr_exceptions.NotEnoughHostsAvailable()
            new_host_ids = set(old_host_id_list) & available
            if new_host_ids:
                # (priority 1) This is a path for update reservation. We pick
                # up a host from hosts reserved by the reservation to update.
                new_host_id = new_host_ids.pop()
            else:
                # (priority 2) This is a path both for update and for new
                # reservation. We pick up hosts with some other reservations
                # if possible and otherwise pick up hosts without any
                # reservation. We can do so by considering the order of the
                # `candidate_id_list`.
                for host_id in candidate_id_list:
                    if host_id in available:
                        new_host_id = host_id
                        break
            new_host_id_list = [new_host_id] * req_amount
        else:
            # Hosts that can accommodate but don't satisfy priority 1
            _, possible_host_list = plugins_utils.list_difference(
                old_host_id_list, candidate_id_list)
            # Hosts that satisfy priority 1
            new_host_id_list, _ = plugins_utils.list_difference(
                candidate_id_list, possible_host_list)
            if affinity is False:
                # Eliminate the duplication
                new_host_id_list = list(set(new_host_id_list))
            for host_id in possible_host_list:
                if (affinity is False) and (host_id in new_host_id_list):
                    # Eliminate the duplication
                    continue
                new_host_id_list.append(host_id)
            if len(new_host_id_list) < req_amount:
                raise mgr_exceptions.NotEnoughHostsAvailable()
            while len(new_host_id_list) > req_amount:
                new_host_id_list.pop()

        # Calculate the difference from the existing reserved host
        removed_host_ids, added_host_ids = plugins_utils.list_difference(
            old_host_id_list, new_host_id_list)

        return {'added': added_host_ids, 'removed': removed_host_ids}

    def _create_flavor(self, reservation_id, vcpus, memory, disk, group_id,
                       source_flavor=None):
        flavor_details = {
            'flavorid': reservation_id,
            'name': RESERVATION_PREFIX + ":" + reservation_id,
            'vcpus': vcpus,
            'ram': memory,
            'disk': disk,
            'is_public': False
            }
        reserved_flavor = self.nova.nova.flavors.create(**flavor_details)

        # Set extra specs to the flavor
        rsv_id_rc_format = reservation_id.upper().replace("-", "_")
        reservation_rc = "resources:CUSTOM_RESERVATION_" + rsv_id_rc_format
        extra_specs = {
            FLAVOR_EXTRA_SPEC: reservation_id,
            reservation_rc: "1"
            }
        if group_id:
            extra_specs["affinity_id"] = group_id

        # Copy across any extra specs from the source flavor
        # while being sure not to overide the ones used above
        if source_flavor:
            source_flavor = json.loads(source_flavor)
        if source_flavor:
            extra_specs["blazar_copy_from_id"] = source_flavor["id"]
            extra_specs["blazar_copy_from_name"] = source_flavor["name"]
            source_extra_specs = source_flavor["extra_specs"]
            for key, value in source_extra_specs.items():
                if key not in extra_specs.keys():
                    extra_specs[key] = value

        LOG.debug(extra_specs)
        reserved_flavor.set_keys(extra_specs)

        return reserved_flavor

    def _create_resources(self, inst_reservation):
        reservation_id = inst_reservation['reservation_id']

        ctx = context.current()
        #user_client = nova.NovaClientWrapper()
        #reserved_group = user_client.nova.server_groups.create(
        #    RESERVATION_PREFIX + ':' + reservation_id,
        #    'affinity' if inst_reservation['affinity'] else 'anti-affinity'
        #    )
        # TODO this should be optional!!
        reserved_group_id = None

        # TODO(johngarbutt): traits and pci alias!?
        resources = []

        # TODO get PCPUs and more!
        if not inst_reservation['vcpus']:
            inst_reservation['vcpus'] = 1
        reserved_flavor = self._create_flavor(reservation_id,
                                              inst_reservation['vcpus'],
                                              inst_reservation['memory_mb'],
                                              inst_reservation['disk_gb'],
                                              reserved_group_id,
                                              inst_reservation['source_flavor'])

        pool = nova.PlacementReservationPool()
        pool_metadata = {
            RESERVATION_PREFIX: reservation_id,
            'filter_tenant_id': ctx.project_id,
            'affinity_id': reserved_group_id
            }
        agg = pool.create(name=reservation_id, metadata=pool_metadata)

        self.placement_client.create_reservation_class(reservation_id)

        return reserved_flavor, reserved_group_id, agg

    def cleanup_resources(self, instance_reservation):
        def check_and_delete_resource(client, id):
            try:
                client.delete(id)
            except nova_exceptions.NotFound:
                pass

        reservation_id = instance_reservation['reservation_id']

        check_and_delete_resource(self.nova.nova.server_groups,
                                  instance_reservation['server_group_id'])
        check_and_delete_resource(self.nova.nova.flavors, reservation_id)
        # TODO(johngarbutt): should we remove all aggregates in placement here?
        check_and_delete_resource(nova.PlacementReservationPool(), reservation_id)

    def update_resources(self, reservation_id):
        """Updates reserved resources in Nova.

        This method updates reserved resources in Compute service. If the
        reservation is in active status, it adds new allocated hosts into
        a reserved aggregate. If the reservation is not started yet, it
        updates a reserved flavor.
        """
        reservation = db_api.reservation_get(reservation_id)

        if reservation['status'] == 'active':
            pool = nova.PlacementReservationPool()

            # Dict of number of instances to reserve on a host keyed by the
            # host id
            allocation_map = collections.defaultdict(lambda: 0)
            for allocation in db_api.host_allocation_get_all_by_values(
                    reservation_id=reservation['id']):
                host_id = allocation['compute_host_id']
                allocation_map[host_id] += 1

            for host_id, num in allocation_map.items():
                host = db_api.host_get(host_id)
                try:
                    pool.add_computehost(reservation, host)
                except mgr_exceptions.AggregateAlreadyHasHost:
                    pass
                except nova_exceptions.ClientException:
                    err_msg = ('Fail to add host %s to aggregate %s.'
                               % (host, reservation['aggregate_id']))
                    raise mgr_exceptions.NovaClientError(err_msg)
                self.placement_client.update_reservation_inventory(
                    host['hypervisor_hostname'], reservation['id'], num)
        else:
            try:
                self.nova.nova.flavors.delete(reservation['id'])
                # TODO(johngarbutt): get inventory?
                resource_inventory = ""
                resources = []
                for req in resource_inventory.split(','):
                    resource_class, amount = req.split(':')
                    resources.append({'name': resource_class, 'value': amount})
                # TODO(johngarbutt): traits and pci alias!?
                self._create_flavor(reservation['id'],
                                    reservation['vcpus'],
                                    reservation['memory_mb'],
                                    reservation['disk_gb'],
                                    reservation['server_group_id'],
                                    reservation['source_flavor'])
            except nova_exceptions.ClientException:
                LOG.exception("Failed to update Nova resources "
                              "for reservation %s", reservation['id'])
                raise mgr_exceptions.NovaClientError()

    def _check_missing_reservation_params(self, values):
        marshall_attributes = set(['amount', 'affinity'])
        # TODO(johngarbutt): do we want a config to require
        # flavor_id and reject other requests, or an enforcer?
        # if flavor_id is present, we ignore the components
        # if flavor_id is not present, we require the components
        if "flavor_id" not in values.keys():
            marshall_attributes = marshall_attributes.union(
                ['vcpus', 'memory_mb', 'disk_gb', 'resource_properties'])

        missing_attr = marshall_attributes - set(values.keys())
        if missing_attr:
            raise mgr_exceptions.MissingParameter(param=','.join(missing_attr))

    def _validate_reservation_params(self, values):
        if 'amount' in values:
            try:
                values['amount'] = strutils.validate_integer(
                    values['amount'], "amount", 1, db_api.DB_MAX_INT)
            except ValueError as e:
                raise mgr_exceptions.MalformedParameter(str(e))

        if 'affinity' in values:
            if (values['affinity'] not in NONE_VALUES and
                    not strutils.is_valid_boolstr(values['affinity'])):
                raise mgr_exceptions.MalformedParameter(
                    param='affinity (must be a bool value or None)')

    def _populate_values_with_flavor_info(self, values):
        if "resource_inventory" in values.keys():
            return

        # Look up flavor to get the reservation details
        flavor_id = values.get('flavor_id')

        # TODO(johngarbutt) hack to get flavor in via horizon!!
        if not flavor_id and values['resource_properties'] and "flavor" in values['resource_properties']:
            from oslo_serialization import jsonutils
            requirements = jsonutils.loads(values['resource_properties'])
            flavor_id = requirements[1]
            values['resource_properties'] = ""

        resource_inventory = {}
        resource_traits = {}
        source_flavor = {}

        if not flavor_id:
            # create resource requests from legacy values, if present
            resource_inventory["VCPU"] = values.get('vcpus', 0)
            resource_inventory["MEMORY_MB"] = values.get('memory_mb', 0)
            resource_inventory["DISK_GB"] = values.get('disk_gb', 0)

        else:
            user_client = nova.NovaClientWrapper()
            flavor = user_client.nova.nova.flavors.get(flavor_id)
            source_flavor = flavor.to_dict()
            # TODO(johngarbutt): use newer api to get this above
            source_flavor["extra_specs"] = flavor.get_keys()

            # Populate the legacy instance reservation fields
            # And override what the user specified, if anything
            values['vcpus'] = int(source_flavor['vcpus'])
            values['memory_mb'] = int(source_flavor['ram'])
            values['disk_gb'] = (
                int(source_flavor['disk']) +
                int(source_flavor['OS-FLV-EXT-DATA:ephemeral']))

            # add default resource requests
            resource_inventory["VCPU"] = values['vcpus']
            resource_inventory["MEMORY_MB"] = values['memory_mb']
            resource_inventory["DISK_GB"] = values['disk_gb']

            # Check for PCPUs
            hw_cpu_policy = source_flavor['extra_specs'].get("hw:cpu_policy")
            if hw_cpu_policy == "dedicated":
                resource_inventory["PCPU"] = source_flavor['vcpus']
                resource_inventory["VCPU"] = 0

            # Check for traits and extra resources
            for key, value in source_flavor['extra_specs'].items():
                if key.startswith("trait:"):
                    trait = key.split(":")[1]
                    if value == "required":
                        resource_traits[trait] = "required"
                    elif value == "forbidden":
                        resource_traits[trait] = "forbidden"

                if key.startswith("resource:"):
                    rc = key.split(":")[1]
                    values[rc] = int(key)

        values["resource_inventory"] = json.dumps(resource_inventory)
        values["resource_traits"] = json.dumps(resource_traits)
        values["source_flavor"] = json.dumps(source_flavor)

        LOG.debug(values)

    def reserve_resource(self, reservation_id, values):
        self._check_missing_reservation_params(values)
        self._validate_reservation_params(values)

        # when user specifies a flavor,
        # populate values from the flavor
        self._populate_values_with_flavor_info(values)

        hosts = self.pickup_hosts(reservation_id, values)

        # TODO(johngarbutt): need the flavor resource_inventory stuff here
        instance_reservation_val = {
            'reservation_id': reservation_id,
            'vcpus': values['vcpus'],
            'memory_mb': values['memory_mb'],
            'disk_gb': values['disk_gb'],
            'amount': values['amount'],
            'affinity': bool_from_string(values['affinity'], default=None),
            'resource_properties': values['resource_properties'],
            'resource_inventory': values['resource_inventory'],
            'resource_traits': values['resource_traits'],
            'source_flavor': values['source_flavor'],
            }
        instance_reservation = db_api.instance_reservation_create(
            instance_reservation_val)

        for host_id in hosts['added']:
            db_api.host_allocation_create({'compute_host_id': host_id,
                                          'reservation_id': reservation_id})

        try:
            flavor, group_id, pool = self._create_resources(instance_reservation)
        except nova_exceptions.ClientException:
            LOG.exception("Failed to create Nova resources "
                          "for reservation %s", reservation_id)
            self.cleanup_resources(instance_reservation)
            raise mgr_exceptions.NovaClientError()

        db_api.instance_reservation_update(instance_reservation['id'],
                                           {'flavor_id': flavor.id,
                                            'server_group_id': group_id,
                                            'aggregate_id': pool.id})

        return instance_reservation['id']

    def update_host_allocations(self, added, removed, reservation_id):
        allocations = db_api.host_allocation_get_all_by_values(
            reservation_id=reservation_id)

        removed_allocs = []
        for host_id in removed:
            for allocation in allocations:
                if allocation['compute_host_id'] == host_id:
                    removed_allocs.append(allocation['id'])
                    break

        # TODO(tetsuro): It would be nice to have something like
        # db_api.host_allocation_replace() to process the following
        # deletion and addition in *one* DB transaction.
        for alloc_id in removed_allocs:
            db_api.host_allocation_destroy(alloc_id)

        for added_host in added:
            db_api.host_allocation_create({'compute_host_id': added_host,
                                           'reservation_id': reservation_id})

    def update_reservation(self, reservation_id, new_values):
        """Updates an instance reservation with requested parameters.

        This method allows users to update an instance reservation under the
        following conditions.
        - If an instance reservation has not started yet
             - vcpus, memory_mb disk_gb and amount can be updateable unless
               Blazar can accommodate the new request.
        - If an instance reservation has already started
             - only amount is increasable.
        """
        self._validate_reservation_params(new_values)

        reservation = db_api.reservation_get(reservation_id)
        lease = db_api.lease_get(reservation['lease_id'])

        updatable = ['vcpus', 'memory_mb', 'disk_gb', 'affinity', 'amount',
                     'resource_properties']
        if (not any([k in updatable for k in new_values.keys()])
                and new_values['start_date'] >= lease['start_date']
                and new_values['end_date'] <= lease['end_date']):
            # no update because of just shortening the reservation time
            return

        if (reservation['status'] == 'active' and
                any([k in updatable[:-1] for k in new_values.keys()])):
            msg = "An active reservation only accepts to update amount."
            raise mgr_exceptions.InvalidStateUpdate(msg)

        if reservation['status'] == 'error':
            msg = "An error reservation doesn't accept an updating request."
            raise mgr_exceptions.InvalidStateUpdate(msg)

        if new_values.get('affinity', None):
            new_values['affinity'] = bool_from_string(new_values['affinity'],
                                                      default=None)

        for key in updatable:
            if key not in new_values:
                new_values[key] = reservation[key]

        changed_hosts = self.pickup_hosts(reservation_id, new_values)

        if (reservation['status'] == 'active'
                and len(changed_hosts['removed']) > 0):
            err_msg = ("Instance reservation doesn't allow to reduce/replace "
                       "reserved instance slots when the reservation is in "
                       "active status.")
            raise mgr_exceptions.CantUpdateParameter(err_msg)

        db_api.instance_reservation_update(
            reservation['resource_id'],
            {key: new_values[key] for key in updatable})

        self.update_host_allocations(changed_hosts['added'],
                                     changed_hosts['removed'],
                                     reservation_id)
        self.update_resources(reservation_id)

    def on_start(self, resource_id):
        ctx = context.current()
        instance_reservation = db_api.instance_reservation_get(resource_id)
        reservation_id = instance_reservation['reservation_id']

        try:
            self.nova.flavor_access.add_tenant_access(reservation_id,
                                                      ctx.project_id)
        except nova_exceptions.ClientException:
            LOG.info('Failed to associate flavor %(reservation_id)s '
                     'to project %(project_id)s',
                     {'reservation_id': reservation_id,
                      'project_id': ctx.project_id})
            raise mgr_exceptions.EventError()

        pool = nova.PlacementReservationPool()

        # Dict of number of instances to reserve on a host keyed by the
        # host id
        allocation_map = collections.defaultdict(lambda: 0)
        for allocation in db_api.host_allocation_get_all_by_values(
                reservation_id=reservation_id):
            host_id = allocation['compute_host_id']
            allocation_map[host_id] += 1

        for host_id, num in allocation_map.items():
            host = db_api.host_get(host_id)
            pool.add_computehost(instance_reservation, host)
            self.placement_client.update_reservation_inventory(
                host['hypervisor_hostname'], reservation_id, num)

    def on_end(self, resource_id):
        instance_reservation = db_api.instance_reservation_get(resource_id)
        reservation_id = instance_reservation['reservation_id']
        ctx = context.current()

        try:
            self.nova.flavor_access.remove_tenant_access(
                reservation_id, ctx.project_id)
        except nova_exceptions.NotFound:
            pass

        hostnames = []
        allocations = db_api.host_allocation_get_all_by_values(
            reservation_id=reservation_id)
        for allocation in allocations:
            host = db_api.host_get(allocation['compute_host_id'])
            pool = nova.PlacementReservationPool()
            pool.remove_computehost(instance_reservation, host)
            db_api.host_allocation_destroy(allocation['id'])
            hostnames.append(host['hypervisor_hostname'])

        for server in self.nova.servers.list(search_opts={
                'flavor': reservation_id,
                'all_tenants': 1}, detailed=False):
            try:
                self.nova.servers.delete(server=server)
            except nova_exceptions.NotFound:
                LOG.info("Could not find server '%s', may have been deleted "
                         "concurrently.", server.id)
            except Exception as e:
                LOG.exception("Failed to delete server '%s': %s.", server.id,
                              str(e))

        # We need to check the deletion is complete before deleting the
        # reservation inventory. See the bug #1813252 for details.
        if not self._check_server_deletion(reservation_id):
            LOG.error('Timed out while deleting servers on reservation %s',
                      reservation_id)
            raise mgr_exceptions.ServerDeletionTimeout()

        self.cleanup_resources(instance_reservation)

        for host_name in hostnames:
            try:
                self.placement_client.delete_reservation_inventory(
                    host_name, reservation_id)
            except openstack_ex.ResourceProviderNotFound:
                pass
        self.placement_client.delete_reservation_class(reservation_id)

    @retrying.retry(stop_max_delay=INSTANCE_DELETION_TIMEOUT,
                    wait_fixed=5000,  # 5 seconds interval
                    retry_on_result=lambda x: x is False)
    def _check_server_deletion(self, reservation_id):
        servers = self.nova.servers.list(search_opts={
            'flavor': reservation_id, 'all_tenants': 1}, detailed=False)
        if servers:
            LOG.info('Waiting to delete servers: %s ', servers)
            return False
        return True

    def heal_reservations(self, failed_resources, interval_begin,
                          interval_end):
        """Heal reservations which suffer from resource failures.

        :param failed_resources: failed resources
        :param interval_begin: start date of the period to heal.
        :param interval_end: end date of the period to heal.
        :return: a dictionary of {reservation id: flags to update}
                 e.g. {'de27786d-bd96-46bb-8363-19c13b2c6657':
                       {'missing_resources': True}}
        """
        reservation_flags = collections.defaultdict(dict)

        host_ids = [h['id'] for h in failed_resources]
        reservations = db_utils.get_reservations_by_host_ids(
            host_ids, interval_begin, interval_end)

        for reservation in reservations:
            if reservation['resource_type'] != plugin.RESOURCE_TYPE:
                continue

            if self._heal_reservation(reservation, host_ids):
                if reservation['status'] == status.reservation.ACTIVE:
                    reservation_flags[reservation['id']].update(
                        {'resources_changed': True})
            else:
                reservation_flags[reservation['id']].update(
                    {'missing_resources': True})

        return reservation_flags

    def _heal_reservation(self, reservation, host_ids):
        """Allocate alternative host(s) for the given reservation.

        :param reservation: A reservation that has allocations to change
        :param host_ids: Failed host ids
        :return: True if all the allocations in the given reservation
                 are successfully allocated
        """
        lease = db_api.lease_get(reservation['lease_id'])

        ret = True
        allocations = [
            alloc for alloc in reservation['computehost_allocations']
            if alloc['compute_host_id'] in host_ids]

        if reservation['affinity']:
            old_host_id = allocations[0]['compute_host_id']
            new_host_id = self._select_host(reservation, lease)

            self._pre_reallocate(reservation, old_host_id)

            if new_host_id is None:
                for allocation in allocations:
                    db_api.host_allocation_destroy(allocation['id'])
                LOG.warning('Could not find alternative host for '
                            'reservation %s (lease: %s).',
                            reservation['id'], lease['name'])
                ret = False
            else:
                for allocation in allocations:
                    db_api.host_allocation_update(
                        allocation['id'], {'compute_host_id': new_host_id})
                self._post_reallocate(
                    reservation, lease, new_host_id, len(allocations))

        else:
            new_host_ids = []
            for allocation in allocations:
                old_host_id = allocation['compute_host_id']
                new_host_id = self._select_host(reservation, lease)

                self._pre_reallocate(reservation, old_host_id)

                if new_host_id is None:
                    db_api.host_allocation_destroy(allocation['id'])
                    LOG.warning('Could not find alternative host for '
                                'reservation %s (lease: %s).',
                                reservation['id'], lease['name'])
                    ret = False
                    continue

                db_api.host_allocation_update(
                    allocation['id'], {'compute_host_id': new_host_id})
                new_host_ids.append(new_host_id)

            for new_host, num in collections.Counter(new_host_ids).items():
                self._post_reallocate(reservation, lease, new_host, num)

        return ret

    def _select_host(self, reservation, lease):
        """Returns the alternative host id or None if not found."""
        values = {}
        values['start_date'] = max(datetime.datetime.utcnow(),
                                   lease['start_date'])
        values['end_date'] = lease['end_date']
        specs = ['vcpus', 'memory_mb', 'disk_gb', 'affinity', 'amount',
                 'resource_properties']
        for key in specs:
            values[key] = reservation[key]
        try:
            changed_hosts = self.pickup_hosts(reservation['id'], values)
        except mgr_exceptions.NotEnoughHostsAvailable:
            return None
        # We should get at least one host to add because the old host can't
        # be in the candidates.
        return changed_hosts['added'][0]

    def _pre_reallocate(self, reservation, host_id):
        """Delete the reservation inventory/aggregates for the host."""
        pool = nova.PlacementReservationPool()
        # Remove the failed host from the aggregate.
        if reservation['status'] == status.reservation.ACTIVE:
            host = db_api.host_get(host_id)
            pool.remove_computehost(reservation, host)
            try:
                self.placement_client.delete_reservation_inventory(
                    host['hypervisor_hostname'], reservation['id'])
            except openstack_ex.ResourceProviderNotFound:
                pass

    def _post_reallocate(self, reservation, lease, host_id, num):
        """Add the reservation inventory/aggregates for the host."""
        pool = nova.PlacementReservationPool()
        if reservation['status'] == status.reservation.ACTIVE:
            # Add the alternative host into the aggregate.
            new_host = db_api.host_get(host_id)
            pool.add_computehost(reservation, new_host)
            # Here we use "additional=True" not to break the existing
            # inventory(allocations) on the new host
            self.placement_client.update_reservation_inventory(
                new_host['hypervisor_hostname'], reservation['id'], num,
                additional=True)
        LOG.warning('Resource changed for reservation %s (lease: %s).',
                    reservation['id'], lease['name'])

    def _get_extra_capabilities(self, host_id):
        extra_capabilities = {}
        raw_extra_capabilities = (
            db_api.host_extra_capability_get_all_per_host(host_id))
        for capability, capability_name in raw_extra_capabilities:
            key = capability_name
            extra_capabilities[key] = capability.capability_value
        return extra_capabilities

    def get(self, host_id):
        host = db_api.host_get(host_id)
        extra_capabilities = self._get_extra_capabilities(host_id)
        if host is not None and extra_capabilities:
            res = host.copy()
            res.update(extra_capabilities)
            return res
        else:
            return host
