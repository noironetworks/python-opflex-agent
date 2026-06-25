#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import hashlib
import os
import uuid


SNAT_FILE_EXTENSION = 'snat'
SNAT_FILE_FORMAT = "%s." + SNAT_FILE_EXTENSION
SERVICE_FILE_EXTENSION = 'service'
SERVICE_FILE_FORMAT = "%s." + SERVICE_FILE_EXTENSION


class DistributedSnatManager(object):
    """Distributed SNAT state manager for endpoint-based rendering.

    This class intentionally keeps logic minimal and reuses the existing
    endpoint manager file writer/delete helpers for all filesystem updates.
    """

    def __init__(self, snats_dir, service_dir, write_fn, delete_fn):
        self.snat_mapping_file = os.path.join(snats_dir, SNAT_FILE_FORMAT)
        self.service_mapping_file = os.path.join(service_dir,
                                                 SERVICE_FILE_FORMAT)
        self._write_file = write_fn
        self._delete_file = delete_fn

        # snat_uuid -> set(endpoint_uuid)
        self._snat_to_endpoints = {}
        # endpoint_uuid -> set(snat_uuid)
        self._endpoint_to_snats = {}
        # snat_uuid -> {snat_ip,start,end}
        self._snat_to_ip_range = {}

    def sync_endpoint(self, endpoint_uuid, dist_snat_entries, ep_mapping):
        old_snats = self._endpoint_to_snats.get(endpoint_uuid, set())
        new_snats = set()

        for entry in (dist_snat_entries or []):
            snat_uuid = entry.get('uuid')
            if not snat_uuid:
                continue

            new_snats.add(snat_uuid)
            self._snat_to_endpoints.setdefault(snat_uuid, set()).add(
                endpoint_uuid)
            self._snat_to_ip_range[snat_uuid] = {
                'snat_ip': entry.get('snat_ip'),
                'start': entry.get('start'),
                'end': entry.get('end')}

            if entry.get('snat_file'):
                self._write_file(snat_uuid, entry['snat_file'],
                                 self.snat_mapping_file)
            if entry.get('service_file'):
                self._write_file(snat_uuid, entry['service_file'],
                                 self.service_mapping_file)

        for snat_uuid in (old_snats - new_snats):
            self._discard_snat_for_endpoint(endpoint_uuid, snat_uuid)

        if new_snats:
            ep_mapping['snat-uuids'] = sorted(new_snats)
            self._endpoint_to_snats[endpoint_uuid] = new_snats
        else:
            ep_mapping.pop('snat-uuids', None)
            self._endpoint_to_snats.pop(endpoint_uuid, None)

    def cleanup_port(self, port_id):
        for ep_uuid in [x for x in list(self._endpoint_to_snats)
                        if x.startswith(port_id + '|')]:
            for snat_uuid in list(self._endpoint_to_snats.get(ep_uuid, set())):
                self._discard_snat_for_endpoint(ep_uuid, snat_uuid)
            self._endpoint_to_snats.pop(ep_uuid, None)

    def get_dist_snat_mappings(self):
        result = {}
        for info in list(self._snat_to_ip_range.values()):
            if info.get('snat_ip') and info.get('start') is not None:
                result[info['snat_ip']] = {
                    'start': info['start'],
                    'end': info['end']}
        return result

    def _discard_snat_for_endpoint(self, endpoint_uuid, snat_uuid):
        eps = self._snat_to_endpoints.get(snat_uuid, set())
        eps.discard(endpoint_uuid)
        if eps:
            return

        self._snat_to_endpoints.pop(snat_uuid, None)
        self._snat_to_ip_range.pop(snat_uuid, None)
        self._delete_file(snat_uuid, self.snat_mapping_file)
        self._delete_file(snat_uuid, self.service_mapping_file)

    def _stable_dist_snat_uuid(self, hsi):
        seed = '%s|%s|%s' % (
            hsi.get('host_snat_ip', ''),
            hsi.get('external_segment_name', ''),
            hsi.get('service_ip', ''))
        digest = hashlib.md5(seed.encode('utf-8')).hexdigest()
        return str(uuid.UUID(digest))

    def _safe_int(self, value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def build_dist_snat_entries(self, mapping, mapping_dict):
        dist_entries = []
        host_snat_ips = mapping.get('host_snat_ips', [])
        interface_name = mapping_dict.get('interface-name')
        interface_vlan = mapping_dict.get('access-interface-vlan')
        service_domain = mapping.get('vrf_tenant', 'common')

        for hsi in host_snat_ips:
            start = self._safe_int(hsi.get('start_port'))
            end = self._safe_int(hsi.get('end_port'))
            if start is None or end is None:
                continue

            snat_uuid = self._stable_dist_snat_uuid(hsi)
            service_mac = hsi.get('service_mac') or hsi.get('host_snat_mac')
            service_nodes = []
            for node in hsi.get('service_nodes', []):
                node_start = self._safe_int(node.get('start_port'))
                node_end = self._safe_int(node.get('end_port'))
                if node_start is None or node_end is None:
                    continue
                service_nodes.append({
                    'mac': node.get('mac'),
                    'port-range': [{'start': node_start, 'end': node_end}]
                })

            snat_file = {
                'uuid': snat_uuid,
                'interface-name': interface_name,
                'snat-ip': hsi.get('host_snat_ip'),
                'interface-mac': service_mac,
                'local': True,
                'dest': [hsi.get('dest_prefix', '0.0.0.0/0')],
                'port-range': [{'start': start, 'end': end}],
                'remote': service_nodes,
            }
            if interface_vlan is not None:
                snat_file['interface-vlan'] = interface_vlan

            service_file = {
                'uuid': snat_uuid,
                'domain-policy-space': service_domain,
                'domain-name': (
                    hsi.get('service_vrf') or
                    mapping.get('vrf_name')
                ),
                'service-mode': 'loadbalancer',
                'service-mac': service_mac,
                'interface-name': interface_name,
                'interface-ip': hsi.get('service_ip'),
                'service-mapping': [{
                    'next-hop-ips': None,
                    'terminating-next-hop-ips': None,
                    'conntrack-enabled': True,
                }]
            }
            if interface_vlan is not None:
                service_file['interface-vlan'] = interface_vlan

            dist_entries.append({
                'uuid': snat_uuid,
                'snat_ip': hsi.get('host_snat_ip'),
                'start': start,
                'end': end,
                'snat_file': snat_file,
                'service_file': service_file,
            })
        return dist_entries
