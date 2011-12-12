# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2011 Midokura KK
# Copyright (C) 2011 Nicira, Inc
# Copyright 2011 OpenStack LLC.
# Copyright (c) 2011 Justin Santa Barbara
# All Rights Reserved.
#
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

"""VIF drivers for Illumos."""

from nova import flags
from nova import log as logging
from nova.network import linux_net
from nova.virt.libvirt import netutils
from nova import utils
from nova.virt.vif import VIFDriver
from nova import exception

LOG = logging.getLogger('nova.virt.illumos.vif')

FLAGS = flags.FLAGS


class IllumosVifDriver(VIFDriver):
    """VIF driver for Linux bridge."""

    def _get_configurations(self, vnic_name, network, mapping):
        """Get a dictionary of VIF configurations for bridge type."""
        # Assume that the gateway also acts as the dhcp server.
        gateway6 = mapping.get('gateway6')
        mac_id = mapping['mac'].replace(':', '')

        extra_params = "\n"
#        if FLAGS.allow_same_net_traffic:
#            template = "<parameter name=\"%s\"value=\"%s\" />\n"
#            net, mask = netutils.get_net_and_mask(network['cidr'])
#            values = [("PROJNET", net), ("PROJMASK", mask)]
#            if FLAGS.use_ipv6:
#                net_v6, prefixlen_v6 = netutils.get_net_and_prefixlen(
#                                           network['cidr_v6'])
#                values.extend([("PROJNETV6", net_v6),
#                               ("PROJMASKV6", prefixlen_v6)])
#
#            extra_params = "".join([template % value for value in values])
#        else:
#            extra_params = "\n"

        result = {
            'id': mac_id,
            'bridge_name': vnic_name,
            'mac_address': mapping['mac'],
            'ip_address': mapping['ips'][0]['ip'],
            'dhcp_server': mapping['dhcp_server'],
            'extra_params': extra_params,
        }

        if gateway6:
            result['gateway6'] = gateway6 + "/128"

        return result

    def _build_vnc_name(self, instance, mapping):
        # 31 characters max, must end with a number
        instance_name = instance['name']

        interface_key = mapping['mac'].replace(':', '')
        #interface_key = mapping['vif_uuid']

        instance_key = instance_name.replace('instance', '')

        vnic_name = 'vnic_%s_%s_0' % (instance_key, interface_key)
        vnic_name = vnic_name.replace('-', '_')
        vnic_name = vnic_name.replace('__', '_')

        return vnic_name

    def plug(self, instance, network, mapping):
        """Create the VNIC"""
        vnic_name = self._build_vnc_name(instance, mapping)

        mac = mapping['mac']
        vnic_over = network['bridge_interface']

        vnic = IllumosVnic.create(vnic_over, mac, vnic_name)

        allowed_ips = []
        for ip in mapping['ips']:
            allowed_ips.append(ip['ip'])

        vnic.enable_protection(allowed_ips)

        return self._get_configurations(vnic_name, network, mapping)

    def unplug(self, instance, network, mapping):
        """Destroy the VNIC"""
        vnic_name = self._build_vnc_name(instance, mapping)
        IllumosVnic.destroy(vnic_name)


class IllumosVnic(object):
    def __init__(self, name):
        super(IllumosVnic, self).__init__()
        self.name = name

    @staticmethod
    def create(underlying_vnic, mac, name):
        utils.execute('dladm', 'create-vnic', '-l', underlying_vnic,
                      '-m', mac, name)
        return IllumosVnic(name)

    @staticmethod
    def destroy(name):
        try:
            utils.execute('dladm', 'delete-vnic', name)
        except exception.ProcessExecutionError as e:
            if 'invalid link name' in e.stderr:
                LOG.info(_("Vnic already deleted: %s"), name)
                return
            raise

    def enable_protection(self, allowed_ips):
        #mac-nospoof,
        #restricted,
        #ip-nospoof,
        #dhcp-nospoof
        utils.execute('dladm', 'set-linkprop',
                      '-p', 'protection=mac-nospoof,ip-nospoof,restricted',
                      self.name)

        allowed_ips_property = 'allowed-ips=%s' % ','.join(allowed_ips)
        utils.execute('dladm', 'set-linkprop',
                      '-p', allowed_ips_property, self.name)
