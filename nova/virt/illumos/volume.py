# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# Copyright 2011 Justin Santa Barbara
#
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

"""Volume drivers for illumos."""

import os
import time

from nova import exception
from nova import flags
from nova import log as logging
from nova import utils

LOG = logging.getLogger('nova.virt.illumos.volume')
FLAGS = flags.FLAGS
flags.DECLARE('num_iscsi_scan_tries', 'nova.volume.driver')


class IllumosVolumeDriver(object):
    """Base class for volume drivers."""
    def __init__(self, connection):
        self.connection = connection

    def connect_volume(self, connection_info, mount_device):
        """Connect the volume. Returns xml for libvirt."""
#        driver = self._pick_volume_driver()
        device_path = connection_info['data']['device_path']
        return device_path

    def disconnect_volume(self, connection_info, mount_device):
        """Disconnect the volume"""
        pass


class IllumosISCSIVolumeDriver(IllumosVolumeDriver):
    """Driver to attach Network volumes to libvirt."""

    def _is_discovery_enabled(self, service_key='Static'):
        # TODO(justinsb): Cache this??

        out, _err = utils.execute('iscsiadm', 'list', 'discovery')

        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            key, _, value = line.partition(':')
            if key == service_key:
                value = value.strip()
                if value == 'enabled':
                    return True
                assert value == 'disabled'
                return False

        raise Exception('Could not find status of discovery')

    def _enable_discovery(self, method='--static'):
        # iscsiadm modify discovery --static enable
        utils.execute('iscsiadm', 'modify', 'discovery', method, 'enable')

    def _add_static_target(self, target_iqn, target_portal):
        # iscsiadm add static-config <iqn>
        target = '%s,%s' % (target_iqn, target_portal)
        utils.execute('iscsiadm', 'add', 'static-config', target)

    def _parse_iscsiadm_list(self, out):
        # NOTE: Erases hierarchies
        conf = {}
        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            key, _, value = line.partition(':')
            value = value.strip()
            conf[key] = value

        return conf

    def _has_static_target(self, target_iqn, target_portal):
        # iscsiadm list static-config <iqn>
        target = '%s,%s' % (target_iqn, target_portal)
        out, err = utils.execute('iscsiadm', 'list', 'static-config', target,
                                 check_exit_code=False)
        if err:
            if err.strip().endswith('not found'):
                return False
            raise Exception(_('Error checking for iscsi target %(target)s: '
                              '%(err)s') % locals())
        data = self._parse_iscsiadm_list(out)
        return 'Static Configuration Target' in data

    def _configure_iscsi_targets(self):
        # devfsadm -i iscsi
        utils.execute('devfsadm', '-i', 'iscsi')

    def _get_iscsi_device(self, target):
        #iscsiadm list target -S iqn.2010-10.org.openstack:volume-00000005
        out, _err = utils.execute('iscsiadm', 'list', 'target', '-S', target)
        os_device_name = None

        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            key, _, value = line.partition(':')
            if key == 'OS Device Name':
                assert not os_device_name
                os_device_name = value.strip()
                if os_device_name == 'Not Available':
                    os_device_name = None

        return os_device_name

    def connect_volume(self, connection_info, mount_device):
        """Attach the volume to instance_name"""
        iscsi_properties = connection_info['data']

        #try:
        #    # NOTE(vish): if we are on the same host as nova volume, the
        #    #             discovery makes the target so we don't need to
        #    #             run --op new
        #    self._run_iscsiadm(iscsi_properties, ())
        #except exception.ProcessExecutionError:
        #    self._run_iscsiadm(iscsi_properties, ('--op', 'new'))

        target_iqn = iscsi_properties['target_iqn']
        target_portal = iscsi_properties['target_portal']

        if iscsi_properties.get('auth_method'):
            raise Exception('iSCSI auth not implemented on illumos')

        if not self._is_discovery_enabled():
            self._enable_discovery()

        if not self._has_static_target(target_iqn, target_portal):
            self._add_static_target(target_iqn, target_portal)

        host_device = self._get_iscsi_device(target_iqn)

        if not host_device:
            self._configure_iscsi_targets()

        host_device = self._get_iscsi_device(target_iqn)

        #if iscsi_properties.get('auth_method'):
        #    self._iscsiadm_update(iscsi_properties,
        #                          "node.session.auth.authmethod",
        #                          iscsi_properties['auth_method'])
        #    self._iscsiadm_update(iscsi_properties,
        #                          "node.session.auth.username",
        #                          iscsi_properties['auth_username'])
        #    self._iscsiadm_update(iscsi_properties,
        #                          "node.session.auth.password",
        #                          iscsi_properties['auth_password'])
        #
        #self._run_iscsiadm(iscsi_properties, ("--login",))
        #
        #self._iscsiadm_update(iscsi_properties, "node.startup", "automatic")

        if not host_device:
            raise exception.Error(_("iSCSI device not found for %s") %
                                  (target_iqn))

        #host_device = ("/dev/disk/by-path/ip-%s-iscsi-%s-lun-0" %
        #                (iscsi_properties['target_portal'],
        #                 iscsi_properties['target_iqn']))
        #
        ## The /dev/disk/by-path/... node is not always present immediately
        ## TODO(justinsb): This retry-with-delay is a pattern, move to utils?
        #tries = 0
        #while not os.path.exists(host_device):
        #    if tries >= FLAGS.num_iscsi_scan_tries:
        #        raise exception.Error(_("iSCSI device not found at %s") %
        #                              (host_device))
        #
        #    LOG.warn(_("ISCSI volume not yet found at: %(mount_device)s. "
        #               "Will rescan & retry.  Try number: %(tries)s") %
        #             locals())
        #
        #    # The rescan isn't documented as being necessary(?), but it helps
        #    self._run_iscsiadm(iscsi_properties, ("--rescan",))
        #
        #    tries = tries + 1
        #    if not os.path.exists(host_device):
        #        time.sleep(tries ** 2)

        #if tries != 0:
        #    LOG.debug(_("Found iSCSI node %(mount_device)s "
        #                "(after %(tries)s rescans)") %
        #              locals())

        connection_info['data']['device_path'] = host_device
        sup = super(IllumosISCSIVolumeDriver, self)
        return sup.connect_volume(connection_info, mount_device)

    def disconnect_volume(self, connection_info, mount_device):
        """Detach the volume from instance_name"""
        sup = super(IllumosISCSIVolumeDriver, self)
        sup.disconnect_volume(connection_info, mount_device)

        # TODO(justinsb): Implement this!
        raise Exception("Illumos volume disconnect not yet implemented")
        #iscsi_properties = connection_info['data']
        #self._iscsiadm_update(iscsi_properties, "node.startup", "manual")
        #self._run_iscsiadm(iscsi_properties, ("--logout",))
        #self._run_iscsiadm(iscsi_properties, ('--op', 'delete'))
