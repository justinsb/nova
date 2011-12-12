# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# All Rights Reserved.
# Copyright (c) 2010 Citrix Systems, Inc.
# Copyright (c) 2011 Piston Cloud Computing, Inc
# Copyright (c) 2011 Justin Santa Barbara
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

"""
A connection to a hypervisor for illumos.

Supports KVM.

**Related Flags**

"""

import hashlib
import functools
import inspect
import os
import random
import shutil
import tempfile

from nova import context as nova_context
from nova import db
from nova import exception
from nova import flags
from nova import log as logging
from nova import utils
from nova.compute import instance_types
from nova.compute import power_state
from nova.virt import disk
from nova.virt import driver
from nova.virt import images
from nova.virt.illumos import utils as illumos_utils
from nova.virt.illumos import monitor

LOG = logging.getLogger('nova.virt.illumos.connection')


FLAGS = flags.FLAGS
flags.DEFINE_string('illumos_device_conf_template',
                    utils.abspath('virt/illumos/devices.conf.template'),
                    'Illumos KVM configuration template')
flags.DEFINE_string('illumos_vif_driver',
                    'nova.virt.illumos.vif.IllumosVifDriver',
                    'The illumos VIF driver to configure the VIFs.')
flags.DEFINE_string('illumos_zvol_base',
                    'rpool/kvm',
                    'The ZFS path under which to create zvols for instances.')
flags.DEFINE_list('illumos_volume_drivers',
                  ['iscsi=nova.virt.illumos.volume.IllumosISCSIVolumeDriver'],
                  'Libvirt handlers for remote volumes.')


Template = None


def warn_stub():
    function_name = inspect.stack()[1][3]
    LOG.warning("Stub function invoked: %s", function_name)


def get_connection(read_only):
    # These are loaded late so that there's no need to install these
    # libraries when not using libvirt.
    _late_load_cheetah()
    return IllumosConnection(read_only)


def _late_load_cheetah():
    global Template
    if Template is None:
        t = __import__('Cheetah.Template', globals(), locals(),
                       ['Template'], -1)
        Template = t.Template


def _get_eph_disk(ephemeral):
    return 'disk.eph' + str(ephemeral['num'])


class IllumosInstance(object):

    def __init__(self, name, state):
        self.name = name
        self.state = state


class IllumosConnection(driver.ComputeDriver):
    """Hypervisor driver for Illumos"""

    def __init__(self, read_only):
        self.devices_template = open(FLAGS.illumos_device_conf_template).read()

        self.vif_driver = utils.import_object(FLAGS.illumos_vif_driver)

        self.volume_drivers = {}
        for driver_str in FLAGS.illumos_volume_drivers:
            driver_type, _sep, driver = driver_str.partition('=')
            driver_class = utils.import_class(driver)
            self.volume_drivers[driver_type] = driver_class(self)

        self.instances = {}
        self.host_status = {
          'host_name-description': 'Fake Host',
          'host_hostname': 'fake-mini',
          'host_memory_total': 8000000000,
          'host_memory_overhead': 10000000,
          'host_memory_free': 7900000000,
          'host_memory_free_computed': 7900000000,
          'host_other_config': {},
          'host_ip_address': '192.168.1.109',
          'host_cpu_info': {},
          'disk_available': 500000000000,
          'disk_total': 600000000000,
          'disk_used': 100000000000,
          'host_uuid': 'cedb9b39-9388-41df-8891-c5c9a0c0fe5f',
          'host_name_label': 'fake-mini'}
        self._mounts = {}

    def _lookup_by_name(self, instance_name):
        """Retrieve KvmInstance object given an instance name.

        All error handling should be handled in this method and
        relevant nova exceptions should be raised in response.

        """
        kvm_instance = KvmInstance(instance_name)
        if not kvm_instance.exists():
                raise exception.InstanceNotFound(instance_id=instance_name)
        return kvm_instance

    def init_host(self, host):
        warn_stub()
        return

    def list_instances(self):
        warn_stub()
        return self.instances.keys()

    def _map_to_instance_info(self, instance):
        instance = utils.check_isinstance(instance, IllumosInstance)
        info = driver.InstanceInfo(instance.name, instance.state)
        return info

    def list_instances_detail(self):
        warn_stub()
        info_list = []
        for instance in self.instances.values():
            info_list.append(self._map_to_instance_info(instance))
        return info_list

    def plug_vifs(self, instance, network_info):
        """Plug VIFs into networks."""
        for (network, mapping) in network_info:
            self.vif_driver.plug(instance, network, mapping)

    def unplug_vifs(self, instance, network_info):
        """Unplug VIFs from networks."""
        for (network, mapping) in network_info:
            self.vif_driver.unplug(instance, network, mapping)

    @exception.wrap_exception()
    def spawn(self, context, instance, image_meta,
              network_info=None, block_device_info=None):
        conf = self._build_conf(context, instance, network_info, False,
                          block_device_info=block_device_info)
        #self.firewall_driver.setup_basic_filtering(instance, network_info)
        #self.firewall_driver.prepare_instance_filter(instance, network_info)
        self._create_image(context, instance, conf, network_info=network_info,
                           block_device_info=block_device_info)

        self._create_kvm_instance(conf)
        LOG.debug(_("instance %s: started"), instance['name'])
        #self.firewall_driver.apply_instance_filter(instance, network_info)

        def _wait_for_boot():
            """Called at an interval until the VM is running."""
            instance_name = instance['name']

            try:
                state = self.get_info(instance_name)['state']
            except exception.NotFound:
                msg = (_("During instance start, %s disappeared.")
                       % instance_name)
                LOG.error(msg)
                raise utils.LoopingCallDone

            if state == power_state.RUNNING:
                msg = _("Instance %s spawned successfully.") % instance_name
                LOG.info(msg)
                raise utils.LoopingCallDone

        timer = utils.LoopingCall(_wait_for_boot)
        return timer.start(interval=0.5, now=True)

    def snapshot(self, context, instance, name):
        warn_stub()
        if not instance['name'] in self.instances:
            raise exception.InstanceNotRunning()

    def reboot(self, instance, network_info, reboot_type):
        warn_stub()
        pass

    def get_host_ip_addr(self):
        warn_stub()
        return '192.168.0.1'

    def resize(self, instance, flavor):
        warn_stub()
        pass

    def set_admin_password(self, instance, new_pass):
        warn_stub()
        pass

    def inject_file(self, instance, b64_path, b64_contents):
        warn_stub()
        pass

    def agent_update(self, instance, url, md5hash):
        warn_stub()
        pass

    def rescue(self, context, instance, network_info, image_meta):
        warn_stub()
        pass

    def unrescue(self, instance, network_info):
        warn_stub()
        pass

    def poll_rebooting_instances(self, timeout):
        warn_stub()
        pass

    def poll_rescued_instances(self, timeout):
        warn_stub()
        pass

    def migrate_disk_and_power_off(self, context, instance, dest,
                                   instance_type):
        warn_stub()
        pass

    def poll_unconfirmed_resizes(self, resize_confirm_window):
        warn_stub()
        pass

    @exception.wrap_exception()
    def pause(self, instance):
        """Pause VM instance"""
        kvm_instance = self._lookup_by_name(instance.name)
        kvm_instance.pause()

    @exception.wrap_exception()
    def unpause(self, instance):
        """Unpause paused VM instance"""
        kvm_instance = self._lookup_by_name(instance.name)
        kvm_instance.unpause()

    def suspend(self, instance):
        warn_stub()
        pass

    def resume(self, instance):
        warn_stub()
        pass

    def destroy(self, instance, network_info, block_device_info=None,
                cleanup=True):
        instance_name = instance['name']

        kvm = KvmInstance(instance_name)
        #kvm.stop()
        kvm.disable_smf()
        kvm.delete_smf()

        self.unplug_vifs(instance, network_info)

        #def _wait_for_destroy():
        #    """Called at an interval until the VM is gone."""
        #    instance_name = instance['name']
        #
        #    try:
        #        state = self.get_info(instance_name)['state']
        #    except exception.NotFound:
        #        msg = _("Instance %s destroyed successfully.") % instance_name
        #        LOG.info(msg)
        #        raise utils.LoopingCallDone

        #timer = utils.LoopingCall(_wait_for_destroy)
        #timer.start(interval=0.5, now=True)

        #self.firewall_driver.unfilter_instance(instance,
        #                                       network_info=network_info)

        # NOTE(vish): we disconnect from volumes regardless
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)
        for vol in block_device_mapping:
            connection_info = vol['connection_info']
            mountpoint = vol['mount_device']
            xml = self.volume_driver_method('disconnect_volume',
                                            connection_info,
                                            mountpoint)
        if cleanup:
            self._cleanup(kvm)

        return True

    def _cleanup(self, kvm):
        target = kvm.path_base()
        zvol_base = kvm.zvol_base()
        instance_name = kvm.instance_name()
        LOG.info(_('instance %(instance_name)s: deleting instance files'
                ' %(target)s') % locals())
        if os.path.exists(target):
            shutil.rmtree(target)
        Zfs.destroy(zvol_base, recursive=True)

    def volume_driver_method(self, method_name, connection_info,
                             *args, **kwargs):
        driver_type = connection_info.get('driver_volume_type')
        if not driver_type in self.volume_drivers:
            raise exception.VolumeDriverNotFound(driver_type=driver_type)
        driver = self.volume_drivers[driver_type]
        method = getattr(driver, method_name)
        return method(connection_info, *args, **kwargs)

    @exception.wrap_exception()
    def attach_volume(self, connection_info, instance_name, mountpoint):
#        virt_dom = self._lookup_by_name(instance_name)
        mount_device = mountpoint.rpartition("/")[2]
        local_device = self.volume_driver_method('connect_volume',
                                                 connection_info,
                                                 mount_device)

        drive = {}
        drive['path'] = local_device
        drive['id'] = mount_device
        drive['boot'] = 'off'
        drive['format'] = 'raw'
        drive['media'] = 'disk'

        kvm = KvmInstance(instance_name)
        kvm.attach_drive(drive)

    def detach_volume(self, connection_info, instance_name, mountpoint):
        """Detach the disk attached to the instance"""
        warn_stub()
        try:
            del self._mounts[instance_name][mountpoint]
        except KeyError:
            pass
        return True

    def get_info(self, instance_name):
        """Retrieve information for a specific instance name."""
        kvm = KvmInstance(instance_name)
        smf = kvm.find_smf()
        if not smf:
            raise exception.InstanceNotFound(instance_id=instance_name)

        # columns = ['state', 'nstate', 'inst', 'scope', 'svc']

        smf_state = smf.state()
        if smf_state == 'online':
            state = power_state.RUNNING
        elif smf_state == 'offline':
            # TODO(justinsb): This isn't a great mapping
            state = power_state.BUILDING
        elif smf_state == 'uninitialized':
            state = power_state.BUILDING
        elif smf_state == 'degraded':
            # TODO(justinsb): This isn't a great mapping
            state = power_state.FAILED
        elif smf_state == 'maintenance':
            state = power_state.FAILED
        elif smf_state == 'disabled':
            state = power_state.SHUTDOWN
        else:
            raise Exception(_('Unhandled SMF state: %s') % (smf_state))

        # TODO(justinsb): Collect good values here
        max_mem = 0
        mem = 0
        num_cpu = 1
        cpu_time = 0

        return {'state': state,
                'max_mem': max_mem,
                'mem': mem,
                'num_cpu': num_cpu,
                'cpu_time': cpu_time}

    def get_diagnostics(self, instance_name):
        warn_stub()
        return 'FAKE_DIAGNOSTICS'

    def get_all_bw_usage(self, start_time, stop_time=None):
        """Return bandwidth usage info for each interface on each
           running VM"""
        warn_stub()
        bwusage = []
        return bwusage

    def list_disks(self, instance_name):
        warn_stub()
        return ['A_DISK']

    def list_interfaces(self, instance_name):
        warn_stub()
        return ['A_VIF']

    def block_stats(self, instance_name, disk_id):
        warn_stub()
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        warn_stub()
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_console_output(self, instance):
        warn_stub()
        return 'FAKE CONSOLE\xffOUTPUT'

    def get_ajax_console(self, instance):
        warn_stub()
        return {'token': 'FAKETOKEN',
                'host': 'fakeajaxconsole.com',
                'port': 6969}

    def get_vnc_console(self, instance):
        warn_stub()
        return {'token': 'FAKETOKEN',
                'host': 'fakevncconsole.com',
                'port': 6969}

    def get_console_pool_info(self, console_type):
        warn_stub()
        return  {'address': '127.0.0.1',
                 'username': 'fakeuser',
                 'password': 'fakepassword'}

    def refresh_security_group_rules(self, security_group_id):
        warn_stub()
        return True

    def refresh_security_group_members(self, security_group_id):
        warn_stub()
        return True

    def refresh_provider_fw_rules(self):
        warn_stub()
        pass

    def update_available_resource(self, ctxt, host):
        """Updates compute manager resource info on ComputeNode table.

        Since we don't have a real hypervisor, pretend we have lots of
        disk and ram.
        """

        warn_stub()
        try:
            service_ref = db.service_get_all_compute_by_host(ctxt, host)[0]
        except exception.NotFound:
            raise exception.ComputeServiceUnavailable(host=host)

        # Updating host information
        dic = {'vcpus': 1,
               'memory_mb': 4096,
               'local_gb': 1028,
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               'hypervisor_type': 'illumos_kvm',
               'hypervisor_version': '1',
               'cpu_info': '?'}

        compute_node_ref = service_ref['compute_node']
        if not compute_node_ref:
            LOG.info(_('Compute_service record created for %s ') % host)
            dic['service_id'] = service_ref['id']
            db.compute_node_create(ctxt, dic)
        else:
            LOG.info(_('Compute_service record updated for %s ') % host)
            db.compute_node_update(ctxt, compute_node_ref[0]['id'], dic)

    def compare_cpu(self, xml):
        """This method is supported only by libvirt."""
        warn_stub()
        raise NotImplementedError('This method is supported only by libvirt.')

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        """This method is supported only by libvirt."""
        warn_stub()
        raise NotImplementedError('This method is supported only by libvirt.')

    def get_instance_disk_info(self, ctxt, instance_ref):
        """This method is supported only by libvirt."""
        warn_stub()
        return

    def live_migration(self, context, instance_ref, dest,
                       post_method, recover_method, block_migration=False):
        """This method is supported only by libvirt."""
        warn_stub()
        return

    def pre_live_migration(self, block_device_info):
        """This method is supported only by libvirt."""
        warn_stub()
        return

    def unfilter_instance(self, instance_ref, network_info):
        """This method is supported only by libvirt."""
        warn_stub()
        raise NotImplementedError('This method is supported only by libvirt.')

    def test_remove_vm(self, instance_name):
        """ Removes the named VM, as if it crashed. For testing"""
        warn_stub()
        self.instances.pop(instance_name)

    def update_host_status(self):
        """Return fake Host Status of ram, disk, network."""
        warn_stub()
        return self.host_status

    def get_host_stats(self, refresh=False):
        """Return fake Host Status of ram, disk, network."""
        warn_stub()
        return self.host_status

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        warn_stub()
        pass

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        warn_stub()
        pass

    def _create_image(self, context, inst, conf, suffix='',
                      disk_images=None, network_info=None,
                      block_device_info=None):
        if not suffix:
            suffix = ''

        # syntactic nicety
        def basepath(fname='', suffix=suffix):
            return os.path.join(FLAGS.instances_path,
                                inst['name'],
                                fname + suffix)

        # ensure directories exist and are writable
        illumos_utils.ensure_tree(basepath(suffix=''))

        LOG.info(_('instance %s: Creating image'), inst['name'])
        illumos_utils.write_to_file(conf['path_device_conf'],
                                    self._render_device_conf(conf))

        # NOTE(vish): No need add the suffix to console.log
        illumos_utils.write_to_file(basepath('console.log', ''), '', 007)

    def _create_kvm_instance(self, conf):
        instance_name = conf['name']
        vnc_display = conf['vnc_display']

        kvm = KvmInstance(instance_name)
        smf_name = kvm.smf_name()
        utils.execute('svccfg', '-s', 'site/kvm', 'add', instance_name)
        utils.execute('svccfg', '-s', 'site/kvm:' + instance_name, 'addpg',
                      'kvm', 'application')
        utils.execute('svccfg', '-s', 'site/kvm:' + instance_name, 'setprop',
                      'kvm/device_config_file=astring:',
                      conf['path_device_conf'])
        utils.execute('svccfg', '-s', 'site/kvm:' + instance_name, 'setprop',
                      'kvm/monitor_file=astring:', conf['path_monitor'])
        utils.execute('svccfg', '-s', 'site/kvm:' + instance_name, 'setprop',
                      'kvm/vcpus=astring:', conf['vcpus'])
        utils.execute('svccfg', '-s', 'site/kvm:' + instance_name, 'setprop',
                      'kvm/memory_mb=astring:', conf['memory_mb'])

        if vnc_display:
            utils.execute('svccfg', '-s', 'site/kvm:' + instance_name,
                          'setprop', 'kvm/vnc_display=integer:', vnc_display)
        utils.execute('svcadm', 'enable', smf_name)

    def _resolve_instance_type(self, conf, instance):
        # FIXME(vish): stick this in db
        inst_type_id = instance['instance_type_id']
        inst_type = instance_types.get_instance_type(inst_type_id)
        conf['instance_type'] = inst_type
        return inst_type

    def _resolve_nics(self, conf, instance, network_info):
        nics = []
        for (network, mapping) in network_info:
            vif = self.vif_driver.plug(instance, network, mapping)

            nic = {}
            nic['vif'] = vif
            nic['name'] = 'nic%s' % len(nics)
            nic['vlan'] = len(nics)
            nic['model'] = 'e1000'
            nic['mac'] = vif['mac_address']
            nic['device'] = vif['bridge_name']
            nics.append(nic)

        return nics

    def _resolve_root_image(self, context, conf, instance, kvm_instance):
        disk_images = {'image_id': instance['image_ref'],
                       'kernel_id': instance['kernel_id'],
                       'ramdisk_id': instance['ramdisk_id']}

        root_fname = hashlib.sha1(str(disk_images['image_id'])).hexdigest()
        size = FLAGS.minimum_root_size

        zvol_base = kvm_instance.zvol_base()
        zvol_root = os.path.join(zvol_base, 'root')

        cache_zvol = os.path.join(FLAGS.illumos_zvol_base, 'cache', root_fname)
        self._cache_image(fn=self._fetch_image,
                          context=context,
                          target=zvol_root,
                          cache_zvol=cache_zvol,
                          fname=root_fname,
                          image_id=disk_images['image_id'],
                          user_id=instance['user_id'],
                          project_id=instance['project_id'],
                          size=size)
        drive = {}
        drive['path'] = '/dev/zvol/dsk/' + zvol_root
        drive['id'] = 0
        drive['boot'] = 'on'
        drive['format'] = 'raw'
        drive['media'] = 'disk'

        return drive

    def _resolve_config_drive(self, context, conf, inst, network_info):
        if inst['key_data']:
            key = str(inst['key_data'])
        else:
            key = None
        net = None

        nets = []
        ifc_template = open(FLAGS.injected_network_template).read()
        ifc_num = -1
        have_injected_networks = False
        admin_context = nova_context.get_admin_context()
        for (network_ref, mapping) in network_info:
            ifc_num += 1

            if not network_ref['injected']:
                continue

            have_injected_networks = True
            address = mapping['ips'][0]['ip']
            netmask = mapping['ips'][0]['netmask']
            address_v6 = None
            gateway_v6 = None
            netmask_v6 = None
            if FLAGS.use_ipv6:
                address_v6 = mapping['ip6s'][0]['ip']
                netmask_v6 = mapping['ip6s'][0]['netmask']
                gateway_v6 = mapping['gateway6']
            net_info = {'name': 'eth%d' % ifc_num,
                   'address': address,
                   'netmask': netmask,
                   'gateway': mapping['gateway'],
                   'broadcast': mapping['broadcast'],
                   'dns': ' '.join(mapping['dns']),
                   'address_v6': address_v6,
                   'gateway6': gateway_v6,
                   'netmask_v6': netmask_v6}
            nets.append(net_info)

        if have_injected_networks:
            net = str(Template(ifc_template,
                               searchList=[{'interfaces': nets,
                                            'use_ipv6': FLAGS.use_ipv6}]))

        metadata = inst.get('metadata')
        if not any((key, net, metadata)):
            return None

        basepath = conf['path_base']
        path_cd = os.path.join(basepath, 'config.iso')

        config_base = tempfile.mkdtemp()
        disk.inject_data_into_fs(config_base, key, net, metadata,
                                 utils.execute)

        volume_label = 'openstack_config'
        utils.execute('mkisofs', '-input-charset', 'utf-8',
                      '-V', volume_label, '-R', '-o', path_cd, config_base)

        #TODO(justinsb): Delete the temp dir

        drive = {}
        drive['path'] = path_cd
        drive['id'] = 'config_cd'
        drive['boot'] = 'off'
        drive['format'] = 'raw'
        drive['media'] = 'cdrom'

        return drive

    def _resolve_drives(self, context, conf, instance, block_device_info,
                          kvm_instance):
        #block_device_mapping =
        #driver.block_device_info_get_mapping(block_device_info)

        drives = []

        drive = self._resolve_root_image(context, conf, instance, kvm_instance)
        drives.append(drive)

#        for vol in block_device_mapping:
#            -drive file=${drive.path},if=none,
#                id=drive-virtio-disk${drive.id},boot=${drive.boot},
#                format=${drive.format} \
#            -device virtio-blk-pci,bus=pci.0,
#                drive=drive-virtio-disk${drive.id},
#                   id=virtio-disk${drive.id}
#
#            drive = {}
#            connection_info = vol['connection_info']
#            mountpoint = vol['mount_device']
#            xml = self.volume_driver_method('connect_volume',
#                                            connection_info,
#                                            mountpoint)
#            drives.append(xml)
#
#        drives.append(drive)
#            drive = {}
#            connection_info = vol['connection_info']
#            mountpoint = vol['mount_device']
#            xml = self.volume_driver_method('connect_volume',
#                                            connection_info,
#                                            mountpoint)
#            drives.append(xml)

        return drives

    def _build_conf(self, context, instance, network_info, rescue=False,
                     block_device_info=None):

        conf = {}
        conf['instance'] = instance
        conf['name'] = instance['name']
        conf['vnc_display'] = self._find_unused_vnc()

        kvm_instance = KvmInstance(instance['name'])

        # ensure directories exist and are writable
        illumos_utils.ensure_tree(kvm_instance.path_base())

        conf['path_base'] = kvm_instance.path_base()
        conf['path_device_conf'] = kvm_instance.path_device_conf()
        conf['path_monitor'] = kvm_instance.path_monitor()

        instance_type = self._resolve_instance_type(conf, instance)
        conf['memory_mb'] = instance_type['memory_mb']
        conf['vcpus'] = instance_type['vcpus']
        conf['rescue'] = rescue

        conf['nics'] = self._resolve_nics(conf, instance, network_info)
        conf['drives'] = self._resolve_drives(context, conf, instance,
                                              block_device_info,
                                              kvm_instance)

        drive = self._resolve_config_drive(context, conf, instance,
                                           network_info)
        if drive:
            conf['drives'].append(drive)

        LOG.debug(_("_build_conf produced %s") % conf)

        return conf

    def _render_device_conf(self, conf):
        rendered = str(Template(self.devices_template, searchList=[conf]))
        LOG.debug(_('instance %s: finished _render_conf method') %
                  conf['name'])
        return rendered

    @staticmethod
    def _cache_image(fn, target, fname, cache_zvol, cow=False,
                       *args, **kwargs):
        """See libvirt's _get_image method"""
        @utils.synchronized(cache_zvol)
        def sync_download_to_zvol(fname, cache_zvol, *args, **kwargs):
            if Zfs.exists(cache_zvol):
                return

            base_dir = tempfile.mkdtemp()

            base = os.path.join(base_dir, fname)
            metadata = fn(target=base, *args, **kwargs)

            image_size = metadata.get('image_size', '10G')

            temp_zvol = cache_zvol + '_tmp_' + str(random.randint(1, 99999999))
            #TODO(justinsb): Delete temp_zvol on failure
            Zfs.create_zvol(temp_zvol, image_size)

            zvol_target = '/dev/zvol/dsk/' + temp_zvol
            if illumos_utils.is_gzipped(base):
                # We presume this is gzipped-raw (i.e. a 'golden' image)
                illumos_utils.gunzip(base, zvol_target)
            else:
                utils.execute('qemu-img', 'convert', '-O', 'raw',
                              base, zvol_target)

            Zfs.snapshot(temp_zvol, 'ready')
            Zfs.rename(temp_zvol, cache_zvol)

            shutil.rmtree(base_dir)

        sync_download_to_zvol(fname, cache_zvol, *args, **kwargs)

        Zfs.clone(cache_zvol, 'ready', target)

    def _fetch_image(self, context, target, image_id, user_id, project_id,
                     size=None):
        """Grab image and optionally attempt to resize it"""
        return images.fetch_to_raw(context, image_id, target,
                                   user_id, project_id)
#        if size:
#            disk.extend(target, size)

    def _find_unused_vnc(self):
        """Find an unassigned vnc screen id"""
        properties = Smf.query_properties('svc:/site/kvm:*', 'kvm/vnc_display')

        start = 1
        end = 999

        for _i in xrange(0, 100):  # don't loop forever
            screen = str(random.randint(start, end))

            found = False
            for _, prop in properties.items():
                if prop.value == screen:
                    found = True
                    break

            if not found:
                return screen

        raise Exception(_('Unable to find an open vnc screen'))


class KvmInstance(object):
    def __init__(self, name):
        self._instance_name = name
        self.cached_monitor = None

    def instance_name(self):
        return self._instance_name

    def path_base(self):
        return KvmInstance.build_basepath(self.instance_name())

    def path_monitor(self):
        return os.path.join(self.path_base(), 'instance.monitor')

    def path_device_conf(self):
        return os.path.join(self.path_base(), 'device.conf')

    def zvol_base(self):
        return os.path.join(FLAGS.illumos_zvol_base, self.instance_name())

    @staticmethod
    def build_basepath(instance_name):
        return os.path.join(FLAGS.instances_path, instance_name)

    def smf_name(self):
        return 'svc:/site/kvm:' + self.instance_name()

    def disable_smf(self):
        smf = self.find_smf()
        if not smf:
            # SMF is already dead
            return
        Smf.disable_smf(smf.fmri())

    def delete_smf(self):
        smf = self.find_smf()
        if not smf:
            # SMF is already dead
            return
        Smf.delete_smf(smf.fmri())

    def find_smf(self):
        fmri = self.smf_name()
        smfs = Smf.list_services(fmri)
        if len(smfs) == 0:
            return None
        if len(smfs) == 1:
            return smfs[0]
        raise Exception(_("Multiple SMFs found with same fmri"))

    def get_monitor(self):
        mon = self.cached_monitor
        if mon:
            if not mon.is_connected():
                mon = None

        if not mon:
            mon = monitor.Monitor(self.path_monitor())

        self.cached_monitor = mon

        return mon

    def attach_drive(self, drive):
        # TODO(justinsb): We need to persist this to survive host reboots

        path = drive['path']
        interface = 'none'
        drive_format = drive['format']
        boot = drive['boot']
        key = drive['id']
        media = drive['media']

        bus = 'pci.0'
        device_driver = 'virtio-blk-pci'

        drive_id = 'drive_%s' % (key)
        device_id = 'device_%s' % (key)

        conn = self.get_monitor()
        conn.drive_add(path, interface, drive_id, boot, drive_format, media)
        conn.device_add(device_driver, bus, drive_id, device_id)

    def pause(self):
        self.get_monitor().pause()

    def unpause(self):
        self.get_monitor().unpause()

    def stop(self):
        self.get_monitor().stop()


class Zfs(object):
    @staticmethod
    def exists(path):
        (_, stderr) = utils.execute('zfs', 'list', path, check_exit_code=False)
        if stderr:
            return False
        return True

    @staticmethod
    def create_zvol(path, size):
        # Image_size must be a multiple of block size.
        # We assume it is
        utils.execute('zfs', 'create', '-p', '-V', size, path)

    @staticmethod
    def snapshot(path, name):
        snapshot = '%s@%s' % (path, name)
        utils.execute('zfs', 'snapshot', snapshot)

    @staticmethod
    def clone(src, snapshot, dest):
        src_snapshot = '%s@%s' % (src, snapshot)
        utils.execute('zfs', 'clone', '-p', src_snapshot, dest)

    @staticmethod
    def rename(old_name, new_name):
        utils.execute('zfs', 'rename', old_name, new_name)

    @staticmethod
    def destroy(zvol, recursive=False, unsafe_recursive=False):
        cmd = ['zfs', 'destroy']
        if recursive:
            cmd.append('-r')
        if unsafe_recursive:
            cmd.append('-R')
        cmd.append(zvol)
        try:
            utils.execute(*cmd)
        except exception.ProcessExecutionError as e:
            if 'dataset does not exist' in e.stderr:
                LOG.info(_("ZFS dataset already destroyed: %s"), zvol)
                return
            raise


class SmfProperty(object):
    def __init__(self, key, smf_type, value):
        super(SmfProperty, self).__init__()
        self.key = key
        self.smf_type = smf_type
        self.value = value

    def property_path(self):
        # e.g. svc:/site/kvm:i-00000041/:properties/application/config_file
        items = self.key.split(':')
        if len(items) != 4:
            raise Exception(_('Cannot parse smf property: %s') % self.key)
        return items[3]


class Smf(object):
    def __init__(self):
        super(Smf, self).__init__()
        self._data = None
        self._properties = None

    def fmri(self):
        return 'svc:/%s:%s' % (self._data['svc'], self._data['inst'])

    def properties(self):
        if not self._properties:
            self._properties = Smf.get_properties(self.fmri())
        return self._properties

    def state(self):
        return self._data['state']

    @staticmethod
    def delete_smf(fmri):
        utils.execute('svccfg', 'delete', fmri)

    @staticmethod
    def disable_smf(fmri):
        utils.execute('svcadm', 'disable', '-s', fmri)

    @staticmethod
    def list_services(fmri=None):
        columns = ['state', 'nstate', 'inst', 'scope', 'svc']
        output_format = ','.join(columns)

        if fmri:
            (stdout, stderr) = utils.execute('svcs', '-H', '-o', output_format,
                                             fmri, check_exit_code=False)
            if stderr:
                #TODO(justinsb): Use new exit-code handling
                if "doesn't match any instances" in stderr:
                    pass
                else:
                    raise Exception(_('Error querying SMF service: %(fmri)s. '
                                      '%(stderr)s') % locals())
        else:
            (stdout, _) = utils.execute('svcs', '-H',
                                        '-o', output_format, '-a')

        smfs = []

        for line in stdout.splitlines():
            items = line.split()
            if len(items) != len(columns):
                raise Exception(("Cannot parse line from smf: %s") % line)
            smf = Smf()
            smf._data = {}
            for i in range(len(items)):
                smf._data[columns[i]] = items[i]
            smfs.append(smf)

        return smfs

    @staticmethod
    def query_properties(fmri_spec, property_group=None):
        #svcprop "svc:/site/kvm:*"
        #svcprop -p application "svc:/site/kvm:*"

        # -f means we always get the same format (even when there's 1 match)
        cmd = ['svcprop', '-f']
        if property_group:
            cmd.extend(['-p', property_group])
        cmd.append(fmri_spec)

        (stdout, stderr) = utils.execute(*cmd, check_exit_code=False)
        if stderr:
            #TODO(justinsb): Use new exit-code handling
            if "doesn't match any entities" in stderr:
                pass
            else:
                raise Exception(_('Error querying SMF properties: %s') %
                                (stderr))

        properties = {}

        for line in stdout.splitlines():
            items = line.split()
            if len(items) < 3:
                raise Exception(("Cannot parse line from svcprop: %s") % line)
            key = items[0]
            property_type = items[1]
            property_value = ' '.join(items[2:])

            properties[key] = SmfProperty(key, property_type, property_value)

        return properties
