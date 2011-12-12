# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
A connection to the KVM monitor socket using the QMP (JSON) protocol
"""

import json
import socket

from nova import log as logging


LOG = logging.getLogger('nova.virt.illumos.monitor')


class Monitor(object):
    def __init__(self, monitor_path):
        self._cache_supported_commands = None

        self.conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        LOG.debug(_('QMP connecting to: %s') % (monitor_path))
        self.conn.connect(monitor_path)
        self.conn_file = self.conn.makefile()
        self._negotiate()

    def is_connected(self):
        return self.conn

    def _negotiate(self):
        _server_hello = self._receive_json()
        self.execute('qmp_capabilities')

    def close(self):
        if self.conn:
            self.conn.close()
        self.conn = None

    def execute(self, execute_cmd, args=None):
        self._send(execute_cmd, args)
        response = self._receive_json()
        if 'error' in response:
            raise Exception(_('Error communicating with KVM: %s') % (response))
        return response['return']

    def _send(self, execute_cmd, args):
        o = {}
        o['execute'] = execute_cmd
        if args:
            o['arguments'] = args

        data = json.dumps(o)

        # Apparently we may need a dummy byte with some KVM versions
        data = data + ' '

        LOG.debug(_('QMP sending: %s') % (data))

        self.conn.send(data)

    def on_event(self, event):
        LOG.debug(_("Got KVM event: %s") % event)
        pass

    def _receive_json(self):
        while True:
            line = self.conn_file.readline()
            LOG.debug(_('QMP read: %s') % (line))
            o = json.loads(line)
            if 'event' in o:
                self.on_event(o)
            else:
                return o

    def query_version(self):
        return self.execute('query-version')

    def query_kvm(self):
        return self.execute('query-kvm')

    def query_vnc(self):
        return self.execute('query-vnc')

    def query_uuid(self):
        return self.execute('query-uuid')

    def query_block(self):
        return self.execute('query-block')

    def query_blockstats(self):
        return self.execute('query-blockstats')

    def system_reset(self):
        return self.execute('system_reset')

    def pause(self):
        return self.execute('stop')

    def unpause(self):
        return self.execute('cont')

    def stop(self):
        return self.execute('quit')

    def human_monitor_command(self, command):
        return self.execute('human-monitor-command',
                             {'command-line': command})

    def drive_add(self, file, interface, id, boot, format, media):
        # TODO(justinsb): It sucks that the return value changes...
#        if self.is_command_supported('drive_add'):
#            return self.execute('drive_add', { 'file':  file,
#                                                'if': interface,
#                                                'id': id,
#                                                'boot': boot,
#                                                'format': format,
#                                                'media': media })
        drive_spec = ('file=%s,if=%s,id=%s,boot=%s,format=%s,media=%s' %
                      (file, interface, id, boot, format, media))
        text = 'drive_add %s %s' % ('dummy', drive_spec)

        return self.human_monitor_command(text)

    def device_add(self, driver, bus, drive, id):
#        return self.execute('device_add', { 'driver':  driver,
#                                             'bus': bus,
#                                             'drive': drive,
#                                             'id': id })
        device_spec = ('%s,bus=%s,drive=%s,id=%s' %
                      (driver, bus, drive, id))
        text = 'device_add %s' % (device_spec)

        return self.human_monitor_command(text)

    def is_command_supported(self, command):
        return command in self.supported_commands()

    def supported_commands(self):
        if not self._cache_supported_commands:
            commands = self.execute('query-commands')
            supported_commands = []
            for command in commands:
                supported_commands.append(command['name'])
            self._cache_supported_commands = supported_commands
        return self._cache_supported_commands
