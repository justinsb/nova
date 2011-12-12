# vim: tabstop=4 shiftwidth=4 softtabstop=4

#    Copyright 2010 United States Government as represented by the
#    Administrator of the National Aeronautics and Space Administration.
#    All Rights Reserved.
#    Copyright (c) 2010 Citrix Systems, Inc.
#    Copyright (c) 2011 Piston Cloud Computing, Inc
#    Copyright (c) 2011 OpenStack LLC
#    Copyright (c) 2011 Justin Santa Barbara
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

import os
import random
import shutil

from nova import exception
from nova import flags
from nova import utils
from nova.virt import disk
from nova.virt import images

FLAGS = flags.FLAGS


def execute(*args, **kwargs):
    return utils.execute(*args, **kwargs)


def create_image(disk_format, path, size):
    """Create a disk image

    :param disk_format: Disk image format (as known by qemu-img)
    :param path: Desired location of the disk image
    :param size: Desired size of disk image. May be given as an int or
                 a string. If given as an int, it will be interpreted
                 as bytes. If it's a string, it should consist of a number
                 followed by an optional prefix ('k' for kilobytes, 'm'
                 for megabytes, 'g' for gigabytes, 't' for terabytes). If no
                 prefix is given, it will be interpreted as bytes.
    """
    execute('zfs', 'create', '-p', '-V', size, path)


def ensure_tree(path):
    """Create a directory (and any ancestor directories required)

    :param path: Directory to create
    """
    execute('mkdir', '-p', path)


def write_to_file(path, contents, umask=None):
    """Write the given contents to a file

    :param path: Destination file
    :param contents: Desired contents of the file
    :param umask: Umask to set when creating this file (will be reset)
    """
    if umask:
        saved_umask = os.umask(umask)

    try:
        with open(path, 'w') as f:
            f.write(contents)
    finally:
        if umask:
            os.umask(saved_umask)


def chown(path, owner):
    """Change ownership of file or directory

    :param path: File or directory whose ownership to change
    :param owner: Desired new owner (given as uid or username)
    """
    utils.execute('chown', owner, path, run_as_root=True)


def fetch_image(context, target, image_id, user_id, project_id,
                 size=None):
    """Grab image and optionally attempt to resize it"""
    images.fetch(context, image_id, target, user_id, project_id)
    if size:
        disk.extend(target, size)


def is_gzipped(path):
    try:
        utils.execute('gzip', '-l', path)
        return True
    except exception.ProcessExecutionError:
        return False


def gunzip(src, dest):
    # This approach is not a source of pride
    # TODO(justinsb): We also want to keep files sparse.
    #  A python helper might work well
    cmd = 'gunzip -c %s > %s' % (src, dest)
    utils.execute('/bin/sh', '-c', cmd)
