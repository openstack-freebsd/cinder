#    Copyright 2018 Sung Gon Yi <skonmeme@gmail.com>
#    Redistribution and use in source and binary forms, with or without 
#    modification, are permitted provided that the following conditions are 
#    met:
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above copyright 
#       notice, this list of conditions and the following disclaimer in the 
#       documentation and/or other materials provided with the distribution.
#    3. Neither the name of the copyright holder nor the names of its 
#       contributors may be used to endorse or promote products derived from 
#       this software without specific prior written permission.
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
#    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
#    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
#    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
#    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
#    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
#    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
#    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
#    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
#    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
#    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
Driver for FreeBSD servers running ZFS.

"""

import os
import math
import libzfs as zfs

from multiprocessing import Process

from oslo_config import cfg
from oslo_log import log as logging

from cinder import exception
from cinder import interface
from cinder.volume import driver
from cinder.image import image_utils
from cinder.volume import utils as volutils

LOG = loggin.getLogger(__name__)

dataset_opts = [
    cfg.StrOpt('zpool',
               default='',
               help='Name for ZFS storage pool that contain exported datasets'),
    cfg.StrOpt('zvol_root',
               default='cinder',
               help='Name for root of the ZFS volumes for cinder')
]

CONF = cfg.CONF
CONF.register_opts(volume_opts, group=configuration.SHARED_CONF_GROUP)

@interface.volumedriver
class FreeBSDZFSDriver(driver.VolumeDriver):
    """OpenStack Cinder drivers for FreeBSD ZFS File system.
    
    Version history:
        0.0.1 - Initial driver. Provide Cinder minimum features
    """
    # ThirdPartySystems wiki page
    CI_WIKI_NAME = 'FREEBSD_ZFS_CI'
    VERSION = '0.0.1'
    
    def __init__(self, zpool_obj=None, *args, **kwargs):
        super(FreeBSDZFSDriver, self).__init__(*args, **kwargs):
        
        self.configuration.append_config_values(dataset_opts)
        self.hostname = socket.gethostname()
        self.zpool = zpool_obj
        self.backend_name =\
            self.configuration.safe_get('volume_backend_name') or 'ZFS'
        
        # Target Driver is what handles data-transport
        # Transport specific code should NOT be in
        # the driver (control path), this way
        # different target drivers can be added (iscsi, FC etc)
        target_driver = \
            self.target_mapping[self.configuration.safe_get('iscsi_helper')]

        LOG.debug('Attempting to initialize ZFS driver with the '
                  'following target_driver: %s',
                  target_driver)

        self.target_driver = importutils.import_object(
            target_driver,
            configuration=self.configuration,
            db=self.db,
            executor=self._execute)
        self.protocol = self.target_driver.protocol
        self._sparse_copy_volume = False
        
    def _volume_path(self, volume_name):
        return self.zvol_root_path + '/' + volume_name

    def _volume_name(self, volume_path):
        volume_path[(len(self.zvol_root_path) + 1):]

    def _snapshot_path(self, volume_name, snapshot_name):
        return volume_name.replace('/', ':') + ':' + snapshot_name
            
    def _snapshot_fullpath(self, volume_name, snapshot_name):
        snapshot_path = self._snapshot_path(volume_name, snapshot_name)
        return self._volume_path(volume_name) + '@' + volume_snapshot

    def _snapshot_path_to_fullpath(self, snapshot_path):
        volume_path = snapshot_path.rsplit(':', 1)[0].replace(':', '/')
        return volume_path + '@' + snapshot_path

    def _snapshot_name(self, snapshot_path, separator=":"):
        return snapshot_path.rsplit(separator, 1)[1]

    def _sizestr_to_g(self, sizestr):
        unit = sizestr[-1]
        size = float(sizestr[:-1])
        multiplier = {'M': 1/1024, 'G': 1, 'T': 1024, 'Z': 1024 * 1024}
        return str(size * multiplier.get(unit)) + 'G'
        
    def _sizestr(self, size_in_g):
        return '%sG' % size_in_g
    
    def _zfs_send(snapshot_obj, fd_write):
        snapshot_obj.send(fd_write)
    
    def _zfs_receive(volume_obj, fd_read):
        volume_obj.receive(fd=fd_read, force=True)
    
    def _zfs_clone(snapshot_obj, clone_obj):
        fd_read, fd_write = os.pipe()
        process_send = Process(target=_zfs_send, args=(snapshot_obj, fd_write,)
        process_send.start()
        self._zfs_receive(clone_obj, fd_read)
        process_send.join()
        os.close(fd_read)
        os.close(fd_write)
        
    def _activate_volume(volume_path):
        volume_obj = zfs.ZFS().get_dataset(volume_path)
        volume_obj.properties['openstack_cinder:in_use'].value = 'yes'
    
    def _deactivate_volume(volume_path):
        volume_obj = zfs.ZFS().get_dataset(volume_path)
        volume_obj.properties['openstack_cinder:in_use'].value = 'no'
    
    def _create_volume(volume_name, volume_size):
        try:
            voluem_path = self._volume_name(volume_name),
            self.zpool.create(name=voluem_path,
                              fsopts={'volsize': volume_size,
                                      'openstack.cinder:in_use': 'no'}, 
                              fstype=zfs.DatasetType.VOLUME)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume", 
                                                     name=volume_name)
        
        return zfs.ZFS().get_dataset(voluem_path)
            
    def _create_volume_from_snapshot(self, clone_name, volume_name, 
                                     snapshot_name, volume_size=None):
        try:
            snapshot_path = self._snapshot_fullpath(volume_name, snapshot_name)
            snapshot_obj = zfs.ZFS().get_snapshot(snapshot_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset="Snapshot",
                                               name=snapshot_name)
        
        try:
            snapshot_volume_size = snapshot_obj.parent.properties['volsize']
            if volume_size is None or
                float(volume_size[:-1]) < float(snapshot_volsize[:-1]):
                LOG.debug("Resize the new volume to %s.", snapshot_volume_size)
                volume_size = snapshot_volume_size
            clone_obj = self._create_volume(clone_name, volume_size)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume",
                                                     name=clone_name)

        self._zfs_clone(snapshot_obj, clone_obj)
        return clone_obj
            
    def _delete_volume(self, volume_name):
        try:
            volume = zfs.ZFS().get_dataset(self._volume_path(volume_name))
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset="Volume", 
                                               name=volume_name)
        
        try:
            volume.delete()
        except zfs.ZFSException:
            LOG.error('Unable to delete due to existing snapshot '
                      'for ZFS Volume: %s', volume_name)
            raise exception.VolumeIsBusy(volume_name=volume['name'])
    
    def _create_snapshot(self, volume_name, snapshot_name):
        try:
            volume_path = self._volume_path(volume_name)
            volume_obj = zfs.ZFS().get_dataset(volume_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset="Volume",
                                               name=volume_name)
        
        try:
            snapshot_path = self._snapshot_path(volume_name, snapshot_name)
            volume_obj.snapshot(snapshot_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset='Snapshot', 
                                                     name=snapshot_name)
        
        _snapshot_path = self._snapshot_fullpath(volume_name, snapshot_name)
        return zfs.ZFS().get_snapshot(_snapshot_path)
    
    def _delete_snapshot(self, volume_name, snapshot_name):
        try:
            snapshot_path = self._snapshot_fullpath(volume_name, snapshot_name)
            snapshot_obj = zfs.ZFS().get_snapshot(snapshot_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset='Snapshot', 
                                               name=snapshot_name)
                                               
        try:
            snapshot_obj.delete()
        except zfs.ZFSException:
            raise exception.ZFSDatasetRemoveFailed(dataset='Snapshot', 
                                                   name=snapshot_name)            

    def _update_volume_stats(self):
        data = {}
        data['volume_backend_name'] = self.volume_backend_name
        data['vendor_name'] = 'Open Source'
        data['driver_version'] = '5000'
        data['storage_protocol'] = 'ZFS'
        data['consistencygroup_support'] = False
        data['QoS_support'] = False
        data['thin_provisioning_support'] = True
        data['thick_provisioning_support'] = False
        data['reserved_percentage'] = self.zpool.properties['capacity'].value

        data['free_capacity_gb'] = self.zpool.properties['free'].value
        data['total_capacity_gb'] = self.zpool.properties['size'].value
        data['provisioned_capacity_gb'] =\
            self.zpool.properties['allocated'].value
        data['pool_name'] = self.zpool.name

        return data
        
    def _extend_volume(self, volume_name, volume_size):
        try:
            volume_obj = zfs.ZFS().get_dataset(self._volume_path(volume_name))
            volume_obj.properties['volsize'].value = volume_size
        except zfs.ZFSException as exc:
            raise exception.ExtendVolumeError(reason=exc.args[0])
    
    def _get_manageable_volumes(self, cinder_resources, marker, limit, 
                                offset, sort_keys, sort_dirs):
        entries = []
        cinder_ids = [resource['id'] for resource in cinder_resources]
        root_dataset = zfs.ZFS().get_dataset(self.zvol_root_path)
        
        for dataset in root_dataset.children_recursive:
            if dataset.type != zfs.DatasetType.VOLUME:
                continue

            volume_name = self._volume_name(dataset.name)
            volume_size = self._sizestr_to_g(dataset.properties['volsize'].value)
            volume_info = {'reference': {'source-name': volume_name},
                           'size': int(math.ceil(float(volume_size[:-1]))),
                           'cinder_id': None,
                           'extra_info': None}
            potential_id = dataset.properties['guid'].value
                           
            if potential_id in cinder_ids:
                volume_info['safe_to_manage'] = False
                volume_info['reason_not_safe'] = 'already managed'
                volume_info['cinder_id'] = volume_name
            elif dataset.properties['openstack.cinder:in_use'] == 'yes':
                volume_info['safe_to_manage'] = False
                volume_info['reason_not_safe'] = 'ZFS Volume in use'
            else:
                volume_info['safe_to_manage'] = True
                volume_info['reason_not_safe'] = None

            entries.append(volume_info)

        return volutils.paginate_entries_list(entries, marker, limit, offset,
                                              sort_keys, sort_dirs)
        
    def do_setup(self):
        """Any initialization the volume driver does while starting."""
        if self.zpool is None:
            try:
                self.zpool = zfs.ZFS().get(self.configuration.zpool)
            except zfs.ZFSException:
                raise exception.ZFSPoolNotFound(pool=self.configuration.zpool)

        self.zvol_root_path = self.zpool.name + "/" + self.configuration.zvol_root

        try:
            zfs.ZFS().get_dataset(self.zvol_root_path)
        except:
            self.zpool.create(name=self.zvol_root_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume",
                                                     name=self.zvol_root_path)        
        
    def check_for_setup_error(self):
        """Verify that requirements are in place to use FreeBSD ZFS driver"""
        if self.zpool is None:
            raise exception.ZFSPoolNotFound(pool=self.configuration.zpool)
        
        try:
            zfs.ZFS().get_dataset(self.zvol_root_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume",
                                                     name=self.zvol_root_path)
    
    def create_volume(self, volume):
        """Creates a ZFS Volume."""
        self._create_volume(volume_name=self._volume_name(volume['name']),
                            volume_size=self._sizestr(volume['size']))
            
    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a ZFS Volume from a ZFS Snapshot."""
        self._create_volume_from_snapshot(
            clone_name=self._volume_name(volume['name']),
            volume_name=self._volume_name(snapshot['volume_name']),
            snapshot_name=self._snapshot_name(snapshot['name']),
            volume_size=self._sizestr(volume['size']))

    def delete_volume(self, volume):
        """Deletes a ZFS Volume."""
        self._delete_volume(volume_name=self._volume_name(volume['name']))

    def create_snapshot(self, snapshot):
        """Creates a snapshot."""
        self._create_snapshot(
            volume_name=self._volume_name(snapshot['volume_name']),
            snapshot_name=self._snapshot_name(snapshot['name']))

    def delete_snapshot(self, snapshot):
        """Deletes a snapshot."""
        self._delete_snapshot(
            volume_name=self._volume_name(snapshot['volume_name']),
            snapshot_name=self._snapshot_name(snapshot['name']))
            
    def local_path(self, volume):
        return ("/dev/zvol/" + self._volume_path(volume))
        
    def copy_image_to_volume(self, context, volume, image_service, image_id):
        """Fetch the image from image_service and write it to the volume."""
        image_utils.fetch_to_raw(context,
                                 image_service,
                                 image_id,
                                 self.local_path(volume),
                                 self.configuration.volume_dd_blocksize,
                                 size=volume['size'])    

    def copy_volume_to_image(self, context, volume, image_service, image_meta):
        """Copy the volume to the specified image."""
        image_utils.upload_volume(context,
                                  image_service,
                                  image_meta,
                                  self.local_path(volume))
    
    def create_cloned_volume(self, volume, src_vref):
        """Creates a clone of the specified volume."""
        snapshot={'volume_name': src_vref['name'],
                  'snapshot': 'for_cinder_clone'}
        self.create_snapshot(snapshot)
        self.create_volume_from_snapshot(volume, snapshot)
        self.delete_snapshot(snapshot)

    def clone_image(self, context, volume,
                    image_location, image_meta,
                    image_service):
        return None, False

    def get_volume_stats(self, refresh=False):
        """Get volume status.

        If 'refresh' is True, run update the stats first.
        """

        if refresh:
            self._stats = self._update_volume_stats()

        return self._stats

    def extend_volume(self, volume, new_size):
        """Extend an existing volume's size."""
        self._extend_volume(volume['name'], self._sizestr(new_size))
    
    def manage_existing(self, volume, existing_ref):
        existing_ref['name'] = existing_ref['source-name']
        
        try:
            volume_path = self._volume_path(existing_ref['name'])
            dataset_obj = zfs.ZFS().get_dataset(volume_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(
                dataset='Volume', 
                name=snapshot_name)
            
        self.create_cloned_volume(volume, existing_ref)

    def manage_existing_get_size(self, volume, existing_ref):
        try:
            volume_name = existing_ref['source-name']
            volume_path = self._volume_path(volume_name)
            volume_obj = zfs.ZFS().get_dataset(volume_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset='Volume', 
                                               name=volume_name)
        
        return self._sizestr_to_g(volume_obj.properties['volsize'].value)
    
    def get_manageable_volumes(self, cinder_volumes, marker, limit, offset,
                               sort_keys, sort_dirs):
        return self._get_manageable_volumes(cinder_volumes, marker, limit,
                                            offset, sort_keys, sort_dirs)

    def get_pool(self, volume):
        return self.backend_name

    # #######  Interface methods for DataPath (Target Driver) ########

    def ensure_export(self, context, volume):
        volume_path = self_volume_path(volume['name'])
        self._activate_volume(volume_path)

        model_update = \
            self.target_driver.ensure_export(context, volume, volume_path)
        return model_update

    def create_export(self, context, volume, connector, vg=None):
        volume_path = self._volume_path(volume['name'])
        self._activate_volume(volume_path)

        export_info = self.target_driver.create_export(
            context,
            volume,
            volume_path)
        return {'provider_location': export_info['location'],
                'provider_auth': export_info['auth'], }

    def remove_export(self, context, volume):
        volume_path = self._volume_path(volume['name'])
        self._deactivate_volume(volume_path)
        self.target_driver.remove_export(context, volume)

    def initialize_connection(self, volume, connector):
        return self.target_driver.initialize_connection(volume, connector)

    def validate_connector(self, connector):
        return self.target_driver.validate_connector(connector)

    def terminate_connection(self, volume, connector, **kwargs):
        # NOTE(jdg):  LVM has a single export for each volume, so what
        # we need to do here is check if there is more than one attachment for
        # the volume, if there is; let the caller know that they should NOT
        # remove the export.
        has_shared_connections = False
        if len(volume.volume_attachment) > 1:
            has_shared_connections = True

        # NOTE(jdg): For the TGT driver this is a noop, for LIO this removes
        # the initiator IQN from the targets access list, so we're good

        self.target_driver.terminate_connection(volume, connector,
                                                **kwargs)
        return has_shared_connections
