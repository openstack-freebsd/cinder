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

import libzfs as zfs

from oslo_config import cfg
from oslo_log import log as logging

from cinder import exception
from cinder import interface
from cinder.volume import driver
from cinder.image import image_utils

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
        
    def _volume_path(self, volume_name):
        if volume_name.startswith(self.zvol_root_path):
            return volume_name
        else:
            return self.zvol_root_path + '/' + volume_name

    def _volume_name(self, volume_path):
        if volume_path.startswith(self.zvol_root_path):
            volume_path[(len(self.zvol_root_path) + 1):]
        else:
            return volume_path

    def _snapshot_path(self, volume_name, snapshot_name):
        if snapshot_name.startswith(self.zvol_root_path):
            return snapshot_path
        else:
            volume_snapshot =\
                 volume_name.replace('/', ':') + ':' + snapshot_name
            return self._volume_path(volume_name) + '@' + volume_snapshot

    def _snapshot_name(self, snapshot_path, separator=":"):
        try:
            if snapshot_path.startswith(self.zvol_root_path):
                snapshot_path.rsplit(separator, 1)[1]
            return snapshot_path
        except ValueError:
            return snapshot_path

    def _sizestr(self, size_in_g):
        return '%sg' % size_in_g
    
    def _create_volume(volume_name, volume_size):
        try:
            self.zpool.create(name=volume_name,
                              fsopts={'volsize': volume_size}, 
                              fstype=zfs.DatasetType.VOLUME)
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume", 
                                                     name=volume_name)
            
    def _create_volume_from_snapshot(self, clone_name, volume_name, 
                                     snapshot_name, volume_size=None):
        try:
            snapshot_path = self._snapshot_path(volume_name, snapshot_name)
            snapshot_obj = zfs.ZFS().get_snapshot(snapshot_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset="Snapshot",
                                               name=snapshot_name)
        
        try:
            if volume_size is None:
                volume_size = snapshot_obj.parent.properties['volsize'].value                
            snapshot_obj.clone(name=self._volume_path(clone_name), 
                               opts={'volsize': volume_size})
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset="Volume",
                                                     name=clone_name)
            
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
        try;
            _volume_path = self._volume_path(volume_name)
            dataset_obj = zfs.ZFS().get_dataset(_volume_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset="Volume",
                                               name=volume_name)
        
        try:
            _snapshot_path = self._snapshot_name(volume_name, snapshot_name)
            dataset_obj.snapshot(self._snapshot_name(_snapshot_path, "@"))
        except zfs.ZFSException:
            raise exception.ZFSDatasetCreationFailed(dataset='Snapshot', 
                                                     name=snapshot_name)
    
    def _delete_snapshot(self, volume_name, snapshot_name):
        try:
            _snapshot_path = self._snapshot_name(volume_name, snapshot_name)
            snapshot_obj = zfs.ZFS().get_snapshot(_snapshot_path)
        except zfs.ZFSException:
            raise exception.ZFSDatasetNotFound(dataset='Snapshot', 
                                               name=snapshot_name)
                                               
        try:
            snapshot_obj.delete()
        except zfs.ZFSException:
            raise exception.ZFSDatasetRemoveFailed(dataset='Snapshot', 
                                                   name=snapshot_name)            

    def _update_volume_stats():
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
        
    def check_for_setup_error(self):
        """Verify that requirements are in place to use FreeBSD ZFS driver"""
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
                  'snapshot': 'for_clone'}
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
    
    # LVM


    def extend_volume(self, volume, new_size):
        """Extend an existing volume's size."""
        self.vg.extend_volume(volume['name'],
                              self._sizestr(new_size))

    def manage_existing(self, volume, existing_ref):
        """Manages an existing LV.

        Renames the LV to match the expected name for the volume.
        Error checking done by manage_existing_get_size is not repeated.
        """
        lv_name = existing_ref['source-name']
        self.vg.get_volume(lv_name)

        vol_id = volutils.extract_id_from_volume_name(lv_name)
        if volutils.check_already_managed_volume(vol_id):
            raise exception.ManageExistingAlreadyManaged(volume_ref=lv_name)

        # Attempt to rename the LV to match the OpenStack internal name.
        try:
            self.vg.rename_volume(lv_name, volume['name'])
        except processutils.ProcessExecutionError as exc:
            exception_message = (_("Failed to rename logical volume %(name)s, "
                                   "error message was: %(err_msg)s")
                                 % {'name': lv_name,
                                    'err_msg': exc.stderr})
            raise exception.VolumeBackendAPIException(
                data=exception_message)

    def manage_existing_object_get_size(self, existing_object, existing_ref,
                                        object_type):
        """Return size of an existing LV for manage existing volume/snapshot.

        existing_ref is a dictionary of the form:
        {'source-name': <name of LV>}
        """

        # Check that the reference is valid
        if 'source-name' not in existing_ref:
            reason = _('Reference must contain source-name element.')
            raise exception.ManageExistingInvalidReference(
                existing_ref=existing_ref, reason=reason)
        lv_name = existing_ref['source-name']
        lv = self.vg.get_volume(lv_name)

        # Raise an exception if we didn't find a suitable LV.
        if not lv:
            kwargs = {'existing_ref': lv_name,
                      'reason': 'Specified logical volume does not exist.'}
            raise exception.ManageExistingInvalidReference(**kwargs)

        # LV size is returned in gigabytes.  Attempt to parse size as a float
        # and round up to the next integer.
        try:
            lv_size = int(math.ceil(float(lv['size'])))
        except ValueError:
            exception_message = (_("Failed to manage existing %(type)s "
                                   "%(name)s, because reported size %(size)s "
                                   "was not a floating-point number.")
                                 % {'type': object_type,
                                    'name': lv_name,
                                    'size': lv['size']})
            raise exception.VolumeBackendAPIException(
                data=exception_message)
        return lv_size

    def manage_existing_get_size(self, volume, existing_ref):
        return self.manage_existing_object_get_size(volume, existing_ref,
                                                    "volume")

    def manage_existing_snapshot_get_size(self, snapshot, existing_ref):
        if not isinstance(existing_ref, dict):
            existing_ref = {"source-name": existing_ref}
        return self.manage_existing_object_get_size(snapshot, existing_ref,
                                                    "snapshot")

    def manage_existing_snapshot(self, snapshot, existing_ref):
        dest_name = self._escape_snapshot(snapshot['name'])
        snapshot_temp = {"name": dest_name}
        if not isinstance(existing_ref, dict):
            existing_ref = {"source-name": existing_ref}
        return self.manage_existing(snapshot_temp, existing_ref)

    def _get_manageable_resource_info(self, cinder_resources, resource_type,
                                      marker, limit, offset, sort_keys,
                                      sort_dirs):
        entries = []
        lvs = self.vg.get_volumes()
        cinder_ids = [resource['id'] for resource in cinder_resources]

        for lv in lvs:
            is_snap = self.vg.lv_is_snapshot(lv['name'])
            if ((resource_type == 'volume' and is_snap) or
                    (resource_type == 'snapshot' and not is_snap)):
                continue

            if resource_type == 'volume':
                potential_id = volutils.extract_id_from_volume_name(lv['name'])
            else:
                unescape = self._unescape_snapshot(lv['name'])
                potential_id = volutils.extract_id_from_snapshot_name(unescape)
            lv_info = {'reference': {'source-name': lv['name']},
                       'size': int(math.ceil(float(lv['size']))),
                       'cinder_id': None,
                       'extra_info': None}

            if potential_id in cinder_ids:
                lv_info['safe_to_manage'] = False
                lv_info['reason_not_safe'] = 'already managed'
                lv_info['cinder_id'] = potential_id
            elif self.vg.lv_is_open(lv['name']):
                lv_info['safe_to_manage'] = False
                lv_info['reason_not_safe'] = '%s in use' % resource_type
            else:
                lv_info['safe_to_manage'] = True
                lv_info['reason_not_safe'] = None

            if resource_type == 'snapshot':
                origin = self.vg.lv_get_origin(lv['name'])
                lv_info['source_reference'] = {'source-name': origin}

            entries.append(lv_info)

        return volutils.paginate_entries_list(entries, marker, limit, offset,
                                              sort_keys, sort_dirs)

    def get_manageable_volumes(self, cinder_volumes, marker, limit, offset,
                               sort_keys, sort_dirs):
        return self._get_manageable_resource_info(cinder_volumes, 'volume',
                                                  marker, limit,
                                                  offset, sort_keys, sort_dirs)

    def get_manageable_snapshots(self, cinder_snapshots, marker, limit, offset,
                                 sort_keys, sort_dirs):
        return self._get_manageable_resource_info(cinder_snapshots, 'snapshot',
                                                  marker, limit,
                                                  offset, sort_keys, sort_dirs)

    def retype(self, context, volume, new_type, diff, host):
        """Retypes a volume, allow QoS and extra_specs change."""

        LOG.debug('LVM retype called for volume %s. No action '
                  'required for LVM volumes.',
                  volume['id'])
        return True

    def migrate_volume(self, ctxt, volume, host, thin=False, mirror_count=0):
        """Optimize the migration if the destination is on the same server.

        If the specified host is another back-end on the same server, and
        the volume is not attached, we can do the migration locally without
        going through iSCSI.
        """

        false_ret = (False, None)
        if volume['status'] != 'available':
            return false_ret
        if 'location_info' not in host['capabilities']:
            return false_ret
        info = host['capabilities']['location_info']
        try:
            (dest_type, dest_hostname, dest_vg, lvm_type, lvm_mirrors) =\
                info.split(':')
            lvm_mirrors = int(lvm_mirrors)
        except ValueError:
            return false_ret
        if (dest_type != 'LVMVolumeDriver' or dest_hostname != self.hostname):
            return false_ret

        if dest_vg == self.vg.vg_name:
            message = (_("Refusing to migrate volume ID: %(id)s. Please "
                         "check your configuration because source and "
                         "destination are the same Volume Group: %(name)s.") %
                       {'id': volume['id'], 'name': self.vg.vg_name})
            LOG.error(message)
            raise exception.VolumeBackendAPIException(data=message)

        vg_list = volutils.get_all_volume_groups()
        try:
            next(vg for vg in vg_list if vg['name'] == dest_vg)
        except StopIteration:
            LOG.error("Destination Volume Group %s does not exist",
                      dest_vg)
            return false_ret

        helper = utils.get_root_helper()

        lvm_conf_file = self.configuration.lvm_conf_file
        if lvm_conf_file.lower() == 'none':
            lvm_conf_file = None

        dest_vg_ref = lvm.LVM(dest_vg, helper,
                              lvm_type=lvm_type,
                              executor=self._execute,
                              lvm_conf=lvm_conf_file)

        self._create_volume(volume['name'],
                            self._sizestr(volume['size']),
                            lvm_type,
                            lvm_mirrors,
                            dest_vg_ref)
        # copy_volume expects sizes in MiB, we store integer GiB
        # be sure to convert before passing in
        size_in_mb = int(volume['size']) * units.Ki
        try:
            volutils.copy_volume(self.local_path(volume),
                                 self.local_path(volume, vg=dest_vg),
                                 size_in_mb,
                                 self.configuration.volume_dd_blocksize,
                                 execute=self._execute,
                                 sparse=self._sparse_copy_volume)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.error("Volume migration failed due to "
                          "exception: %(reason)s.",
                          {'reason': six.text_type(e)}, resource=volume)
                dest_vg_ref.delete(volume)
        self._delete_volume(volume)
        return (True, None)

    def get_pool(self, volume):
        return self.backend_name

    # #######  Interface methods for DataPath (Target Driver) ########

    def ensure_export(self, context, volume):
        volume_path = "/dev/%s/%s" % (self.configuration.volume_group,
                                      volume['name'])

        self.vg.activate_lv(volume['name'])

        model_update = \
            self.target_driver.ensure_export(context, volume, volume_path)
        return model_update

    def create_export(self, context, volume, connector, vg=None):
        if vg is None:
            vg = self.configuration.volume_group

        volume_path = "/dev/%s/%s" % (vg, volume['name'])

        self.vg.activate_lv(volume['name'])

        export_info = self.target_driver.create_export(
            context,
            volume,
            volume_path)
        return {'provider_location': export_info['location'],
                'provider_auth': export_info['auth'], }

    def remove_export(self, context, volume):
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
