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

        LOG.debug('Attempting to initialize LVM driver with the '
                  'following target_driver: %s',
                  target_driver)

        self.target_driver = importutils.import_object(
            target_driver,
            configuration=self.configuration,
            db=self.db,
            executor=self._execute)
        self.protocol = self.target_driver.protocol
        self._sparse_copy_volume = False

    def __volume_path(self, volume_name):
        if volume_name.startswith(self.zvol_root_path):
            return volume_name
        else:
            return self.zvol_root_path + '/' + volume_name

    def __volume_name(self, volume_path):
        if volume_path.startswith(self.zvol_root_path):
            volume_path[(len(self.zvol_root_path) + 1):]
        else:
            return volume_path

    def __snapshot_path(self, volumne_name, snapshot_name):
        return self.__volume_path(volume_name) + '@' + snapshot_name

    def __snapshot_name(self, snapshot_path):
        return 

    def _sizestr(self, size_in_g):
        return '%sg' % size_in_g
    
    def _create_volume(name, volsize):
        try:
            self.zpool.create(name=self.__volume_path(name), 
                              fsopts={'volsize': volsize}, 
                              fstype=zfs.DatasetType.VOLUME)
        except zfs.ZFSException:
            raise exception.ZFSVolumeCreationFailed(volume=name)
            
    def _create_volume_from_snapshot(self, volume_name, snapshot_name):
        try:
            snapshot_obj = zfs.ZFS().get_snapshot(snapshot_name)
        except zfs.ZFSException:
            raise exception.ZFSVolumeNotFound(volume=volume_name)
        
        try:
            snapshot_obj.clone(name=volume_name)
        except zfs.ZFSException:
            raise exception.ZFSVolumeCreationFailed(volume=volume_name)
            
    def _delete_volume(self, name):
        try:
            volume = zfs.ZFS().get_dataset(name)
            volume.delete()
        except zfs.ZFSException:
            raise exception.ZFSVolumeNotFound(volume=name)

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
            raise exception.ZFSVolumeCreationFailed(volume=self.zvol_root_path)
    
    def create_volume(self, volume):
        """Creates a ZFS Volume."""
        self._create_volume(name=volume['name'],
                            fsopts=self._sizestr(volume['size']))
            
    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a ZFS Volume from a ZFS Snapshot."""
        self._create_volume_from_snapshot(volume['name'], snapshot['name'])

    def delete_volume(self, volume):
        """Deletes a ZFS Volume."""
        self._delete_volume(name=volume['name'])

    def create_snapshot(self, snapshot):
        """Creates a snapshot."""

    # LVM

    def update_migrated_volume(self, ctxt, volume, new_volume,
                               original_volume_status):
        """Return model update from LVM for migrated volume.

        This method should rename the back-end volume name(id) on the
        destination host back to its original name(id) on the source host.

        :param ctxt: The context used to run the method update_migrated_volume
        :param volume: The original volume that was migrated to this backend
        :param new_volume: The migration volume object that was created on
                           this backend as part of the migration process
        :param original_volume_status: The status of the original volume
        :returns: model_update to update DB with any needed changes
        """
        name_id = None
        provider_location = None
        if original_volume_status == 'available':
            current_name = CONF.volume_name_template % new_volume['id']
            original_volume_name = CONF.volume_name_template % volume['id']
            try:
                self.vg.rename_volume(current_name, original_volume_name)
            except processutils.ProcessExecutionError:
                LOG.error('Unable to rename the logical volume '
                          'for volume: %s', volume['id'])
                # If the rename fails, _name_id should be set to the new
                # volume id and provider_location should be set to the
                # one from the new volume as well.
                name_id = new_volume['_name_id'] or new_volume['id']
                provider_location = new_volume['provider_location']
        else:
            # The back-end will not be renamed.
            name_id = new_volume['_name_id'] or new_volume['id']
            provider_location = new_volume['provider_location']
        return {'_name_id': name_id, 'provider_location': provider_location}

    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a volume from a snapshot."""
        if self.configuration.lvm_type == 'thin':
            self.vg.create_lv_snapshot(volume['name'],
                                       self._escape_snapshot(snapshot['name']),
                                       self.configuration.lvm_type)
            if volume['size'] > snapshot['volume_size']:
                LOG.debug("Resize the new volume to %s.", volume['size'])
                self.extend_volume(volume, volume['size'])
            self.vg.activate_lv(volume['name'], is_snapshot=True,
                                permanent=True)
            return
        self._create_volume(volume['name'],
                            self._sizestr(volume['size']),
                            self.configuration.lvm_type,
                            self.configuration.lvm_mirrors)

        # Some configurations of LVM do not automatically activate
        # ThinLVM snapshot LVs.
        self.vg.activate_lv(snapshot['name'], is_snapshot=True)

        # copy_volume expects sizes in MiB, we store integer GiB
        # be sure to convert before passing in
        volutils.copy_volume(self.local_path(snapshot),
                             self.local_path(volume),
                             snapshot['volume_size'] * units.Ki,
                             self.configuration.volume_dd_blocksize,
                             execute=self._execute,
                             sparse=self._sparse_copy_volume)

    def delete_volume(self, volume):
        """Deletes a logical volume."""

        # NOTE(jdg):  We don't need to explicitly call
        # remove export here because we already did it
        # in the manager before we got here.

        if self._volume_not_present(volume['name']):
            # If the volume isn't present, then don't attempt to delete
            return True

        if self.vg.lv_has_snapshot(volume['name']):
            LOG.error('Unable to delete due to existing snapshot '
                      'for volume: %s', volume['name'])
            raise exception.VolumeIsBusy(volume_name=volume['name'])

        self._delete_volume(volume)
        LOG.info('Successfully deleted volume: %s', volume['id'])

    def create_snapshot(self, snapshot):
        """Creates a snapshot."""

        self.vg.create_lv_snapshot(self._escape_snapshot(snapshot['name']),
                                   snapshot['volume_name'],
                                   self.configuration.lvm_type)

    def delete_snapshot(self, snapshot):
        """Deletes a snapshot."""
        if self._volume_not_present(self._escape_snapshot(snapshot['name'])):
            # If the snapshot isn't present, then don't attempt to delete
            LOG.warning("snapshot: %s not found, "
                        "skipping delete operations", snapshot['name'])
            LOG.info('Successfully deleted snapshot: %s', snapshot['id'])
            return True

        # TODO(yamahata): zeroing out the whole snapshot triggers COW.
        # it's quite slow.
        self._delete_volume(snapshot, is_snapshot=True)

    def revert_to_snapshot(self, context, volume, snapshot):
        """Revert a volume to a snapshot"""

        # NOTE(tommylikehu): We still can revert the volume because Cinder
        # will try the alternative approach if 'NotImplementedError'
        # is raised here.
        if self.configuration.lvm_type == 'thin':
            msg = _("Revert volume to snapshot not implemented for thin LVM.")
            raise NotImplementedError(msg)
        else:
            self.vg.revert(self._escape_snapshot(snapshot.name))
            self.vg.deactivate_lv(volume.name)
            self.vg.activate_lv(volume.name)
            # Recreate the snapshot that was destroyed by the revert
            self.create_snapshot(snapshot)

    def local_path(self, volume, vg=None):
        if vg is None:
            vg = self.configuration.volume_group
        # NOTE(vish): stops deprecation warning
        escaped_group = vg.replace('-', '--')
        escaped_name = self._escape_snapshot(volume['name']).replace('-', '--')
        return "/dev/mapper/%s-%s" % (escaped_group, escaped_name)

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
        if self.configuration.lvm_type == 'thin':
            self.vg.create_lv_snapshot(volume['name'],
                                       src_vref['name'],
                                       self.configuration.lvm_type)
            if volume['size'] > src_vref['size']:
                LOG.debug("Resize the new volume to %s.", volume['size'])
                self.extend_volume(volume, volume['size'])
            self.vg.activate_lv(volume['name'], is_snapshot=True,
                                permanent=True)
            return

        mirror_count = 0
        if self.configuration.lvm_mirrors:
            mirror_count = self.configuration.lvm_mirrors
        LOG.info('Creating clone of volume: %s', src_vref['id'])
        volume_name = src_vref['name']
        temp_id = 'tmp-snap-%s' % volume['id']
        temp_snapshot = {'volume_name': volume_name,
                         'size': src_vref['size'],
                         'volume_size': src_vref['size'],
                         'name': 'clone-snap-%s' % volume['id'],
                         'id': temp_id}

        self.create_snapshot(temp_snapshot)

        # copy_volume expects sizes in MiB, we store integer GiB
        # be sure to convert before passing in
        try:
            self._create_volume(volume['name'],
                                self._sizestr(volume['size']),
                                self.configuration.lvm_type,
                                mirror_count)

            self.vg.activate_lv(temp_snapshot['name'], is_snapshot=True)
            volutils.copy_volume(
                self.local_path(temp_snapshot),
                self.local_path(volume),
                src_vref['size'] * units.Ki,
                self.configuration.volume_dd_blocksize,
                execute=self._execute,
                sparse=self._sparse_copy_volume)
        finally:
            self.delete_snapshot(temp_snapshot)

    def clone_image(self, context, volume,
                    image_location, image_meta,
                    image_service):
        return None, False

    def get_volume_stats(self, refresh=False):
        """Get volume status.

        If 'refresh' is True, run update the stats first.
        """

        if refresh:
            self._update_volume_stats()

        return self._stats

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
    






    
class VolumeDriver(ManageableVD, CloneableImageVD, ManageableSnapshotsVD,
                   MigrateVD, BaseVD):
    def check_for_setup_error(self):
        raise NotImplementedError()

    def create_volume(self, volume):
        raise NotImplementedError()

    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a volume from a snapshot.

        If volume_type extra specs includes 'replication: <is> True'
        the driver needs to create a volume replica (secondary),
        and setup replication between the newly created volume and
        the secondary volume.
        """

        raise NotImplementedError()

    def create_replica_test_volume(self, volume, src_vref):
        raise NotImplementedError()

    def delete_volume(self, volume):
        raise NotImplementedError()

    def create_snapshot(self, snapshot):
        """Creates a snapshot."""
        raise NotImplementedError()

    def delete_snapshot(self, snapshot):
        """Deletes a snapshot."""
        raise NotImplementedError()

    def local_path(self, volume):
        raise NotImplementedError()

    def clear_download(self, context, volume):
        pass

    def extend_volume(self, volume, new_size):
        msg = _("Extend volume not implemented")
        raise NotImplementedError(msg)

    def manage_existing(self, volume, existing_ref):
        msg = _("Manage existing volume not implemented.")
        raise NotImplementedError(msg)

    def revert_to_snapshot(self, context, volume, snapshot):
        """Revert volume to snapshot.

        Note: the revert process should not change the volume's
        current size, that means if the driver shrank
        the volume during the process, it should extend the
        volume internally.
        """
        msg = _("Revert volume to snapshot not implemented.")
        raise NotImplementedError(msg)

    def manage_existing_get_size(self, volume, existing_ref):
        msg = _("Manage existing volume not implemented.")
        raise NotImplementedError(msg)

    def get_manageable_volumes(self, cinder_volumes, marker, limit, offset,
                               sort_keys, sort_dirs):
        msg = _("Get manageable volumes not implemented.")
        raise NotImplementedError(msg)

    def unmanage(self, volume):
        pass

    def manage_existing_snapshot(self, snapshot, existing_ref):
        msg = _("Manage existing snapshot not implemented.")
        raise NotImplementedError(msg)

    def manage_existing_snapshot_get_size(self, snapshot, existing_ref):
        msg = _("Manage existing snapshot not implemented.")
        raise NotImplementedError(msg)

    def get_manageable_snapshots(self, cinder_snapshots, marker, limit, offset,
                                 sort_keys, sort_dirs):
        msg = _("Get manageable snapshots not implemented.")
        raise NotImplementedError(msg)

    def unmanage_snapshot(self, snapshot):
        """Unmanage the specified snapshot from Cinder management."""

    def retype(self, context, volume, new_type, diff, host):
        return False, None

    # #######  Interface methods for DataPath (Connector) ########
    def ensure_export(self, context, volume):
        raise NotImplementedError()

    def create_export(self, context, volume, connector):
        raise NotImplementedError()

    def create_export_snapshot(self, context, snapshot, connector):
        raise NotImplementedError()

    def remove_export(self, context, volume):
        raise NotImplementedError()

    def remove_export_snapshot(self, context, snapshot):
        raise NotImplementedError()

    def initialize_connection(self, volume, connector, **kwargs):
        raise NotImplementedError()

    def initialize_connection_snapshot(self, snapshot, connector, **kwargs):
        """Allow connection from connector for a snapshot."""

    def terminate_connection(self, volume, connector, **kwargs):
        """Disallow connection from connector

        :param volume: The volume to be disconnected.
        :param connector: A dictionary describing the connection with details
                          about the initiator. Can be None.
        """

    def terminate_connection_snapshot(self, snapshot, connector, **kwargs):
        """Disallow connection from connector for a snapshot."""

    def create_consistencygroup(self, context, group):
        """Creates a consistencygroup.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :returns: model_update

        model_update will be in this format: {'status': xxx, ......}.

        If the status in model_update is 'error', the manager will throw
        an exception and it will be caught in the try-except block in the
        manager. If the driver throws an exception, the manager will also
        catch it in the try-except block. The group status in the db will
        be changed to 'error'.

        For a successful operation, the driver can either build the
        model_update and return it or return None. The group status will
        be set to 'available'.
        """
        raise NotImplementedError()

    def create_consistencygroup_from_src(self, context, group, volumes,
                                         cgsnapshot=None, snapshots=None,
                                         source_cg=None, source_vols=None):
        """Creates a consistencygroup from source.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be created.
        :param volumes: a list of volume dictionaries in the group.
        :param cgsnapshot: the dictionary of the cgsnapshot as source.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :param source_cg: the dictionary of a consistency group as source.
        :param source_vols: a list of volume dictionaries in the source_cg.
        :returns: model_update, volumes_model_update

        The source can be cgsnapshot or a source cg.

        param volumes is retrieved directly from the db. It is a list of
        cinder.db.sqlalchemy.models.Volume to be precise. It cannot be
        assigned to volumes_model_update. volumes_model_update is a list of
        dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        To be consistent with other volume operations, the manager will
        assume the operation is successful if no exception is thrown by
        the driver. For a successful operation, the driver can either build
        the model_update and volumes_model_update and return them or
        return None, None.
        """
        raise NotImplementedError()

    def delete_consistencygroup(self, context, group, volumes):
        """Deletes a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be deleted.
        :param volumes: a list of volume dictionaries in the group.
        :returns: model_update, volumes_model_update

        param volumes is retrieved directly from the db. It is a list of
        cinder.db.sqlalchemy.models.Volume to be precise. It cannot be
        assigned to volumes_model_update. volumes_model_update is a list of
        dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate volumes_model_update and model_update
        and return them.

        The manager will check volumes_model_update and update db accordingly
        for each volume. If the driver successfully deleted some volumes
        but failed to delete others, it should set statuses of the volumes
        accordingly so that the manager can update db correctly.

        If the status in any entry of volumes_model_update is 'error_deleting'
        or 'error', the status in model_update will be set to the same if it
        is not already 'error_deleting' or 'error'.

        If the status in model_update is 'error_deleting' or 'error', the
        manager will raise an exception and the status of the group will be
        set to 'error' in the db. If volumes_model_update is not returned by
        the driver, the manager will set the status of every volume in the
        group to 'error' in the except block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager. The statuses of the
        group and all volumes in it will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and volumes_model_update and return them or
        return None, None. The statuses of the group and all volumes
        will be set to 'deleted' after the manager deletes them from db.
        """
        raise NotImplementedError()

    def update_consistencygroup(self, context, group,
                                add_volumes=None, remove_volumes=None):
        """Updates a consistency group.

        :param context: the context of the caller.
        :param group: the dictionary of the consistency group to be updated.
        :param add_volumes: a list of volume dictionaries to be added.
        :param remove_volumes: a list of volume dictionaries to be removed.
        :returns: model_update, add_volumes_update, remove_volumes_update

        model_update is a dictionary that the driver wants the manager
        to update upon a successful return. If None is returned, the manager
        will set the status to 'available'.

        add_volumes_update and remove_volumes_update are lists of dictionaries
        that the driver wants the manager to update upon a successful return.
        Note that each entry requires a {'id': xxx} so that the correct
        volume entry can be updated. If None is returned, the volume will
        remain its original status. Also note that you cannot directly
        assign add_volumes to add_volumes_update as add_volumes is a list of
        cinder.db.sqlalchemy.models.Volume objects and cannot be used for
        db update directly. Same with remove_volumes.

        If the driver throws an exception, the status of the group as well as
        those of the volumes to be added/removed will be set to 'error'.
        """
        raise NotImplementedError()

    def create_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Creates a cgsnapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be created.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: model_update, snapshots_model_update

        param snapshots is retrieved directly from the db. It is a list of
        cinder.db.sqlalchemy.models.Snapshot to be precise. It cannot be
        assigned to snapshots_model_update. snapshots_model_update is a list
        of dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate snapshots_model_update and model_update
        and return them.

        The manager will check snapshots_model_update and update db accordingly
        for each snapshot. If the driver successfully deleted some snapshots
        but failed to delete others, it should set statuses of the snapshots
        accordingly so that the manager can update db correctly.

        If the status in any entry of snapshots_model_update is 'error', the
        status in model_update will be set to the same if it is not already
        'error'.

        If the status in model_update is 'error', the manager will raise an
        exception and the status of cgsnapshot will be set to 'error' in the
        db. If snapshots_model_update is not returned by the driver, the
        manager will set the status of every snapshot to 'error' in the except
        block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager and the statuses of
        cgsnapshot and all snapshots will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and snapshots_model_update and return them or
        return None, None. The statuses of cgsnapshot and all snapshots
        will be set to 'available' at the end of the manager function.
        """
        raise NotImplementedError()

    def delete_cgsnapshot(self, context, cgsnapshot, snapshots):
        """Deletes a cgsnapshot.

        :param context: the context of the caller.
        :param cgsnapshot: the dictionary of the cgsnapshot to be deleted.
        :param snapshots: a list of snapshot dictionaries in the cgsnapshot.
        :returns: model_update, snapshots_model_update

        param snapshots is retrieved directly from the db. It is a list of
        cinder.db.sqlalchemy.models.Snapshot to be precise. It cannot be
        assigned to snapshots_model_update. snapshots_model_update is a list
        of dictionaries. It has to be built by the driver. An entry will be
        in this format: {'id': xxx, 'status': xxx, ......}. model_update
        will be in this format: {'status': xxx, ......}.

        The driver should populate snapshots_model_update and model_update
        and return them.

        The manager will check snapshots_model_update and update db accordingly
        for each snapshot. If the driver successfully deleted some snapshots
        but failed to delete others, it should set statuses of the snapshots
        accordingly so that the manager can update db correctly.

        If the status in any entry of snapshots_model_update is
        'error_deleting' or 'error', the status in model_update will be set to
        the same if it is not already 'error_deleting' or 'error'.

        If the status in model_update is 'error_deleting' or 'error', the
        manager will raise an exception and the status of cgsnapshot will be
        set to 'error' in the db. If snapshots_model_update is not returned by
        the driver, the manager will set the status of every snapshot to
        'error' in the except block.

        If the driver raises an exception during the operation, it will be
        caught by the try-except block in the manager and the statuses of
        cgsnapshot and all snapshots will be set to 'error'.

        For a successful operation, the driver can either build the
        model_update and snapshots_model_update and return them or
        return None, None. The statuses of cgsnapshot and all snapshots
        will be set to 'deleted' after the manager deletes them from db.
        """
        raise NotImplementedError()

    def clone_image(self, volume, image_location, image_id, image_meta,
                    image_service):
        return None, False

    def get_pool(self, volume):
        """Return pool name where volume reside on.

        :param volume: The volume hosted by the driver.
        :returns: name of the pool where given volume is in.
        """
        return None

    def migrate_volume(self, context, volume, host):
        return (False, None)

    def accept_transfer(self, context, volume, new_user, new_project):
        pass

    