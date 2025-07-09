from ironic.common import exception
from ironic.drivers.modules.redfish import boot as redfish_boot
from ironic.common import boot_devices
from ironic.drivers.modules.redfish import utils as redfish_utils
from oslo_log import log

LOG = log.getLogger(__name__)

class HpeSuperdomeRedfishVirtualMediaBoot(redfish_boot.RedfishVirtualMediaBoot):

    VIRTUAL_MEDIA_DEVICES = {
        boot_devices.FLOPPY: 'Floppy',
        boot_devices.CDROM: 'DVD',
    }

    def _get_virtual_media_resource(self, task, device=None):
        """Override to get virtual media resource from /Systems path on Superdome."""
        system_path = task.node.driver_info.get('redfish_system_id')
        if not system_path:
            raise exception.MissingParameterValue(
                "Missing 'redfish_system_id' in driver_info.")

        system = redfish_utils.get_system(task.node)
        conn = system._conn  # sushy System object connection
        virtual_media_path = system_path.rstrip('/') + '/VirtualMedia'
        return conn.get(virtual_media_path)

