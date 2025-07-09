from ironic.drivers.modules.redfish import boot as redfish_boot
from ironic.drivers import generic
from ironic.drivers.modules.hpe_superdome import boot

class HpeSuperdomeHardware(generic.GenericHardware):

    @property
    def supported_boot_interfaces(self):
        inherited = super().supported_boot_interfaces
        try:
            idx = inherited.index(redfish_boot.RedfishVirtualMediaBoot)
            inherited[idx] = boot.HpeSuperdomeRedfishVirtualMediaBoot
        except ValueError:
            inherited.append(boot.HpeSuperdomeRedfishVirtualMediaBoot)
        return inherited

    @property
    def supported_management_interfaces(self):
        return super().supported_management_interfaces

    @property
    def supported_power_interfaces(self):
        return super().supported_power_interfaces

