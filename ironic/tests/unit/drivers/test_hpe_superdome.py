import unittest
from ironic.drivers import hpe_superdome
from ironic.drivers.modules.hpe_superdome import boot as superdome_boot
from ironic.drivers.modules.redfish import boot as redfish_boot

class TestHpeSuperdomeHardware(unittest.TestCase):
    def test_supported_boot_interfaces_override(self):
        hw = hpe_superdome.HpeSuperdomeHardware()
        boot_ifaces = hw.supported_boot_interfaces
        # Ensure the custom boot interface is present
        self.assertIn(superdome_boot.HpeSuperdomeRedfishVirtualMediaBoot, boot_ifaces)

if __name__ == '__main__':
    unittest.main()
