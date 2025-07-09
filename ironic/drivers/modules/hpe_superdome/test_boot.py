import unittest
from unittest import mock
from ironic.drivers.modules.hpe_superdome import boot

class FakeNode:
    def __init__(self, driver_info):
        self.driver_info = driver_info

class FakeTask:
    def __init__(self, driver_info):
        self.node = FakeNode(driver_info)

class TestHpeSuperdomeRedfishVirtualMediaBoot(unittest.TestCase):
    def setUp(self):
        self.boot = boot.HpeSuperdomeRedfishVirtualMediaBoot()
        self.driver_info = {
            'redfish_system_id': '/redfish/v1/Systems/Partition0'
        }
        self.task = FakeTask(self.driver_info)

    @mock.patch('ironic.drivers.modules.redfish.utils.get_system')
    def test_real_class_and_driver_info(self, mock_get_system):
        mock_system = mock.Mock()
        mock_conn = mock.Mock()
        mock_system._conn = mock_conn
        mock_get_system.return_value = mock_system
        mock_conn.get.return_value = 'virtual_media_resource'

        result = self.boot._get_virtual_media_resource(self.task)
        mock_get_system.assert_called_once_with(self.task.node)
        mock_conn.get.assert_called_once_with('/redfish/v1/Systems/Partition0/VirtualMedia')
        self.assertEqual(result, 'virtual_media_resource')

    @mock.patch('ironic.drivers.modules.redfish.utils.get_system')
    def test_missing_system_id(self, mock_get_system):
        self.task.node.driver_info = {}
        with self.assertRaises(Exception) as cm:
            self.boot._get_virtual_media_resource(self.task)
        self.assertIn('Missing', str(cm.exception))

    @mock.patch('ironic.drivers.modules.redfish.utils.get_system')
    def test_virtual_media_path_for_node016r_bb097(self, mock_get_system):
        self.task.node.driver_info = {
            'redfish_system_id': '/redfish/v1/Systems/Partition0'
        }
        mock_system = mock.Mock()
        mock_conn = mock.Mock()
        mock_system._conn = mock_conn
        mock_get_system.return_value = mock_system
        mock_conn.get.return_value = 'virtual_media_resource'

        result = self.boot._get_virtual_media_resource(self.task)
        mock_get_system.assert_called_once_with(self.task.node)
        mock_conn.get.assert_called_once_with('/redfish/v1/Systems/Partition0/VirtualMedia')
        self.assertEqual(result, 'virtual_media_resource')

if __name__ == '__main__':
    unittest.main()
