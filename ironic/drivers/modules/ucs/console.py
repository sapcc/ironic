import os

from oslo_log import log as logging
from oslo_utils import excutils

from ironic.common import exception
from ironic.conf import CONF
from ironic.drivers.modules import console_utils
from ironic.drivers.modules.ipmitool import _console_pwfile_path
from ironic.drivers.modules.ipmitool import _parse_driver_info
from ironic.drivers.modules.ipmitool import IPMIShellinaboxConsole

from ironic_lib import utils as ironic_utils

LOG = logging.getLogger(__name__)


class UcsShellInaboxConsole(IPMIShellinaboxConsole):
    def start_console(self, task):
        """Start a remote console for the node.

        :param task: a task from TaskManager
        :raises: InvalidParameterValue if required ipmi parameters are missing
        :raises: PasswordFileFailedToCreate if unable to create a file
                 containing the password
        :raises: ConsoleError if the directory for the PID file cannot be
                 created
        :raises: ConsoleSubprocessFailed when invoking the subprocess failed
        """
        driver_info = _parse_driver_info(task.node)
        path = _console_pwfile_path(driver_info['uuid'])
        pw_file = console_utils.make_persistent_password_file(
            path, driver_info['password'] or '\0')
        user = driver_info.get('username')
        address = driver_info.get('address')

        cmd = (("/:%(uid)s:%(gid)s:HOME:" + CONF.console.ssh_command_pattern) %
                {'uid': os.getuid(),
                 'gid': os.getgid(),
                 'pw_file': pw_file,
                 'username': user,
                 'address': address
                 })

        try:
            console_utils.start_shellinabox_console(driver_info['uuid'],
                                                    driver_info['port'], cmd)
        except (exception.ConsoleError, exception.ConsoleSubprocessFailed):
            with excutils.save_and_reraise_exception():
                ironic_utils.unlink_without_raise(path)
