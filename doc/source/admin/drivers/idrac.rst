============
iDRAC driver
============

Overview
========

The integrated Dell Remote Access Controller (iDRAC_) is an out-of-band
management platform on Dell EMC servers, and is supported directly by
the ``idrac`` hardware type. This driver uses the Dell Web Services for
Management (WSMAN) protocol and the standard Distributed Management Task
Force (DMTF) Redfish protocol to perform all of its functions.

iDRAC_ hardware is also supported by the generic ``ipmi`` and ``redfish``
hardware types, though with smaller feature sets.

Key features of the Dell iDRAC driver include:

* Out-of-band node inspection
* Boot device management
* Power management
* RAID controller management and RAID volume configuration
* BIOS settings configuration

Ironic Features
---------------

The ``idrac`` hardware type supports the following Ironic interfaces:

* `Inspect Interface`_: Hardware inspection
* Management Interface: Boot device management
* Power Interface: Power management
* `RAID Interface`_: RAID controller and disk management
* `Vendor Interface`_: BIOS management

Prerequisites
-------------

The ``idrac`` hardware type requires the ``python-dracclient`` library
to be installed on the ironic conductor node(s) if an Ironic node is
configured to use an ``idrac-wsman`` interface implementation, for example::

    sudo pip install 'python-dracclient>=3.1.0'

Additionally, the ``idrac`` hardware type requires the ``sushy`` library
to be installed on the ironic conductor node(s) if an Ironic node is
configured to use an ``idrac-redfish`` interface implementation, for example::

   sudo pip install 'python-dracclient>=3.1.0' 'sushy>=2.0.0'

Enabling
--------

The iDRAC driver supports WSMAN for the inspect, management, power,
raid, and vendor interfaces. In addition, it supports Redfish for
the inspect, management, and power interfaces. The iDRAC driver
allows you to mix and match WSMAN and Redfish interfaces.

The ``idrac-wsman`` implementation must be enabled to use WSMAN for
an interface. The ``idrac-redfish`` implementation must be enabled
to use Redfish for an interface.

.. NOTE::
   Redfish is supported for only the inspect, management, and power
   interfaces at the present time.

To enable the ``idrac`` hardware type with the minimum interfaces,
all using WSMAN, add the following to your ``/etc/ironic/ironic.conf``:

.. code-block:: ini

    [DEFAULT]
    enabled_hardware_types=idrac
    enabled_management_interfaces=idrac-wsman
    enabled_power_interfaces=idrac-wsman

To enable all optional features (inspection, RAID, and vendor passthru)
using Redfish where it is supported and WSMAN where not, use the
following configuration:

.. code-block:: ini

    [DEFAULT]
    enabled_hardware_types=idrac
    enabled_inspect_interfaces=idrac-redfish
    enabled_management_interfaces=idrac-redfish
    enabled_power_interfaces=idrac-redfish
    enabled_raid_interfaces=idrac-wsman
    enabled_vendor_interfaces=idrac-wsman

Below is the list of supported interface implementations in priority
order:

================     ===================================================
Interface            Supported Implementations
================     ===================================================
``bios``             ``no-bios``
``boot``             ``ipxe``, ``pxe``
``console``          ``no-console``
``deploy``           ``iscsi``, ``direct``, ``ansible``, ``ramdisk``
``inspect``          ``idrac-wsman``, ``idrac``, ``idrac-redfish``,
                     ``inspector``, ``no-inspect``
``management``       ``idrac-wsman``, ``idrac``, ``idrac-redfish``
``network``          ``flat``, ``neutron``, ``noop``
``power``            ``idrac-wsman``, ``idrac``, ``idrac-redfish``
``raid``             ``idrac-wsman``, ``idrac``, ``no-raid``
``rescue``           ``no-rescue``, ``agent``
``storage``          ``noop``, ``cinder``, ``external``
``vendor``           ``idrac-wsman``, ``idrac``, ``no-vendor``
================     ===================================================

.. NOTE::
   ``idrac`` is the legacy name of the WSMAN interface. It has been
   deprecated in favor of ``idrac-wsman`` and may be removed in a
   future release.

Protocol-specific Properties
----------------------------

The WSMAN and Redfish protocols require different properties to be specified
in the Ironic node's ``driver_info`` field to communicate with the bare
metal system's iDRAC.

The WSMAN protocol requires the following properties:

* ``drac_username``: The WSMAN user name to use when communicating
  with the iDRAC. Usually ``root``.
* ``drac_password``: The password for the WSMAN user to use when
  communicating with the iDRAC.
* ``drac_address``: The IP address of the iDRAC.

The Redfish protocol requires the following properties:

* ``redfish_username``: The Redfish user name to use when
  communicating with the iDRAC. Usually ``root``.
* ``redfish_password``: The password for the Redfish user to use
  when communicating with the iDRAC.
* ``redfish_address``: The URL address of the iDRAC. It must include the
  authority portion of the URL, and can optionally include the scheme. If
  the scheme is missing, https is assumed.
* ``redfish_system_id``: The Redfish ID of the server to be
  managed. This should always be: ``/redfish/v1/Systems/System.Embedded.1``.

For other Redfish protocol parameters see :doc:`/admin/drivers/redfish`.

If using only interfaces which use WSMAN (``idrac-wsman``), then only
the WSMAN properties must be supplied. If using only interfaces which
use Redfish (``idrac-redfish``), then only the Redfish properties must be
supplied. If using a mix of interfaces, where some use WSMAN and others
use Redfish, both the WSMAN and Redfish properties must be supplied.

Enrolling
---------

The following command enrolls a bare metal node with the ``idrac``
hardware type using WSMAN for all interfaces:

.. code-block:: bash

    openstack baremetal node create --driver idrac \
        --driver-info drac_username=user \
        --driver-info drac_password=pa$$w0rd \
        --driver-info drac_address=drac.host

The following command enrolls a bare metal node with the ``idrac``
hardware type using Redfish for all interfaces:

.. code-block:: bash

    openstack baremetal node create --driver idrac \
        --driver-info redfish_username=user \
        --driver-info redfish_password=pa$$w0rd \
        --driver-info redfish_address=drac.host \
        --driver-info redfish_system_id=/redfish/v1/Systems/System.Embedded.1 \
        --inspect-interface idrac-redfish \
        --management-interface idrac-redfish \
        --power-interface idrac-redfish \
        --raid-interface no-raid \
        --vendor-interface no-vendor

The following command enrolls a bare metal node with the ``idrac``
hardware type assuming a mix of Redfish and WSMAN interfaces are used:

.. code-block:: bash

    openstack baremetal node create --driver idrac \
        --driver-info drac_username=user \
        --driver-info drac_password=pa$$w0rd
        --driver-info drac_address=drac.host \
        --driver-info redfish_username=user \
        --driver-info redfish_password=pa$$w0rd \
        --driver-info redfish_address=drac.host \
        --driver-info redfish_system_id=/redfish/v1/Systems/System.Embedded.1 \
        --inspect-interface idrac-redfish \
        --management-interface idrac-redfish \
        --power-interface idrac-redfish

.. NOTE::
   If using WSMAN for the management interface, then WSMAN must be  used
   for the power interface. The same applies to Redfish. It is currently not
   possible to use Redfish for one and WSMAN for the other.

Inspect Interface
=================

The Dell iDRAC out-of-band inspection process catalogs all the same
attributes of the server as the IPMI driver. Unlike IPMI, it does this
without requiring the system to be rebooted, or even to be powered on.
Inspection is performed using the Dell WSMAN or Redfish protocol directly
without affecting the operation of the system being inspected.

The inspection discovers the following properties:

* ``cpu_arch``: cpu architecture
* ``cpus``: number of cpus
* ``local_gb``: disk size in gigabytes
* ``memory_mb``: memory size in megabytes

Extra capabilities:

* ``boot_mode``: UEFI or BIOS boot mode.

It also creates baremetal ports for each NIC port detected in the system.
The ``idrac-wsman`` inspect interface discovers which NIC ports are
configured to PXE boot and sets ``pxe_enabled`` to ``True`` on those ports.
The ``idrac-redfish`` inspect interface does not currently set ``pxe_enabled``
on the ports. The user should ensure that ``pxe_enabled`` is set correctly on
the ports following inspection with the ``idrac-redfish`` inspect interface.


RAID Interface
==============

See :doc:`/admin/raid` for more information on Ironic RAID support.

The following properties are supported by the iDRAC WSMAN raid interface
implementation, ``idrac-wsman``:


Mandatory properties
--------------------

* ``size_gb``: Size in gigabytes (integer) for the logical disk. Use ``MAX`` as
  ``size_gb`` if this logical disk is supposed to use the rest of the space available.
* ``raid_level``: RAID level for the logical disk. Valid values are
  ``0``, ``1``, ``5``, ``6``, ``1+0``, ``5+0`` and ``6+0``.

.. NOTE::
  ``JBOD`` and ``2`` are not supported, and will fail with reason: 'Cannot
  calculate spans for RAID level.'

Optional properties
-------------------

* ``is_root_volume``: Optional. Specifies whether this disk is a root volume.
  By default, this is ``False``.
* ``volume_name``: Optional. Name of the volume to be created. If this is not
  specified, it will be auto-generated.

Backing physical disk hints
---------------------------

See :doc:`/admin/raid` for more information on backing disk hints.

These are machine-independent information. The hints are specified for each
logical disk to help Ironic find the desired disks for RAID configuration.

* ``disk_type``
* ``interface_type``
* ``share_physical_disks``
* ``number_of_physical_disks``

Backing physical disks
----------------------

These are Dell RAID controller-specific values and must match the
names provided by the iDRAC.

* ``controller``: Mandatory. The name of the controller to use.
* ``physical_disks``: Optional. The names of the physical disks to use.

.. NOTE::
  ``physical_disks`` is a mandatory parameter if the property ``size_gb`` is set to ``MAX``.

Examples
--------

Creation of RAID ``1+0`` logical disk with six disks on one controller:

.. code-block:: json

  { "logical_disks":
    [ { "controller": "RAID.Integrated.1-1",
        "is_root_volume": "True",
        "physical_disks": [
          "Disk.Bay.0:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.1:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.2:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.3:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.4:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.5:Enclosure.Internal.0-1:RAID.Integrated.1-1"],
        "raid_level": "1+0",
        "size_gb": "MAX"}]}


Manual RAID Invocation
----------------------

The following command can be used to delete any existing RAID configuration.
It deletes all virtual disks/RAID volumes, unassigns all global and dedicated
hot spare physical disks, and clears foreign configuration:

.. code-block:: bash

  openstack baremetal node clean --clean-steps \
    '[{"interface": "raid", "step": "delete_configuration"}]' ${node_uuid}


The following command shows an example of how to set the target RAID
configuration:

.. code-block:: bash

  openstack baremetal node set --target-raid-config '{ "logical_disks":
    [ { "controller": "RAID.Integrated.1-1",
        "is_root_volume": true,
        "physical_disks": [
          "Disk.Bay.0:Enclosure.Internal.0-1:RAID.Integrated.1-1",
          "Disk.Bay.1:Enclosure.Internal.0-1:RAID.Integrated.1-1"],
        "raid_level": "0",
        "size_gb": "MAX"}]}' ${node_uuid}


The following command can be used to create a RAID configuration:

.. code-block:: bash

  openstack baremetal node clean --clean-steps \
    '[{"interface": "raid", "step": "create_configuration"}]' ${node_uuid}


When the physical disk names or controller names are not known, the
following Python code example shows how the ``python-dracclient`` can
be used to fetch the information directly from the Dell bare metal:

.. code-block:: python

  import dracclient.client


  client = dracclient.client.DRACClient(
      host="192.168.1.1",
      username="root",
      password="calvin")
  controllers = client.list_raid_controllers()
  print(controllers)

  physical_disks = client.list_physical_disks()
  print(physical_disks)


Vendor Interface
================

Dell iDRAC BIOS management is available through the Ironic vendor
passthru interface.

========================  ============   ======================================
Method Name               HTTP Method    Description
========================  ============   ======================================
``abandon_bios_config``   ``DELETE``     Abandon a BIOS configuration job.
``commit_bios_config``    ``POST``       Commit a BIOS configuration job
                                         submitted through ``set_bios_config``.
                                         Required argument: ``reboot`` -
                                         indicates whether a reboot job
                                         should be automatically created
                                         with the config job. Returns a
                                         dictionary containing the ``job_id``
                                         key with the ID of the newly created
                                         config job, and the
                                         ``reboot_required`` key indicating
                                         whether the node needs to be rebooted
                                         to execute the config job.
``get_bios_config``       ``GET``        Returns a dictionary containing the
                                         node's BIOS settings.
``list_unfinished_jobs``  ``GET``        Returns a dictionary containing
                                         the key ``unfinished_jobs``; its value
                                         is a list of dictionaries. Each
                                         dictionary represents an unfinished
                                         config job object.
``set_bios_config``       ``POST``       Change the BIOS configuration on
                                         a node. Required argument: a
                                         dictionary of {``AttributeName``:
                                         ``NewValue``}. Returns a dictionary
                                         containing the ``is_commit_required``
                                         key indicating whether
                                         ``commit_bios_config`` needs to be
                                         called to apply the changes and the
                                         ``is_reboot_required`` value
                                         indicating whether the server must
                                         also be rebooted. Possible values are
                                         ``true`` and ``false``.
========================  ============   ======================================


Examples
--------

Get BIOS Config
~~~~~~~~~~~~~~~

.. code-block:: bash

  openstack baremetal node passthru call --http-method GET ${node_uuid} get_bios_config

Snippet of output showing virtualization enabled:

.. code-block:: json

  {"ProcVirtualization": {
        "current_value": "Enabled",
        "instance_id": "BIOS.Setup.1-1:ProcVirtualization",
        "name": "ProcVirtualization",
        "pending_value": null,
        "possible_values": [
            "Enabled",
            "Disabled"],
        "read_only": false }}

There are a number of items to note from the above snippet:

* ``name``: this is the name to use in a call to ``set_bios_config``.
* ``current_value``: the current state of the setting.
* ``pending_value``: if the value has been set, but not yet committed,
  the new value is shown here. The change can either be committed or
  abandoned.
* ``possible_values``: shows a list of valid values which can be used
  in a call to ``set_bios_config``.
* ``read_only``: indicates if the value is capable of being changed.

Set BIOS Config
~~~~~~~~~~~~~~~

.. code-block:: bash

  openstack baremetal node passthru call ${node_uuid} set_bios_config --arg "name=value"


Walkthrough of perfoming a BIOS configuration change:

The following section demonstrates how to change BIOS configuration settings,
detect that a commit and reboot are required, and act on them accordingly. The
two properties that are being changed are:

* Enable virtualization technology of the processor
* Globally enable SR-IOV

.. code-block:: bash

  openstack baremetal node passthru call ${node_uuid} set_bios_config \
    --arg "ProcVirtualization=Enabled" \
    --arg "SriovGlobalEnable=Enabled"

This returns a dictionary indicating what actions are required next:

.. code-block:: json

  {
    "is_reboot_required": true,
    "is_commit_required": true
  }


Commit BIOS Changes
~~~~~~~~~~~~~~~~~~~

The next step is to commit the pending change to the BIOS. Note that in this
example, the ``reboot`` argument is set to ``true``. The response indicates
that a reboot is no longer required as it has been scheduled automatically
by the ``commit_bios_config`` call. If the reboot argument is not supplied,
the job is still created, however it remains in the ``scheduled`` state
until a reboot is performed. The reboot can be initiated through the
Ironic power API.

.. code-block:: bash

  openstack baremetal node passthru call ${node_uuid} commit_bios_config \
    --arg "reboot=true"

.. code-block:: json

  {
    "job_id": "JID_499377293428",
    "reboot_required": false
  }

The state of any executing job can be queried:

.. code-block:: bash

  openstack baremetal node passthru call --http-method GET ${node_uuid} list_unfinished_jobs


.. code-block:: json

  {"unfinished_jobs":
      [{"status": "Scheduled",
        "name": "ConfigBIOS:BIOS.Setup.1-1",
        "until_time": "TIME_NA",
        "start_time": "TIME_NOW",
        "message": "Task successfully scheduled.",
        "percent_complete": "0",
        "id": "JID_499377293428"}]}


Abandon BIOS Changes
~~~~~~~~~~~~~~~~~~~~

Instead of committing, a pending change can be abandoned:

.. code-block:: bash

  openstack baremetal node passthru call --http-method DELETE ${node_uuid} abandon_bios_config

The abandon command does not provide a response body.


Change Boot Mode
----------------

The boot mode of the iDRAC can be changed to:

* BIOS - Also called legacy or traditional boot mode. The BIOS initializes the
  system’s processors, memory, bus controllers, and I/O devices. After
  initialization is complete, the BIOS passes control to operating system (OS)
  software. The OS loader uses basic services provided by the system BIOS to
  locate and load OS modules into system memory. After booting the system, the
  BIOS and embedded management controllers execute system management
  algorithms, which monitor and optimize the condition of the underlying
  hardware. BIOS configuration settings enable fine-tuning of the
  performance, power management, and reliability features of the system.
* UEFI - The Unified Extensible Firmware Interface does not change the
  traditional purposes of the system BIOS. To a large extent, a UEFI-compliant
  BIOS performs the same initialization, boot, configuration, and management
  tasks as a traditional BIOS. However, UEFI does change the interfaces and
  data structures the BIOS uses to interact with I/O device firmware and
  operating system software. The primary intent of UEFI is to eliminate
  shortcomings in the traditional BIOS environment, enabling system firmware to
  continue scaling with industry trends.

The UEFI boot mode offers:

* Improved partitioning scheme for boot media
* Support for media larger than 2 TB
* Redundant partition tables
* Flexible handoff from BIOS to OS
* Consolidated firmware user interface
* Enhanced resource allocation for boot device firmware

The boot mode can be changed via the vendor passthru interface as follows:

.. code-block:: bash

  openstack baremetal node passthru call ${node_uuid} set_bios_config \
    --arg "BootMode=Uefi"

  openstack baremetal node passthru call ${node_uuid} commit_bios_config \
    --arg "reboot=true"

.. code-block:: bash

  openstack baremetal node passthru call ${node_uuid} set_bios_config \
    --arg "BootMode=Bios"

  openstack baremetal node passthru call ${node_uuid} commit_bios_config \
    --arg "reboot=true"

Known Issues
============

Nodes go into maintenance mode
------------------------------

After some period of time, nodes managed by the ``idrac`` hardware type may go
into maintenance mode in Ironic. This issue can be worked around by changing
the Ironic power state poll interval to 70 seconds. See
``[conductor]sync_power_state_interval`` in ``/etc/ironic/ironic.conf``.

.. _Ironic_RAID: https://docs.openstack.org/ironic/latest/admin/raid.html
.. _iDRAC: https://www.dell.com/idracmanuals

Vendor passthru timeout
-----------------------

When iDRAC is not ready and executing vendor passthru commands, they take more
time as waiting for iDRAC to become ready again and then time out, for example:

.. code-block:: bash

  openstack baremetal node passthru call --http-method GET \
    aed58dca-1b25-409a-a32f-3a817d59e1e0 list_unfinished_jobs
  Timed out waiting for a reply to message ID 547ce7995342418c99ef1ea4a0054572 (HTTP 500)

To avoid this need to increase timeout for messaging in ``/etc/ironic/ironic.conf``
and restart Ironic API service.

.. code-block:: ini

  [DEFAULT]
  rpc_response_timeout = 600

Timeout when powering off
-------------------------

Some servers might be slow when soft powering off and time out. The default retry count
is 6, resulting in 30 seconds timeout (the default retry interval set by
``post_deploy_get_power_state_retry_interval`` is 5 seconds).
To resolve this issue, increase the timeout to 90 seconds by setting the retry count to
18 as follows:

.. code-block:: ini

    [agent]
    post_deploy_get_power_state_retries = 18

Redfish management interface failure to set boot device
-------------------------------------------------------

When using the ``idrac-redfish`` management interface with certain iDRAC
firmware versions (at least versions 2.70.70.70, 4.00.00.00, and
4.10.10.10) and attempting to set the boot device on a baremetal server
that is configured to UEFI boot, the iDRAC will return the following
error::

    Unable to Process the request because the value entered for the
    parameter Continuous is not supported by the implementation.

To work around this issue, set the ``force_persistent_boot_device`` parameter
in ``driver-info`` on the node to ``Never`` by running the following command
from the command line:

.. code-block:: bash

  openstack baremetal node set --driver-info \
    force_persistent_boot_device=Never ${node_uuid}
