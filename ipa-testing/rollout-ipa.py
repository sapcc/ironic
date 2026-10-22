#!/usr/bin/env python3
"""Roll out new IPA images to all baremetal nodes in available/manageable state.

Usage: NEW_KERNEL=<uuid> NEW_RAMDISK=<uuid> NEW_BOOTLOADER=<url> python3 rollout-ipa.py
Optional: DRY_RUN=true, LIMIT=N
"""

import json
import logging
import os
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")
LOG = logging.getLogger(__name__)

SAFE_STATES = {"available", "manageable"}


for var in ("NEW_KERNEL", "NEW_RAMDISK", "NEW_BOOTLOADER"):
    if not os.environ.get(var):
        LOG.error("%s is required", var)
        sys.exit(1)

new_kernel = os.environ["NEW_KERNEL"]
new_ramdisk = os.environ["NEW_RAMDISK"]
new_bootloader = os.environ["NEW_BOOTLOADER"]
dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
limit = int(os.environ.get("LIMIT", "0"))

LOG.info("kernel:     %s", new_kernel)
LOG.info("ramdisk:    %s", new_ramdisk)
LOG.info("bootloader: %s", new_bootloader)
if dry_run:
    LOG.info("(dry run)")

result = subprocess.run(["openstack", "baremetal", "node", "list",
              "--fields", "uuid", "name", "provision_state", "driver_info",
              "-f", "json"], capture_output=True, text=True, check=True)
nodes = json.loads(result.stdout)

eligible, busy = [], []
for n in nodes:
    name = n.get("Name") or n.get("UUID", "")
    state = n.get("Provisioning State") or n.get("provision_state", "")
    di = n.get("Driver Info") or n.get("driver_info") or {}
    if state not in SAFE_STATES:
        busy.append((name, state))
    elif di.get("deploy_kernel") != new_kernel or di.get("deploy_ramdisk") != new_ramdisk:
        eligible.append(name)

LOG.info("Eligible: %d  Busy: %d", len(eligible), len(busy))

for name, state in busy:
    LOG.info("  skipped: %s=%s", name, state)

if not eligible:
    LOG.info("Nothing to do.")
    sys.exit(0)

to_update = eligible[:limit] if limit > 0 else eligible

updated, failed = 0, 0
for node in to_update:
    if dry_run:
        LOG.info("  %s ... would update", node)
        continue
    r = subprocess.run(["openstack", "baremetal", "node", "set",
             "--driver-info", f"deploy_kernel={new_kernel}",
             "--driver-info", f"deploy_ramdisk={new_ramdisk}",
             "--driver-info", f"bootloader={new_bootloader}",
             node], capture_output=True, text=True, check=False)
    if r.returncode == 0:
        LOG.info("  %s ... ok", node)
        updated += 1
    else:
        LOG.error("  %s ... FAILED: %s", node, r.stderr.strip())
        failed += 1

if dry_run:
    LOG.info("Done (dry run).")
else:
    LOG.info("Updated: %d  Failed: %d", updated, failed)
