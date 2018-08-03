# Copyright 2016 Intel Corporation
# Copyright 2014 OpenStack Foundation
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg

from ironic.common.i18n import _

opts = [
    cfg.BoolOpt('enabled',
                default=False,
                help=_('Enable the openstack-watcher-middleware')),
    cfg.StrOpt('service_type',
               default='baremetal',
               help=_('The type of the service')),
    cfg.StrOpt('cadf_service_name',
               default='service/compute/baremetal',
               help=_('The name of the service according to CADF')),
    cfg.StrOpt('config_file',
               help=_('Path to configuration file')),
    cfg.StrOpt('statsd_host',
               default="127.0.0.1",
               help=_('Host of the StatsD backend')),
    cfg.IntOpt('statsd_port',
               default=9125,
               help=_('Port of the StatsD backend')),
]


def register_opts(conf):
    conf.register_opts(opts, group='watcher')
