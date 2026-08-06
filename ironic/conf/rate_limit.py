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
                help=_('Enable the openstack-rate-limit-middleware')),
    cfg.StrOpt('config_file', default="/etc/ironic/ratelimit.yaml",
               help=_('Path to the rate limiting middleware configuration file')),
    cfg.StrOpt('clock_accuracy', default="1ns",
               help=_('If this middleware enforces rate limits in multiple replicas of an API,'
                      'the clock accuracy of the individual replicas can be configured as follows.'
                      'Especially in high-load scenarios, involving a sign. number of concurrent '
                      'requests, choosing nanosecond accuracy is advised - given support by OS and '
                      'clock.')),
    cfg.StrOpt('service_type', default="baremetal",
               help=_('The service type according to CADF specification')),
    cfg.StrOpt('rate_limit_by',
               help=_('Per default rate limits are applied based on '
                      '`initiator_project_id`. However, this can also be se to '
                      '`initiator_host_address` or `target_project_id`')),
    cfg.IntOpt('max_sleep_time_seconds', default=20,
               help=_('The maximal time a request can be suspended in seconds. '
                      'Instead of immediately returning a rate limit response, '
                      'a request can be suspended until the specified maximum '
                      'duration to fit the configured rate limit. This feature '
                      'can be disabled by setting the max sleep time to 0 seconds.')),
    cfg.IntOpt('log_sleep_time_seconds', default=10,
               help=_('Log requests that are going to be suspended for '
                      'log_sleep_time_seconds <= t <= max_sleep_time_seconds.')),
    cfg.StrOpt('backend_secret_file', default='',
               help=_('Password for redis backend stored in a file')),
    cfg.StrOpt('backend_host', default="127.0.0.1",
               help=_('Redis backend host for rate limiting middleware')),
    cfg.PortOpt('backend_port', default=6379,
                help=_('Redis backend port for rate limiting middleware')),
    cfg.IntOpt('backend_max_connections', default=100,
               help=_('Maximum connections for redis connection pool.')),
    cfg.IntOpt('backend_timeout_seconds', default=2,
               help=_('Timeout for obtaining a connection to the backend. '
                      'It should be >= 1 second. Skips rate limit on timeout.')),
]


def register_opts(conf):
    conf.register_opts(opts, group='rate_limit')
