#
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

import six
from base64 import urlsafe_b64encode
from os import urandom
from six.moves import http_client
from six.moves.urllib import parse
from swiftclient import client as swift_client
from swiftclient import exceptions as swift_exceptions
from swiftclient import utils as swift_utils

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common import keystone
from ironic.conf import CONF


def _get_swift_session(**session_args):
    return keystone.get_session('swift', **session_args)


class SwiftAPI(object):
    """API for communicating with Swift."""

    def __init__(self, **session_args):

        # TODO(pas-ha): swiftclient does not support keystone sessions ATM.
        # Must be reworked when LP bug #1518938 is fixed.
        params = {}
        if CONF.deploy.object_store_endpoint_type == 'radosgw':
            params = {'authurl': CONF.swift.auth_url,
                      'user': CONF.swift.username,
                      'key': CONF.swift.password}
        else:
            container_project_id = session_args.pop('container_project_id', None)
            session = _get_swift_session(**session_args)
            preauthurl = keystone.get_service_url(session,
					          service_type='object-store')
            session_project_id = session.get_project_id()

	    if container_project_id and preauthurl.endswith(session_project_id):
                preauthurl = preauthurl.replace(session_project_id, container_project_id)

            params = {
                'retries': CONF.swift.swift_max_retries,
                'preauthurl': preauthurl,
                'preauthtoken': keystone.get_admin_auth_token(session)
            }
            # NOTE(pas-ha):session.verify is for HTTPS urls and can be
            # - False (do not verify)
            # - True (verify but try to locate system CA certificates)
            # - Path (verify using specific CA certificate)
            verify = session.verify
            params['insecure'] = not verify
            if verify and isinstance(verify, six.string_types):
                params['cacert'] = verify

        self.connection = swift_client.Connection(**params)

    def create_object(self, container, object, filename,
                      object_headers=None):
        """Uploads a given file to Swift.

        :param container: The name of the container for the object.
        :param object: The name of the object in Swift
        :param filename: The file to upload, as the object data
        :param object_headers: the headers for the object to pass to Swift
        :returns: The Swift UUID of the object
        :raises: SwiftOperationError, if any operation with Swift fails.
        """
        try:
            self.connection.put_container(container)
        except swift_exceptions.ClientException as e:
            operation = _("put container")
            raise exception.SwiftOperationError(operation=operation, error=e)

        with open(filename, "r") as fileobj:

            try:
                obj_uuid = self.connection.put_object(container,
                                                      object,
                                                      fileobj,
                                                      headers=object_headers)
            except swift_exceptions.ClientException as e:
                operation = _("put object")
                raise exception.SwiftOperationError(operation=operation,
                                                    error=e)

        return obj_uuid

    def get_temp_url(self, container, object, timeout):
        """Returns the temp url for the given Swift object.

        :param container: The name of the container in which Swift object
            is placed.
        :param object: The name of the Swift object.
        :param timeout: The timeout in seconds after which the generated url
            should expire.
        :returns: The temp url for the object.
        :raises: SwiftOperationError, if any operation with Swift fails.
        """
        temp_url_key = self._get_temp_url_key()

        parse_result = parse.urlparse(self.connection.url)
        swift_object_path = '/'.join((parse_result.path, container, object))
        url_path = swift_utils.generate_temp_url(swift_object_path, timeout,
                                                 temp_url_key, 'GET')
        return parse.urlunparse((parse_result.scheme,
                                 parse_result.netloc,
                                 url_path,
                                 None,
                                 None,
                                 None))

    def _get_temp_url_key(self):
        try:
            account_info = self.connection.head_account()
        except swift_exceptions.ClientException as e:
            operation = _("head account")
            raise exception.SwiftOperationError(operation=operation,
                                                error=e)

        temp_url_key = account_info.get('x-account-meta-temp-url-key', None)

        if temp_url_key:
            return temp_url_key

        if CONF.swift.swift_set_temp_url_key:
            temp_url_key = urlsafe_b64encode(urandom(30))
            self.connection.post_account(headers={'x-account-meta-temp-url-key': temp_url_key})
            return temp_url_key

        operation = _("get temp-url-key")
        raise exception.SwiftTempUrlKeyNotFoundError(operation=operation)

    def delete_object(self, container, object):
        """Deletes the given Swift object.

        :param container: The name of the container in which Swift object
            is placed.
        :param object: The name of the object in Swift to be deleted.
        :raises: SwiftObjectNotFoundError, if object is not found in Swift.
        :raises: SwiftOperationError, if operation with Swift fails.
        """
        try:
            self.connection.delete_object(container, object)
        except swift_exceptions.ClientException as e:
            operation = _("delete object")
            if e.http_status == http_client.NOT_FOUND:
                raise exception.SwiftObjectNotFoundError(obj=object,
                                                         container=container,
                                                         operation=operation)

            raise exception.SwiftOperationError(operation=operation, error=e)

    def head_object(self, container, object):
        """Retrieves the information about the given Swift object.

        :param container: The name of the container in which Swift object
            is placed.
        :param object: The name of the object in Swift
        :returns: The information about the object as returned by
            Swift client's head_object call.
        :raises: SwiftOperationError, if operation with Swift fails.
        """
        try:
            return self.connection.head_object(container, object)
        except swift_exceptions.ClientException as e:
            operation = _("head object")
            raise exception.SwiftOperationError(operation=operation, error=e)

    def update_object_meta(self, container, object, object_headers):
        """Update the metadata of a given Swift object.

        :param container: The name of the container in which Swift object
            is placed.
        :param object: The name of the object in Swift
        :param object_headers: the headers for the object to pass to Swift
        :raises: SwiftOperationError, if operation with Swift fails.
        """
        try:
            self.connection.post_object(container, object, object_headers)
        except swift_exceptions.ClientException as e:
            operation = _("post object")
            raise exception.SwiftOperationError(operation=operation, error=e)
