#!/usr/bin/python

# (c) 2016, NetApp, Inc
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
DOCUMENTATION = """
---
module: netapp_e_controller_firmware
short_description: Update firmware for the SANtricity E/EF-Series platform.
description: >
    - Download, check, update and initiate controller firmware for NetApp E-series storage array controllers. This is an
    idempotent module that has several operational options that can tune the module to fit the needs of your playbook.
    The first check is to determine if the storage array is already at the required firmware level.  If it is then no
    other action is taken.
    When the firmware on the storage array is not at the required level (can be lower), the
    I(version_not_present_action) parameter will be checked.  It must be one of two values C(none or upgrade).  When the
    value is none, the module will exit successfully and report the status in the response json data.  Although the
    value name is upgrade, it can be used to downgrade the firmware too.  When the value is upgrade, the module will
    install the firmware file to the storage array by way of the SANtricity WebServices Proxy.  The module does not
    support an embedded deployment of the Web Services Proxy on the E2800 platform at this time.  The upgrade is a
    synchronous action.  It can be made asynchronous in your playbook or through configuration parameters provided with
    the module.  To configure the module to be asynchronous, set I(expiration_time) to 0 and I(expiration_action) to
    continue.  By default, the expiration_time is 10 minutes and will fail if the firmware is not activated once 10
    minutes passes.  10 minutes is a safe duration of time that will allow the E/EF platform to install the firmware to
    the redundant systems in the storage enclosure.  While I/Os will continue to be serviced during the upgrade it is
    better to schedule firmware upgrades at a times other than peak IO workloads.
version_added: '2.2'
dependency: >
    - Requires python module requests.  This module makes HTTP POST calls with file input which requires a more robust
    HTTP library.
author: Kevin Hulquest (@hulquest)
options:
    api_username:
        required: true
        description:
        - The username to authenticate with the SANtricity WebServices Proxy or embedded REST API.
    api_password:
        required: true
        description:
        - The password to authenticate with the SANtricity WebServices Proxy or embedded REST API.
    api_url:
        required: true
        description:
        - The url to the SANtricity WebServices Proxy or embedded REST API.
        example:
        - https://prod-1.wahoo.acme.com/devmgr/v2
    validate_certs:
        required: false
        default: true
        description:
        - Should https certificates be validated?
    required_version:
        required: false
        description: >
            - The version of controller firmware to be running on the storage array.
            - If the version is not present, then use the version_not_present_action parameter to dictate if new
            firmware should be uploaded.
    version_not_present_action:
        required: false
        default: none
        choice: none, upgrade
        description:
            - Take this action if the required_version is not present on the storage array.
    firmware_to_upload:
        required: true
        description:
            - The location of the firmware file to be uploaded.
            - This will verify firmware first.
    expiration_time:
        required: false
        default: 10
        description:
            - The number of minutes to check the firmware activation status.
            - When the firmware upgrade is complete the module no longer waits.
            - When the wait time is met and the firmware update is not complete the module will fail.
    expiration_action:
        required: false
        choice: fail, continue
        default: fail
        description:
            - When the expiration time is passed, use this action to determine if the play is to succeed or not.
            - This parameter can be used in conjunction with expiration_time to simply start the firmware upgrade
              process on a number of storage arrays and not wait until they all complete.  Conversely, this parameter
              can be used to wait for each firmware upgrade to successfully complete and fail when it doesn't.

"""
EXAMPLES = """
---
    - name: Upgrade firmware but don't fail if the operation takes more than 15 minutes.
      netapp_e_controller_firmware:
        ssid: "{{ ssid }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        required_version: "08.25.08.00"
        firmware_to_upload="/home/gkurian/Downloads/08.25/RC_08250800_e10_825_5501.dlp"
        version_not_present_action: "upgrade"
        expiration_time: 15
        expiration_action: "continue"
    - name: Upgrade firmware but fail if the operation takes more than 15 minutes.
      netapp_e_controller_firmware:
        ssid: "{{ ssid }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        required_version: "08.25.08.00"
        firmware_to_upload="/home/gkurian/Downloads/08.25/RC_08250800_e10_825_5501.dlp"
        version_not_present_action: "upgrade"
        expiration_time: 15
        expiration_action: "fail"
    - name: Upgrade firmware in an asynchronous fashion.
      netapp_e_controller_firmware:
        ssid: "{{ ssid }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        required_version: "08.25.08.00"
        firmware_to_upload="/home/gkurian/Downloads/08.25/RC_08250800_e10_825_5501.dlp"
        version_not_present_action: "upgrade"
        expiration_time: 0
        expiration_action: "continue"
    - name: Upgrade all storage systems
      netapp_e_controller_firmware:
        ssid: "{{ item.key }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        required_version: "08.25.08.00"
        version_not_present_action: "upgrade"
        firmware_to_upload: "/home/gkurian/Downloads/08.25/RC_08250800_e10_825_5501.dlp"
      with_dict: "{{ storage_systems }}"
      when: update_firmware
"""
RETURN = """
msg='Firmware upgrade complete. Id[array1].'
version_before_upgrade='08.20.08.00'
version_after_upgrade='08.25.07.00'
"""
import json
import time
import os

from ansible.module_utils.api import basic_auth_argument_spec
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pycompat24 import get_exception
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=True, ignore_errors=False):
    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except HTTPError:
        err = get_exception()
        r = err.fp

    try:
        raw_data = r.read()
        if raw_data:
            data = json.loads(raw_data)
        else:
            raw_data = None
    except:
        if ignore_errors:
            pass
        else:
            raise Exception(raw_data)

    resp_code = r.getcode()

    if resp_code >= 400 and not ignore_errors:
        raise Exception(resp_code, data)
    else:
        return resp_code, data


def upload_file(params):
    """Transfer the firmware file to the proxy."""
    url = 'firmware/upload'
    full_url = params['api_url'] + url

    files = {'firmwareFile': open(params['firmware_to_upload'], 'rb')}

    r = requests.post(full_url, files=files, auth=(params['api_username'], params['api_password']))
    data = json.loads(r.text)

    if r.status_code == 200:
        return {'errors': None, 'file_name': data['fileName']}
    else:
        return {'errors': data}


def poll_activation_status(module):
    """Wait for the array to report back that the firmware was upgraded sucessfully."""
    params = module.params
    now = time.time()
    action = params['expiration_action']
    expiration_time = params['expiration_time']
    then = now + (expiration_time * 60)
    while now < then:
        url = params['api_url'] + 'storage-systems/%s/cfw-upgrade' % params['ssid']
        try:
            (rc, resp) = request(url, ignore_errors=True, url_username=params['api_username'],
                                 url_password=params['api_password'], headers=HEADERS,
                                 validate_certs=params['validate_certs'])
        except:
            err = get_exception()
            module.fail_json(
                msg="Failed to activate controller firmware. Id[%s]. Error[%s]." % (params['ssid'], err.message))
        if rc == 422:
            module.fail_json(
                msg="Health check failed while upgrading controller firmware. Id[%s]. Return code[422]." %
                    params['ssid'], **resp)
        elif rc == 404 or rc == 424:
            module.fail_json(
                msg="Storage array is offline or unreachable. Id[%s]. Return code[%s]." % (params['ssid'], rc))
        else:
            status = resp['running']
            if status is True:
                time.sleep(30)
                now = time.time()
            else:
                return {'status': 'job-complete'}

    if action == 'fail':
        return {'status': 'timeout-expired'}
    else:
        return {'status': 'timeout-continue'}


def running_as_proxy(module):
    """Determine if the deployment is a proxy."""
    params = module.params
    url = params['api_url']
    utils = url.replace('v2', 'utils/about')
    try:
        (rc, resp) = request(utils, ignore_errors=True, url_username=params['api_username'],
                             url_password=params['api_password'], headers=HEADERS,
                             validate_certs=params['validate_certs'])
        if 'runningAsProxy' in resp:
            proxy = resp['runningAsProxy']
            return proxy is True
        else:
            return False
    except:
        err = get_exception()
        module.fail_json(
            msg="Failed to validate proxy deployment. Error[%s]" % err.message)


def get_firmware_version(module):
    """Get the firmware version for the storage array."""
    params = module.params
    array = 'storage-systems/%s' % params['ssid']
    url = params['api_url'] + array
    try:
        (rc, resp) = request(url, ignore_errors=True, url_username=params['api_username'],
                             url_password=params['api_password'], headers=HEADERS,
                             validate_certs=params['validate_certs'])
        if 'fwVersion' in resp:
            return resp['fwVersion']
        else:
            raise Exception('Invalid array response.')
    except:
        err = get_exception()
        module.fail_json(
            msg="Failed to get firmware version. Id[%s]. Error[%s]" % (params['ssid'], err.message))


def activate_firmware(module):
    """Activate the firmware on the storage array."""
    params = module.params
    get_status = 'storage-systems/%s/cfw-upgrade' % params['ssid']
    url = params['api_url'] + get_status
    base = os.path.basename(params['firmware_to_upload'])
    body = {
        "cfwFile": base,
    }

    rc = 404
    try:
        (rc, resp) = request(url, data=json.dumps(body), ignore_errors=True, method='POST',
                             url_username=params['api_username'], url_password=params['api_password'], headers=HEADERS,
                             validate_certs=params['validate_certs'])
    except:
        err = get_exception()
        module.fail_json(
            msg="Failed to activate controller firmware. Id[%s]. Error[%s]" % (params['ssid'], err.message))

    if rc == 202:
        request_id = 'unknown'
        if 'requestId' in resp:
            request_id = resp['requestId']
        return {'errors': None, 'requestId': request_id}
    elif rc == 422:
        module.fail_json(
            msg="Failed health check (return code 422).  The storage array is not capable of upgrading firmware at this time.")
    else:
        module.fail_json(msg="Failed to activate controller firmware. [Return code %s]." % rc)


def main():
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(
        ssid=dict(required=True, type='str'),
        api_url=dict(required=True, type='str'),
        api_username=dict(required=True, type='str'),
        api_password=dict(required=True, type='str'),
        validate_certs=dict(required=False, default=True),
        firmware_to_upload=dict(required=True, type='str'),
        expiration_time=dict(required=False, default=10, type='int'),
        expiration_action=dict(required=False, choices=['continue', 'fail'], default='fail', type='str'),
        required_version=dict(required=True, type='str'),
        version_not_present_action=dict(required=True, choices=['none', 'upgrade'], type='str')
    )

    module = AnsibleModule(argument_spec=argument_spec)

    if not HAS_REQUESTS:
        module.fail_json(msg='The requests module required for this module.  Run sudo pip install requests to resolve.')

    params = module.params

    if not params['api_url'].endswith('/'):
        params['api_url'] += '/'

    if not running_as_proxy(module):
        module.exit_json(msg='The module only supports proxy deployment.')

    version_before = get_firmware_version(module)
    required_version = params['required_version']
    if version_before == required_version:
        module.exit_json(msg='The array is at the required firmware version: %s' % version_before)
    else:
        upgrade_action = params['version_not_present_action']
        if upgrade_action == 'upgrade':
            if 'firmware_to_upload' in params and params['firmware_to_upload'] != '':
                if os.path.isfile(params['firmware_to_upload']):
                    upload_results = upload_file(params)
                    if upload_results['errors'] is not None:
                        module.fail_json(changed=False, msg='Failed to upload firmware.',
                                         error=upload_results['errors'])

                    update_results = activate_firmware(module)
                    if update_results['errors'] is not None:
                        module.fail_json(changed=False, msg='Failed to activate firmware.',
                                         error=upload_results['errors'])
                    else:
                        status = poll_activation_status(module)
                        job_status = status['status']
                        if job_status == 'job-complete':
                            version_after = get_firmware_version(module)
                            module.exit_json(msg='Firmware upgrade complete. Id[%s].' % params['ssid'], changed=True,
                                             version_before_upgrade=version_before, version_after_upgrade=version_after)
                        elif job_status == 'timeout-continue':
                            module.exit_json(
                                msg='Firmware upgrade in progress. Continue mode. Id[%s].' % params['ssid'])
                        elif job_status == 'timeout-expired':
                            module.fail_json(
                                msg='Firmware upgrade did not complete in the amount of time specified by the play.  The operation is still running on the array. Id[%s].' %
                                    params['ssid'])

                else:
                    module.fail_json(changed=False, msg='Could not find firmware file.')
        else:
            # version_not_present_action=continue
            module.exit_json(
                msg='Firmware does not meet requirement but proceeding because of parameter configuration. Id[%s].' %
                    params['ssid'], present_version=version_before)


if __name__ == '__main__':
    main()
