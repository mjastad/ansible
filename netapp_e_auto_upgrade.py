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

# WORK IN PROGRESS

DOCUMENTATION = """
---
module: na_eseries_auto_upgrade
short_description: Auto update to the latest version of the SANtricity Web Services Proxy.
description:
    - Updates the version of the SANtricity Web Services Proxy.
version_added: '2.2'
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
    download_attempts:
        description:
            - The amount of times to check for download status updates
            - "Note: This multiplied by the download_update_wait_time will give you the amount of time the system will have to download the update in seconds before timing out."
            - "Default: 5 checks"
    download_update_wait_time:
        description:
            - The amount of time in seconds to wait between checking the download status.
            - "Note: This multiplied by the download_attempts will give you the amount of time the system will have to download the update in seconds before timing out."
            - "Default: 5 seconds"
    update_attempts:
        description:
            - The amount of times to check the update installation process for status updates
            - "Note: This multiplied by the update_update_wait_time will give you the amount of time the system will have to install the update in seconds before timing out."
            - "Default: 5 checks"
    update_update_wait_time:
        description:
            - The amount of time in seconds to wait between checking the download status.
            - "Note: This multiplied by the update_attempts will give you the amount of time the system will have to download the update in seconds before timing out."
            - "Default: 5 seconds"
"""

EXAMPLES = """
    - name: Auto Update
      _na_eseries_auto_upgrade:
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        validate_certs: "{{ validate_certs }}"
"""

RETURN = """
msg:
    description: Success message
    returned: success
    type: string
    sample: "Sucsessfully updated system Correlation is: 1"
"""

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}

def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=False, ignore_errors=False):
    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except urllib2.HTTPError as err:
        r = err.fp

    try:
        raw_data = r.read()
        data = json.loads(raw_data) if raw_data else None
    except Exception:
        if ignore_errors:
            pass
        else:
            raise Exception(raw_data)

    resp_code = r.getcode()

    if resp_code >= 400 and not ignore_errors:
        raise Exception(resp_code, data)
    else:
        return resp_code, data


def start_download(module, api_url, api_pwd, api_usr):
    get_status = 'upgrade/download'
    url = api_url + get_status
    status = request(url, url_username=api_usr, url_password=api_pwd, headers=HEADERS, method='POST',
                     validate_certs=module.params['validate_certs'])

    if status[0] == 200:
        correlationId = status[1]['correlationId']
        started = True
    else:
        correlationId = status[0]
        started = False

    return started, correlationId


def start_update(module, api_url, api_pwd, api_usr):
    get_status = 'upgrade/reload'
    url = api_url + get_status
    status = request(url, url_username=api_usr, url_password=api_pwd, headers=HEADERS, method='POST',
                     validate_certs=module.params['validate_certs'])

    if status[0] == 200:
        correlationId = status[1]['correlationId']
        started = True
    else:
        correlationId = status[0]
        started = False

    return started, correlationId


def verify_finish_download(module, api_url, api_pwd, api_usr, download_start_correlationId, attempts, update_wait_time):
    last_known = -1
    wait = 5
    attempt = 0

    while attempt < attempts:
        get_status = 'events?lastKnown=%s&wait=%s' % (last_known, wait)
        url = api_url + get_status
        status = request(url, url_username=api_usr, url_password=api_pwd, headers=HEADERS, method='GET',
                         validate_certs=module.params['validate_certs'])

        if status[0] == 200:
            relevent_events = []
            for event in status[1]:
                if event.has_key('correlationId'):
                    if event['correlationId'] == download_start_correlationId:
                        relevent_events.append(event)

            if relevent_events[-1]['status'] == 'success':
                return True, ''
            elif relevent_events[-1]['status'] == 'error':
                return False, relevent_events[-1]['statusMessage']
            else:
                last_known = int(relevent_events[-1]['eventNumber'])
                attempt += 1
                sleep(update_wait_time)
        else:
            return False, status[0]


def verify_finish_update(module, api_url, api_pwd, api_usr, download_start_correlationId, attempts, update_wait_time):
    last_known = -1
    wait = 5
    attempt = 0

    while attempt < attempts:
        get_status = 'events?lastKnown=%s&wait=%s' % (last_known, wait)
        url = api_url + get_status
        status = request(url, url_username=api_usr, url_password=api_pwd, headers=HEADERS, method='GET',
                         validate_certs=module.params['validate_certs'])

        if status[0] == 200:
            relevent_events = []
            for event in status[1]:
                if event.has_key('correlationId'):
                    if event['correlationId'] == download_start_correlationId:
                        relevent_events.append(event)

            if relevent_events[-1]['status'] == 'success':
                return True, ''
            elif relevent_events[-1]['status'] == 'error':
                return False, relevent_events[-1]['statusMessage']
            else:
                last_known = int(relevent_events[-1]['eventNumber'])
                attempt += 1
                sleep(update_wait_time)
        else:
            return False, status[0]


def main():
    module = AnsibleModule(argument_spec=dict(
        api_url=dict(required=True),
        api_username=dict(required=False),
        api_password=dict(required=False, no_log=True),
        validate_certs=dict(required=False, default=True),
        download_attempts=dict(required=False, default=5),
        download_update_wait_time=dict(required=False, default=5),
        update_attempts=dict(required=False, default=5),
        update_update_wait_time=dict(required=False, default=5)
    ),
    )

    p = module.params

    api_url = p.pop('api_url')
    user = p.pop('api_username')
    pwd = p.pop('api_password')
    download_attempts = p.pop('download_attempts')
    download_update_wait_time = int(p.pop('download_update_wait_time'))
    update_attempts = p.pop('update_attempts')
    update_update_wait_time = int(p.pop('update_update_wait_time'))

    if not api_url.endswith('/'):
        api_url += '/'

    download_started, download_start_correlationId = start_download(module, api_url, pwd, user)

    if download_started:
        download_finished, download_finish_correlationId = verify_finish_download(module, api_url, pwd, user,
                                                                                  download_start_correlationId,
                                                                                  download_attempts,
                                                                                  download_update_wait_time)
        if download_finished:
            update_started, update_started_correlationId = start_update(module, api_url, pwd, user)
            if update_started:
                update_finished, update_finish_correlationId = verify_finish_update(module, api_url, pwd, user,
                                                                                    update_started_correlationId,
                                                                                    update_attempts,
                                                                                    update_update_wait_time)
                if update_finished:
                    module.exit_json(changed=True,
                                     msg='Sucsessfully updated system Correlation is: %s' % update_finish_correlationId)
                else:
                    module.fail_json(msg="Could not finish update. Error code: %s" % update_finish_correlationId)
            else:
                module.fail_json(msg="Could not start update. Error code: %s" % download_start_correlationId)
        else:
            module.fail_json(msg="Could not finish download. Error code: %s" % download_finish_correlationId)
    else:
        module.fail_json(msg="Could not start download. Error code: %s" % download_start_correlationId)


from time import sleep

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
