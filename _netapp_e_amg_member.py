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
module: na_eseries_amg_member (Asynchronous Mirror Group)
short_description: add or remove members to async mirror groups 
description:
    - Allows for the addition or removal of members to asynchronous mirror groups for NetApp E-series storage arrays
version_added: '2.2'
author: Kevin Hulquest (@hulquest)
extends_documentation_fragment:
    - auth_basic
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
    name:
        description:
            - The name of the async array you wish to target.
        required: yes
    primary_pool:
        description:
            - The name of the primary storage pool to create the mirrored pair repository volume on.
            - This will default to the pool the the primary volume is located on.
        required: yes
    secondary_pool:
        description:
            - The name of the secondary storage pool to create the mirrored pair repository volume on.
            - This will default to the pool the the secondary volume is located on.
        required: yes
    primary_volume:
        description:
            - The name of the primary volume
        required: yes
    secondary_volume:
        description:
            - The name of the secondary volume
        required: yes
    percent_capacity:
        description:
        - Percentage of the capacity of the primary volume to use for the repository capacity.
        default: 20
    secondary_percent_capacity
        description:
        - Percentage of the capacity of the secondary volume to use for the repository capacity.
        default: 20
    ssid:
        description:
        - The ID of the primary storage array for the async mirror member action
        required: yes
"""
EXAMPLES = """
"""
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
from ansible.module_utils.api import *
from ansible.module_utils.six.moves.urllib.error import HTTPError


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=False, ignore_errors=False):
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
            data = None
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


def get_vol_by_name(module, ssid, name, url, user, pwd, certs, secondary_id=None):
    if secondary_id:
        ssid = secondary_id
    endpoint = url + '/storage-systems/%s/volumes' % ssid

    (rc, vol_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    try:
        vol = filter(lambda d: d['label'] == name, vol_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no volume %s associated with storage array %s" % (name, ssid))

    return vol


def get_sp_by_name(module, ssid, name, url, user, pwd, certs, secondary_id=None):
    if secondary_id:
        ssid = secondary_id

    endpoint = url + '/storage-systems/%s/storage-pools' % ssid
    (rc, sp_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    try:
        sp = filter(lambda d: d['label'] == name, sp_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no storage pool %s associated with storage array %s" % (name, ssid))

    return sp


def get_amg_by_name(module, ssid, name, url, user, pwd, certs):
    endpoint = url + '/storage-systems/%s/async-mirrors' % ssid
    (rc, amg_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    try:
        amg = filter(lambda d: d['label'] == name, amg_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no async mirror group  %s associated with storage array %s" % (name, ssid))
    secondary_array_id = filter(lambda d: d['label'] == name, amg_objs)[0]['remoteTargetId']

    return amg, secondary_array_id


def amg_membership_present(module, ssid, amg_id, pvol_id, svol_id, url, user, pwd, certs):
    endpoint = url + '/storage-systems/%s/async-mirrors/%s/pairs' % (ssid, amg_id)
    (rc, members) = request(endpoint, url_username=user, url_password=pwd, headers=HEADERS, validate_certs=certs)
    # 1600000060080E5000299B64000006055790CC6F => 0200000060080E5000299F88000005F35790CC51
    for mem_obj in members:
        print
        mem_obj['localVolume'], '=>', pvol_id, mem_obj['remoteVolume'], '=>', svol_id
        if mem_obj['localVolume'] == pvol_id and mem_obj['remoteVolume'] == svol_id:
            return True

    return False


def main():
    if "--interactive" in sys.argv:
        import ansible.module_utils.basic
        ansible.module_utils.basic._ANSIBLE_ARGS = json.dumps(dict(
            ANSIBLE_MODULE_ARGS=dict(
                state="present",
                name="MirrorGroup1",
                primary_volume="Alpha",
                secondary_volume="Bravo",
                ssid=1,
                api_username='rw',
                api_password='rw',
                api_url='http://localhost:8080/devmgr/v2'
            )))
    argument_spec = basic_auth_argument_spec()
    argument_spec.update(dict(
        ssid=dict(required=True, type='str'),
        name=dict(required=True, type='str'),
        primary_pool=dict(type='str'),
        secondary_pool=dict(type='str'),
        primary_volume=dict(required=True, type='str'),
        secondary_volume=dict(required=True, type='str'),
        percent_capacity=dict(type='int', default=20),
        secondary_percent_capacity=dict(type='int', default=20),
        state=dict(type='str', required=True, choices=['present', 'absent'])

    ))

    module = AnsibleModule(argument_spec=argument_spec)

    args = module.params

    ssid = args['ssid']
    name = args['name']
    p_pool = args['primary_pool']
    s_pool = args['secondary_pool']
    p_vol = args['primary_volume']
    s_vol = args['secondary_volume']
    pct_cap = args['percent_capacity']
    s_pct_cap = args['secondary_percent_capacity']
    url = args['api_url']
    usr = args['api_username']
    pwd = args['api_password']
    val_certs = args['validate_certs']
    conn = (url, usr, pwd, val_certs)

    # retrieve the amg id and the api id for the secondary array
    amg_id, s_id = get_amg_by_name(module, ssid, name, *conn)
    pvol_id = get_vol_by_name(module, ssid, p_vol, *conn)
    svol_id = get_vol_by_name(module, ssid, s_vol, *conn, secondary_id=s_id)

    print
    pvol_id

    if p_pool:
        p_pool = get_sp_by_name(module, ssid, p_pool, *conn)
    if s_pool:
        s_pool = get_sp_by_name(module, ssid, s_pool, *conn, secondary_id=s_id)

    if amg_membership_present(module, ssid, amg_id, pvol_id, svol_id, *conn):
        # TODO: Shoot back meta about the AMG member
        module.exit_json(changed=False)
    else:
        creation_struct = dict(
            primaryPoolId=p_pool,
            secondaryPoolId=s_pool,
            primaryVolumeRef=pvol_id,
            secondaryVolumeRef=svol_id,
            scanMedia=False,
            validateRepositoryParity=False,
            percentCapacity=pc_cap,
            secondaryPercentCapacity=s_pct_cap
        )

        (rc, new_member_data) = request(url + '/storage-systems/%s/async-mirrors/%s/pairs' % (ssid, amg_id),
                                        url_password=pwd, url_username=usr, headers=HEADERS, method='POST'
                                        )

        module.exit_json(changed=True, **new_member_data)


if __name__ == '__main__':
    main()
