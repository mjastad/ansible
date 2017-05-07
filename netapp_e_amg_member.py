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
module: netapp_e_amg_member (Asynchronous Mirror Group)
short_description: Add or remove volume members to async mirror groups.
description:
    - Allows for the addition or removal of members to asynchronous mirror groups for NetApp E-series storage arrays.
    - Use the name of the volume names for the mirrored pair.  Object ids are not required.
    - The size of the target volume must be of equal or greater capacity.
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
    secondary_percent_capacity:
        description:
        - Percentage of the capacity of the secondary volume to use for the repository capacity.
        default: 20
    ssid:
        description:
        - The ID of the primary storage array for the async mirror member action
        required: yes
"""
EXAMPLES = """
---
vars:
    amg_member_primary_volume: primary
    amg_member_secondary_volume: target
    amg_member_state: absent
    set_amg_member: yes
    amg_array_name: foo
    amg_name: MirrorGroup1
tasks:
    - name: Add mirror pair to async mirror group.
      storage/netapp/netapp_e_amg_member:
        ssid: "{{ ssid }}"
        api_url: "{{ netapp_api_url }}"
        api_username: "{{ netapp_api_username }}"
        api_password: "{{ netapp_api_password }}"
        name: "{{ amg_name }}"
        state: "{{ amg_member_state }}"
        primary_volume: "{{ amg_member_primary_volume }}"
        secondary_volume: "{{ amg_member_secondary_volume }}"
      when: set_amg_member

"""
RETURN = """
msg = 'Mirror pair did not exist.'
msg = 'Mirror pair deleted. Primary[primvaryVolName]. Target[targetVolName]'
Json facts are returned when the mirror pair is created.
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
            force=False, last_mod_time=None, timeout=10, validate_certs=False,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=False, ignore_errors=False):
    """Handle http operations to the SANtricity REST API."""
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
    """Find a volume by name.  The full volume object is returned."""
    if secondary_id:
        ssid = secondary_id
    endpoint = url + '/storage-systems/%s/volumes' % ssid

    try:
        (rc, vol_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    except:
        err = get_exception()
        module.fail_json(msg="Error fetching volumes. Id[%s]. Error[%s]" % (ssid, err.message))
    try:
        vol = filter(lambda d: d['label'] == name, vol_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no volume %s associated with storage array %s" % (name, ssid))

    return vol


def get_sp_by_name(module, ssid, name, url, user, pwd, certs, secondary_id=None):
    """Find a storage pool by name.  The full storage pool object is returned."""
    if secondary_id:
        ssid = secondary_id

    endpoint = url + '/storage-systems/%s/storage-pools' % ssid
    try:
        (rc, sp_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    except:
        err = get_exception()
        module.fail_json(msg="Error fetching storage pools. Id[%s]. Error[%s]" % (ssid, err.message))
    try:
        sp = filter(lambda d: d['label'] == name, sp_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no storage pool %s associated with storage array %s" % (name, ssid))

    return sp


def get_amg_by_name(module, ssid, name, url, user, pwd, certs):
    """Find an async mirror group by name."""
    endpoint = url + '/storage-systems/%s/async-mirrors' % ssid
    try:
        (rc, amg_objs) = request(endpoint, url_username=user, url_password=pwd, validate_certs=certs, headers=HEADERS)
    except:
        err = get_exception()
        module.fail_json(msg="Failed fetching async mirrors. Id [%s]. Error[%s]" % (ssid, err.message))
    try:
        amg = filter(lambda d: d['label'] == name, amg_objs)[0]['id']
    except IndexError:
        module.fail_json(msg="There is no async mirror group  %s associated with storage array %s" % (name, ssid))
    secondary_array_id = filter(lambda d: d['label'] == name, amg_objs)[0]['remoteTargetId']

    return amg, secondary_array_id


def amg_membership_present(module, ssid, amg_id, pvol, svol, url, user, pwd, certs):
    """Determine if a mirror pair already exists."""
    endpoint = url + '/storage-systems/%s/async-mirrors/%s/pairs' % (ssid, amg_id)
    try:
        (rc, members) = request(endpoint, url_username=user, url_password=pwd, headers=HEADERS, validate_certs=certs)
    except:
        err = get_exception()
        module.fail_json(msg="Failed fetching mirrored pairs. Id[%s]. AMG Id[%s]. Error[%s]" %
                             (ssid, amg_id, err.message))
    for mem_obj in members:
        if mem_obj['localVolumeName'] == pvol and mem_obj['remoteVolumeName'] == svol:
            return True, mem_obj

    return False, None


def make_or_delete_mirror_pair(url=None, pwd=None, user=None, headers=None, method='POST', data=None):
    """Handle post and delete operations for adding members to an AMG."""
    (rc, member_data) = request(url, url_password=pwd, url_username=user, headers=headers, method=method,
                                data=data)
    return rc, member_data


def main():
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
    state = args['state']
    name = args['name']
    p_pool = args['primary_pool']
    s_pool = args['secondary_pool']
    p_vol = args['primary_volume']
    s_vol = args['secondary_volume']
    url = args['api_url']
    usr = args['api_username']
    pwd = args['api_password']
    val_certs = args['validate_certs']
    conn = (url, usr, pwd, val_certs)

    # retrieve the amg id and the api id for the secondary array
    amg_id, s_id = get_amg_by_name(module, ssid, name, *conn)
    pvol_id = get_vol_by_name(module, ssid, p_vol, url, usr, pwd, val_certs)
    svol_id = get_vol_by_name(module, ssid, s_vol, url, usr, pwd, val_certs, secondary_id=s_id)
    req = dict(
        primaryVolumeRef=pvol_id,
        secondaryVolumeRef=svol_id,
    )
    if p_pool:
        p_pool = get_sp_by_name(module, ssid, p_pool, *conn)
        req['primaryPoolId'] = p_pool
    if s_pool:
        s_pool = get_sp_by_name(module, ssid, s_pool, url, usr, pwd, val_certs, secondary_id=s_id)
        req['secondaryPoolId'] = s_pool
    (present, amg) = amg_membership_present(module, ssid, amg_id, p_vol, s_vol, *conn)

    msg = None
    changed = False
    if state == 'present':
        if present:
            module.exit_json(changed=changed, **amg)
        else:
            try:
                url += '/storage-systems/%s/async-mirrors/%s/pairs' % (ssid, amg_id)
                (rc, member_data) = make_or_delete_mirror_pair(url=url, pwd=pwd, user=usr, headers=HEADERS,
                                                               method='POST', data=json.dumps(req))
            except:
                err = get_exception()
                module.fail_json(msg="Failed to add member to AMG. Id[%s]. AMG Id[%s]. Error[%s]" %
                                     (ssid, amg_id, err.message))

            module.exit_json(changed=True, **member_data)
    else:
        # state = absent
        if present:
            pair_id = amg['id']
            url += '/storage-systems/%s/async-mirrors/%s/pairs/%s' % (ssid, amg_id, pair_id)
            try:
                make_or_delete_mirror_pair(url=url, pwd=pwd, user=usr, headers=HEADERS, method='DELETE')
                msg = 'Mirror pair deleted. Primary[%s]. Target[%s]' % (p_vol, s_vol)
                changed = True
            except:
                err = get_exception()
                module.fail_json(msg="Error deleting mirror pair. Id[%s]. AmgId[%s].  PairId[%s].  Error[%s]." %
                                     (ssid, amg_id, pair_id, err.message))
        else:
            msg = 'Mirror pair did not exist.'

        module.exit_json(changed=changed, msg=msg)


if __name__ == '__main__':
    main()
