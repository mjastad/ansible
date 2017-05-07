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
DOCUMENTATION = '''
---
module: na_eseries_ethernet
short_description: Manage ethernet adapters on storage array controller
description:
     - Allows for detailed management of ethernet adapters on storage controllers in NetApp E-series storage arrays.
version_added: "2.2"
author: Kevin Hulquest (@hulquest)
extends_documentation_fragment:
    - auth_basic
options:
  alias:
    description:
      - The alias of the ethernet adapter you wish to target. 
      - This along with C(mac_address) is what drives the logic to deterimine which adapter is targeted
      - Note, This module does not allow you to modify the alias of the adapter.
    required: True
  ssid:
    description:
      - the storage system array identifier
    required: True
  mac_address:
    description:
      - The MAC address of the ethernet adapter you wish to target. Note, this module does not allow you to modify the MAC address.
    required: True
  interfaceName:
    description:
      - The name that the ethernet adapter should have, such as 'gei0'.
    required: False
  enableRemoteAccess:
    description:
      - Whether or not to permit remote login via the adapter
    default: False
  ipv4GatewayAddress:
    description:
      - the ipv4 gateway address
    required: False
  ipv6GatewayAddress:
    description:
      - the ipv6 gateway address
    required: False
  ipv4Enabled:
    description:
      - Whether or not to enable ipv4
    default: False
    choices: [True, False]
  ipv6Enabled:
    description:
      - Whether or not to enable ipv6
    default: False
    choices: [True, False]
  ipv4AddressConfigMethod:
    description:
      - Whether ipv4 should use DHCP or statically define a address
    default: configDhcp
    choices: ['configDhcp', 'configStatic']
  ipv6AddressConfigMethod:
    description:
      - Whether ipv6 should be stateless or statically defined
    default: configDhcp
    choices: ['configStateless', 'configStatic']
  ipv4Address:
    description:
      - The ipv4 address to use. Required if C(ipv4AddressConfigMethod) is set to configStatic
    required: False
  ipv6StaticRoutableAddress:
    description:
      - The static, routable address for ipv6
    required: False
  ipv6LocalAddress:
    description:
      - the local ipv6 address
    required: False
  ipv4SubnetMask:
    description:
      - the subnet mask when using ipv4
    required: False
  speedSetting:
    description:
      - the ethernet adapter's speeding setting
    required: False
    default: speedNone
    choices: ['speedNone', 'speedAutoNegotiated', 'speed10MbitHalfDuplex', 'speed10MbitFullDuplex', 'speed100MbitHalfDuplex', 'speed100MbitFullDuplex', 'speed1000MbitHalfDuplex', 'speed1000MbitFullDuplex']
notes:
  - Failure to define or supply all the parameters will result in API defaults being used.
'''

EXAMPLES = '''
# Ensure that the device with the Alias 'Ansible1-A' and the Mac address of 0080E5299C24 is properly configured
- name: Ensure adapter is configured
  na_eseries_ethernet:
    interfaceName: gei0
    mac_address: 0080E5299C24
    enableRemoteAccess: True
    ipv4GatewayAddress: 10.251.230.1
    ipv4Enabled: yes
    ssid: 1
    alias: Ansible1-A
    ipv4Address: 10.251.230.41 
    ipv4SubnetMask: 255.255.255.0
    ipv6Enabled: no
    ipv4AddressConfigMethod: configStatic
    speedSetting speedAutoNegotiated
    api_url: https://10.10.10.10:8080/devmgr/v2
    api_username: rw
    api_password: rw

'''
RETURN = """
"""

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json"
}


def request(url, data=None, headers=None, method='GET', use_proxy=True,
            force=False, last_mod_time=None, timeout=10, validate_certs=True,
            url_username=None, url_password=None, http_agent=None, force_basic_auth=False, ignore_errors=False):
    try:
        r = open_url(url=url, data=data, headers=headers, method=method, use_proxy=use_proxy,
                     force=force, last_mod_time=last_mod_time, timeout=timeout, validate_certs=validate_certs,
                     url_username=url_username, url_password=url_password, http_agent=http_agent,
                     force_basic_auth=force_basic_auth)
    except urllib2.HTTPError, err:
        r = err.fp

    try:
        raw_data = r.read()
        data = json.loads(raw_data) if raw_data else None
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


def check_ethernet_adapters(module, ssid, alias, mac_address, api_url, user, pwd, **post_dict):
    list_ethernet = "storage-systems/%s/configuration/ethernet-interfaces" % ssid
    url = api_url + list_ethernet
    rc, all_nics = request(url, headers=HEADERS, url_username=user, url_password=pwd)
    target_nic = None
    is_matching = True

    # Grab NIC with matching alias and MAC address
    for nic in all_nics:
        if nic['alias'] == alias and nic['macAddr'] == mac_address:
            target_nic = nic
            post_dict['controllerRef'] = nic['controllerRef']
            post_dict['interfaceRef'] = nic['interfaceRef']

    for attr, key in post_dict.iteritems():
        try:
            if target_nic[attr] != key:
                return False, post_dict
        except KeyError:
            e = get_exception()
            # These are two keys that don't map 1:1 to the post body so we catch them here
            if e.message == "speedSetting":
                if target_nic["configuredSpeedSetting"] != key:
                    return False, post_dict

            elif e.message == "enableRemoteAccess":
                if target_nic["rloginEnabled"] != key:
                    print("no rlogin match")
                    return False, post_dict

    return is_matching, post_dict


def main():
    # if '--interactive' in sys.argv:
    # early import the module and reset the complex args
    # import ansible.module_utils.basic

    # ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
    #     # controllerRef="070000000000000000000001",
    #     interfaceName="gei0",
    #     mac_address="0080E5299C24",
    #     enableRemoteAccess=True,
    #     ipv4GatewayAddress="10.251.230.1",
    #     ipv6GatewayAddress='',
    #     ipv6StaticRoutableAddress='',
    #     # interfaceRef="2800070000000000000000000001000000000000",
    #     ipv4Enabled=True,
    #     ipv4Address="10.251.230.41",
    #     ipv4SubnetMask="255.255.255.0",
    #     ipv6Enabled=False,
    #     # ['configDhcp', 'configStatic', '__UNDEFINED']
    #     ipv4AddressConfigMethod='configStatic',
    #     ipv6LocalAddress='',
    #     # 'configStatic', 'configStateless'
    #     ipv6AddressConfigMethod=None,
    #     # ['speedNone', 'speedAutoNegotiated', 'speed10MbitHalfDuplex', 'speed10MbitFullDuplex', 'speed100MbitHalfDuplex', 'speed100MbitFullDuplex', 'speed1000MbitHalfDuplex', 'speed1000MbitFullDuplex', '__UNDEFINED']
    #     speedSetting='speedAutoNegotiated',
    #     api_url="http://localhost:8080/devmgr/v2",
    #     api_username="rw",
    #     api_password="rw",
    #     ssid=1,
    #     alias="Ansible1-A",
    # ))

    module = AnsibleModule(
        argument_spec=dict(
            alias=dict(required=True),
            mac_address=dict(required=True),
            ssid=dict(required=True),
            interfaceName=dict(required=False),
            enableRemoteAccess=dict(required=False, default=False, type='bool'),
            ipv4GatewayAddress=dict(required=False),
            ipv6GatewayAddress=dict(required=False),
            ipv4Enabled=dict(required=False, default=False, type='bool'),
            ipv6Enabled=dict(required=False, default=False, type='bool'),
            ipv4AddressConfigMethod=dict(required=False, default='configDhcp',
                                         choices=['configDhcp', 'configStatic', '']),
            ipv6AddressConfigMethod=dict(required=False, defaulte='configStatic',
                                         choices=['configStatic', 'configStateless', None]),
            ipv4Address=dict(required=False),
            ipv6StaticRoutableAddress=dict(required=False),
            ipv6LocalAddress=dict(required=False),
            ipv4SubnetMask=dict(required=False),
            speedSetting=dict(required=False, default='speedNone',
                              choices=['speedNone', 'speedAutoNegotiated', 'speed10MbitHalfDuplex',
                                       'speed10MbitFullDuplex', 'speed100MbitHalfDuplex', 'speed100MbitFullDuplex',
                                       'speed1000MbitHalfDuplex', 'speed1000MbitFullDuplex']),
            api_url=dict(required=False),
            api_password=dict(required=False, no_log=True),
            api_username=dict(required=False),
        ),
        required_if=[
            ('ipv4AddressConfigMethod', 'configStatic', ['ipv4Address']),
            ('ipv4Enabled', True, ['ipv4GatewayAddress', 'ipv4SubnetMask']),
            ('ipv6AddressConfigMethod', 'configStatic', ['ipv6StaticRoutableAddress']),
            ('ipv6Enabled', True, ['ipv6LocalAddress'])
        ]
    )

    api_url = module.params.pop('api_url')
    pwd = module.params.pop('api_password')
    user = module.params.pop('api_username')
    alias = module.params.pop('alias')
    mac_address = module.params.pop('mac_address')
    ssid = module.params.pop('ssid')

    if not api_url.endswith('/'):
        api_url += '/'

    post_dict = dict()

    for key, value in module.params.iteritems():
        if not value in [None, ""]:
            post_dict[key] = value

    is_matching, updated_post = check_ethernet_adapters(module, ssid, alias, mac_address, api_url, user, pwd,
                                                        **post_dict)

    if is_matching:
        module.exit_json(changed=False, msg="Ethernet adapter matches desired state", **post_dict)

    else:
        url = api_url + "storage-systems/%s/configuration/ethernet-interfaces" % ssid
        body = json.dumps(updated_post, indent=2)
        rc, data = request(url, data=body, method="POST", headers=HEADERS, url_username=user, url_password=pwd)

        module.exit_json(changed=True, msg="Adapter Updated", **data)


from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
