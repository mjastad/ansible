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
module: na_eseries_consistency_group
short_description: Create, delete and manage consistency groups
description:
- Create, delete and manage consistency groups, consistency group members and consistency group snapshots.
version_added: '2.2'
author: Kevin Hulquest (@hulquest)
options:
    state:
        description:
            - If you want the consistency group to exist of not
        required: True
        choices: ['present', 'absent']
    consistency_group_name:
        description:
            - The actual or desired name of the consistency group
        required: True
    consistency_group_full_warn_threshold_percent:
        description:
            - The full warning threshold
            - Unit is percent
    consistency_group_auto_delete_threshold:
        description:
            - The auto-delete threshold.
            - Automatically delete snapshots after this many.
    consistency_group_repository_full_policy:
        description:
            - The repository full policy
        choices: ['failbasewrites', 'purgepit']
    consistency_group_rollback_priority:
        description:
            - Roll-back priority
        choices: ['highest', 'high', 'medium', 'low', 'lowest']
    consistency_group_members:
        description:
            - A list of the volume ids that you want to be members of the consistency group
    snapshot_id:
        description:
            - The snapshot id in question.
            - Required for create_snapshot_view, and rolling back snapshots.
    snapshot_action:
        choices: ['create', 'delete_all_snapshots', 'delete_oldest_snapshot', 'create_snapshot_view', 'delete_snapshot_view', 'rollback']
        description:
            - Avaliable snapshot actions
            - create_snapshot_view requires 'snapshot_id', and 'snapshot_view_name'
            - delete_snapshot_view requires 'snapshot_view_name'
            - rollback requires snapshot_id


"""

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json",
}
EXAMPLES = """
    - name: make consistency group
      na_eseries_consistency_group:
        state: present
        consistency_group_name: "{{ consistency_group_name }}"
        consistency_group_members:
          - "{{ consistency_group_member_1 }}"
          - "{{ consistency_group_member_2 }}"
"""
RETURN = """
"""


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


def update_consistency_group(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    post_data = {}
    if params['consistency_group_full_warn_threshold_percent'] is not None:
        post_data['fullWarnThresholdPercent'] = params['consistency_group_full_warn_threshold_percent']
    if params['consistency_group_name'] is not None:
        post_data['name'] = params['consistency_group_name']
    if params['consistency_group_auto_delete_threshold'] is not None:
        post_data['autoDeleteThreshold'] = params['consistency_group_auto_delete_threshold']
    if params['consistency_group_repository_full_policy'] is not None:
        post_data['repositoryFullPolicy'] = params['consistency_group_repository_full_policy']
    if params['consistency_group_rollback_priority'] is not None:
        post_data['rollbackPriority'] = params['consistency_group_rollback_priority']

    post_data = json.dumps(post_data)

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST', data=post_data)

    if response_code == 200:
        return {'consistency_group_id': response_data['id'], 'errors': None}
    else:
        return {'consistency_group_id': None, 'errors': response_data}


def create_consistency_group(params):
    get_status = 'storage-systems/%s/consistency-groups' % params['ssid']
    url = params['api_url'] + get_status

    post_data = {}
    if params['consistency_group_full_warn_threshold_percent'] is not None:
        post_data['fullWarnThresholdPercent'] = params['consistency_group_full_warn_threshold_percent']
    if params['consistency_group_name'] is not None:
        post_data['name'] = params['consistency_group_name']
    if params['consistency_group_auto_delete_threshold'] is not None:
        post_data['autoDeleteThreshold'] = params['consistency_group_auto_delete_threshold']
    if params['consistency_group_repository_full_policy'] is not None:
        post_data['repositoryFullPolicy'] = params['consistency_group_repository_full_policy']
    if params['consistency_group_rollback_priority'] is not None:
        post_data['rollbackPriority'] = params['consistency_group_rollback_priority']

    post_data = json.dumps(post_data)

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST', data=post_data)

    if response_code == 200:
        return {'consistency_group_id': response_data['id'], 'errors': None}
    else:
        return {'consistency_group_id': None, 'errors': response_data}


def delete_consistency_group(params):
    clever_returned_data = check_if_consistency_group_exists(params)

    get_status = 'storage-systems/%s/consistency-groups/%s' % (params['ssid'],
                                                               clever_returned_data['consistency_group_id'])
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='DELETE')

    if response_code == 204:
        return {'errors': None}
    elif response_code == 404:
        return {'errors': 'StorageDevice not found'}
    elif response_code == 424:
        return {'errors': 'StorageDevice offline'}
    else:
        if response_data is not None:
            return {'errors': response_data}
        else:
            return {'errors': 'Unknown Error. Code: %s' % response_code}


def check_if_consistency_group_exists(params):
    get_status = 'storage-systems/%s/consistency-groups' % params['ssid']
    url = params['api_url'] + get_status
    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'])

    if response_code == 200:
        consistency_group_exists = False

        for consistency_group in response_data:
            if consistency_group['name'] == params['consistency_group_name']:
                consistency_group_exists = True
                consistency_group_id = consistency_group['id']
                break

        if consistency_group_exists is True:
            return {'errors': None, 'existence_status': True, 'consistency_group_id': consistency_group_id}
        else:
            return {'errors': None, 'existence_status': False, 'consistency_group_id': None}
    else:
        return {'errors': response_data, 'existence_status': False, 'consistency_group_id': None}


def check_exixting_consistency_group_members(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/member-volumes' % (params['ssid'],
                                                                              group_id)
    url = params['api_url'] + get_status
    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'])

    if response_code == 404:
        return {'errors': 'Group not found'}
    elif response_code == 424:
        return {'errors': 'Group offline'}
    elif response_code == 200:
        volume_ids = []
        for member in response_data:
            volume_ids.append(member['volumeId'])

        return {'errors': None, 'consistency_group_member_volume_ids': volume_ids}
    else:
        return {'errors': response_code, 'consistency_group_member_volume_ids': []}


def add_potential_member_to_consistency_group_by_volumeid(params, potential_member):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    post_data = {'volumeId': potential_member}
    post_data = json.dumps(post_data)

    get_status = 'storage-systems/%s/consistency-groups/%s/member-volumes' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST', data=post_data)
    if response_code == 404:
        return {'errors': 'Group not found Details: %s' % response_data}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data}
    elif response_code == 201:
        return {'errors': None}
    else:
        return {'errors': str(response_code) + str(response_data)}


def remove_potential_member_from_consistency_group_by_volumeid(params, current_member):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/member-volumes/%s' % (params['ssid'], group_id,
                                                                                 current_member)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='DELETE')
    if response_code == 404:
        return {'errors': 'Group not found Details: %s' % response_data}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data}
    elif response_code == 204:
        return {'errors': None}
    else:
        return {'errors': str(response_code) + str(response_data)}


def manage_members(params, module):
    # We do stuff with the members
    added_members = []
    deleted_members = []
    current_consistency_group_members = check_exixting_consistency_group_members(params)
    for potential_member in params['consistency_group_members']:
        # If the potential member is in the current members and we want it to be there we do nothing.
        # If the potential member is not in the current members we add it

        if potential_member not in current_consistency_group_members['consistency_group_member_volume_ids']:

            potential_member_add_status = add_potential_member_to_consistency_group_by_volumeid(params,
                                                                                                potential_member)

            if potential_member_add_status['errors'] is None:
                added_members.append(potential_member)
            else:
                return {'action_taken': True, 'error': 'Could not add member to consistency group. Errror: %s' %
                                                       potential_member_add_status['errors']}

    for current_member in current_consistency_group_members['consistency_group_member_volume_ids']:
        # If the current member is not in the potential member list we remove it.
        if current_member not in params['consistency_group_members']:
            potential_member_remove_status = remove_potential_member_from_consistency_group_by_volumeid(params,
                                                                                                        current_member)
            if potential_member_remove_status['errors'] is None:
                deleted_members.append(current_member)
            else:
                return {'action_taken': True, 'error': 'Could not delete member from consistency group. Errror: %s' %
                                                       potential_member_remove_status['errors']}

    if len(added_members) > 0 or len(deleted_members) > 0:
        return {'action_taken': True, 'error': None, 'msg': 'Consistency members changed.',
                'added_members': added_members,
                'deleted_members': deleted_members}
    else:
        return {'action_taken': False, 'error': None, 'msg': None}


def create_snapshot(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    post_data = {}
    post_data = json.dumps(post_data)

    get_status = 'storage-systems/%s/consistency-groups/%s/snapshots' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST')

    if response_code == 200:
        return {'errors': None, 'snapshot_id': response_data[0]['id']}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data, 'snapshot_id': None}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Create Snapshot: %s' % response_data, 'snapshot_id': None}
    else:
        return {'errors': str(response_code) + str(response_data), 'snapshot_id': None}


def rollback_snapshot(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    seq_number_results = get_snapshot_seq_number_from_snapshot_id(params)  # ['snapshot_seq_number']

    if seq_number_results['errors'] is None:
        seq_number = get_snapshot_seq_number_from_snapshot_id(params)['snapshot_seq_number']
    else:
        return {'errors': 'Could not find snapshot'}

    post_data = {}
    post_data = json.dumps(post_data)

    get_status = 'storage-systems/%s/consistency-groups/%s/snapshots/%s/rollback' % (
    params['ssid'], group_id, seq_number)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST')

    if response_code == 204:
        return {'errors': None}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Create Snapshot: %s' % response_data}
    else:
        return {'errors': str(response_code) + str(response_data)}


def _delete_snapshot(params, snapshot_number):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/snapshots/%s' % (params['ssid'], group_id, snapshot_number)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='DELETE')

    if response_code == 204:
        return {'errors': None}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Delete Snapshot: %s' % response_data}
    else:
        return {'errors': str(response_code) + str(response_data)}


def get_snapshot_seq_number_from_snapshot_id(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/snapshots' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='GET')

    if response_code == 200:

        snapshot_seq_number = None
        for snapshot in response_data:
            if snapshot['pitRef'] == params['snapshot_id']:
                snapshot_seq_number = snapshot['pitSequenceNumber']
                break

        if snapshot_seq_number is not None:
            return {'errors': None, 'snapshot_seq_number': snapshot_seq_number}
        else:
            return {'errors': 'Could not find snapshot'}

    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data, 'snapshot_seq_number': None}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Delete Snapshot: %s' % response_data, 'snapshot_seq_number': None}
    else:
        return {'errors': str(response_code) + str(response_data), 'snapshot_seq_number': None}


def delete_snapshot(params, delete_all_or_one):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/snapshots' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='GET')

    if response_code == 200:
        snapshot_numbers = []

        for snapshot in response_data:
            snapshot_numbers.append(snapshot['pitSequenceNumber'])

        if delete_all_or_one == 'all':
            for snapshot_number in snapshot_numbers:
                _delete_snapshot(params, snapshot_number)
        elif delete_all_or_one == 'one':
            _delete_snapshot(params, snapshot_numbers[0])
        else:
            pass

        return {'errors': None, 'snapshot_id': response_data[0]['id']}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data, 'snapshot_id': None}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Delete Snapshot: %s' % response_data, 'snapshot_id': None}
    else:
        return {'errors': str(response_code) + str(response_data), 'snapshot_id': None}


def create_snapshot_view(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    post_data = {"name": params['snapshot_view_name'], "pitId": params['snapshot_id']}

    post_data = json.dumps(post_data)

    get_status = 'storage-systems/%s/consistency-groups/%s/views' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='POST', data=post_data)

    if response_code == 201:
        return {'errors': None, 'snapshot_view_id': response_data['id']}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data, 'snapshot_view_id': None}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Create Snapshot: %s' % response_data, 'snapshot_view_id': None}
    else:
        return {'errors': str(response_code) + str(response_data), 'snapshot_view_id': None}


def delete_snapshot_view(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']
    snapshot_id = find_snapshot_view_id_by_name(params)['snapshot_view_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/views/%s' % (params['ssid'], group_id, snapshot_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='DELETE')

    if response_code == 204:
        return {'errors': None}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Not Delete Snapshot: %s' % response_data}
    else:
        return {'errors': str(response_code) + str(response_data)}


def find_snapshot_view_id_by_name(params):
    group_id = check_if_consistency_group_exists(params)['consistency_group_id']

    get_status = 'storage-systems/%s/consistency-groups/%s/views' % (params['ssid'], group_id)
    url = params['api_url'] + get_status

    (response_code, response_data) = request(url, url_username=params['api_username'],
                                             url_password=params['api_password'], headers=HEADERS, ignore_errors=True,
                                             validate_certs=params['validate_certs'], method='GET')

    snapshot_view_id = None
    for view in response_data:
        if view['name'] == params['snapshot_view_name']:
            snapshot_view_id = view['id']
            break

    if response_code == 200:
        if snapshot_view_id is not None:
            return {'errors': None, 'snapshot_view_id': snapshot_view_id}
        else:
            return {'errors': 'Could not find id', 'snapshot_view_id': None}
    elif response_code == 424:
        return {'errors': 'Group offline Details: %s' % response_data, 'snapshot_view_id': None}
    elif response_code == 404:
        return {'errors': 'Device Not Found Could Find Snapshot: %s' % response_data, 'snapshot_view_id': None}
    else:
        return {'errors': str(response_code) + str(response_data), 'snapshot_view_id': None}


def main():
    module = AnsibleModule(argument_spec=dict(
        ssid=dict(required=True, type='str'),
        api_url=dict(required=True),
        api_username=dict(required=False),
        api_password=dict(required=False, no_log=True),
        validate_certs=dict(required=False, default=True),
        state=dict(required=True, choices=['present', 'absent'], type='str'),
        consistency_group_name=dict(required=True, type='str'),
        consistency_group_full_warn_threshold_percent=dict(type='int'),
        consistency_group_auto_delete_threshold=dict(type='int'),
        consistency_group_repository_full_policy=dict(type='str', choices=['failbasewrites', 'purgepit']),
        consistency_group_rollback_priority=dict(type='str', choices=['highest', 'high', 'medium', 'low', 'lowest']),
        consistency_group_members=dict(type='list', default=[]),
        snapshot_id=dict(required=False, type='str'),
        snapshot_action=dict(type='str', choices=['create', 'delete_all_snapshots', 'delete_oldest_snapshot',
                                                  'create_snapshot_view', 'delete_snapshot_view', 'rollback']),
        snapshot_view_name=dict(type='str'),
        update_consistency_group=dict(type='bool', default=False),
    ),
        required_if=[
            ["snapshot_action", 'create_snapshot_view', ['snapshot_id', 'snapshot_view_name'], ],
            ["snapshot_action", 'delete_snapshot_view', ['snapshot_view_name'], ],
            ["snapshot_action", 'rollback', ['snapshot_id'], ],
        ]
    )

    params = module.params
    if not params['api_url'].endswith('/'):
        params['api_url'] += '/'

    if params['consistency_group_members'] is None:
        params['consistency_group_members'] = []

    # We need to check if the group exists already
    check_if_consistency_group_exists_response_data = check_if_consistency_group_exists(params)

    # If we want the group to be present
    if params['state'] == 'present':

        # If it does exist we do this stuff
        if check_if_consistency_group_exists_response_data['existence_status'] is True:

            if params['update_consistency_group'] == True:
                update_consistency_group_response_data = create_consistency_group(params)
                if update_consistency_group_response_data['errors'] is None:
                    module.exit_json(changed=True, msg='Updated consistency group.',
                                     consistency_group_id=update_consistency_group_response_data[
                                         'consistency_group_id'])
                else:
                    module.fail_json(changed=False, msg='Could not update consistency group. Errror: %s' %
                                                        update_consistency_group_response_data['errors'])

            # We need to know if we want to create a snapshot
            if params['snapshot_action'] == 'create':
                create_snapshot_results = create_snapshot(params)

                if create_snapshot_results['errors'] is None:
                    module.exit_json(changed=True, msg='Created snapshot',
                                     snapshot_id=create_snapshot_results['snapshot_id'])
                else:
                    module.fail_json(changed=False, msg=create_snapshot_results['errors'])

            if params['snapshot_action'] == 'delete_oldest_snapshot':

                module.debug(msg=params['snapshot_action'])

                delete_results = delete_snapshot(params, 'one')

                module.debug(msg=params['snapshot_action'])

                if delete_results['errors'] is None:
                    module.exit_json(changed=True, msg='Deleted Oldest Snapshot',
                                     snapshot_id=delete_results['snapshot_id'])
                else:
                    module.fail_json(changed=False, msg=delete_results['errors'])

            if params['snapshot_action'] == 'delete_all_snapshots':
                delete_results = delete_snapshot(params, 'all')

                if delete_results['errors'] is None:
                    module.exit_json(changed=True, msg='Deleted all snapshots')
                else:
                    module.fail_json(changed=False, msg=delete_results['errors'])

            if params['snapshot_action'] == 'create_snapshot_view':
                create_snapshot_view_results = create_snapshot_view(params)

                if create_snapshot_view_results['errors'] is None:
                    module.exit_json(changed=True, msg='Created snapshot view',
                                     snapshot_view_id=create_snapshot_view_results['snapshot_view_id'])
                else:
                    module.fail_json(changed=False, msg=create_snapshot_view_results['errors'])

            if params['snapshot_action'] == 'delete_snapshot_view':
                delete_snapshot_view_results = delete_snapshot_view(params)

                if delete_snapshot_view_results['errors'] is None:
                    module.exit_json(changed=True, msg='Deleted snapshot view')
                else:
                    module.fail_json(changed=False, msg=delete_snapshot_view_results['errors'])

            if params['snapshot_action'] == 'rollback':
                rollback_results = rollback_snapshot(params)

                if rollback_results['errors'] is None:
                    module.exit_json(changed=True, msg='Rolled back to snapshot', snapshot_id=params['snapshot_id'])
                else:
                    module.fail_json(changed=False, msg=rollback_results['errors'])

            # We verify the members
            member_status_data = manage_members(params, module)

            if member_status_data['action_taken'] == True:
                if member_status_data['error'] is None:
                    module.exit_json(changed=True, msg=member_status_data['msg'],
                                     consistency_group_id=check_if_consistency_group_exists_response_data[
                                         'consistency_group_id'],
                                     added_members=member_status_data['added_members'],
                                     deleted_Members=member_status_data['deleted_members'])

                else:
                    module.fail_json(changed=False, msg=member_status_data['error'])

            module.exit_json(changed=False, msg='Group exists',
                             group_id=check_if_consistency_group_exists_response_data['consistency_group_id'])

        # If it does not we need to create it.
        else:
            create_consistency_group_response_data = create_consistency_group(params)

            if create_consistency_group_response_data['errors'] is None:

                # We need to know if we want to create a snapshot
                if params['snapshot_action'] is 'create':
                    create_snapshot_results = create_snapshot(params)

                    if create_snapshot_results['errors'] is None:
                        pass
                    else:
                        module.fail_json(changed=False, msg=create_snapshot_results['errors'])

                # We verify the members
                member_status_data = manage_members(params, module)

                if member_status_data['action_taken'] == True:
                    if member_status_data['error'] is None:
                        pass
                    else:
                        module.fail_json(changed=False, msg=member_status_data['error'])

                module.exit_json(changed=True, msg='Created consistency group.',
                                 consistency_group_id=create_consistency_group_response_data['consistency_group_id'])
            else:
                module.fail_json(changed=False, msg='Could not create consistency group. Errror: %s' %
                                                    create_consistency_group_response_data['errors'])

    # If we want the group to be absent
    else:
        # If it does exist we delete the thing
        if check_if_consistency_group_exists_response_data['existence_status'] is True:
            delete_consistency_group_response_data = delete_consistency_group(params)

            if delete_consistency_group_response_data['errors'] is None:
                module.exit_json(changed=True, msg='Deleted consistency group.')
            else:
                module.fail_json(changed=False, msg='Could not delete consistency group. Errror: %s' %
                                                    delete_consistency_group_response_data['errors'])

        # If it does not we simply state it does not exist
        else:
            module.exit_json(changed=False, msg='Consistency group does not exist.')


import json

from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()
