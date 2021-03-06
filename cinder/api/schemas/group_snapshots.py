# Copyright (C) 2017 NTT DATA
# All Rights Reserved.
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

"""
Schema for V3 Group Snapshots API.

"""

from cinder.api.validation import parameter_types


name_optional = parameter_types.name
name_optional['minLength'] = 0

create = {
    'type': 'object',
    'properties': {
        'type': 'object',
        'group_snapshot': {
            'type': 'object',
            'properties': {
                'group_id': parameter_types.uuid,
                'name': name_optional,
                'description': parameter_types.description,
            },
            'required': ['group_id'],
            'additionalProperties': False,
        },
    },
    'required': ['group_snapshot'],
    'additionalProperties': False,
}

reset_status = {
    'type': 'object',
    'properties': {
        'type': 'object',
        'reset_status': {
            'type': 'object',
            'properties': {
                'status': parameter_types.group_snapshot_status,
            },
            'required': ['status'],
            'additionalProperties': False,
        },
    },
    'required': ['reset_status'],
    'additionalProperties': False,
}
