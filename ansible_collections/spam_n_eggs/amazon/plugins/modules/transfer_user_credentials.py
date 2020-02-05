#!/usr/bin/python
# transfer_user_credentials.py
#
# Ansible AWS Transfer User Management Plugin
# Copyright (C) 2020  Mark Horninger; Dominion Solutions LLC; TAPP Network, LLC

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: transfer_user_credentials
short_description: AWS Transfer User Management
version_added: "2.4"
description:
  - A Module designed to manage AWS Transfer Users
requirements: [ "boto3", "pydash" ]
author: "Mark J. Horninger (@spam-n-eggs); Dominion Solutions LLC (@dominion-solutions); TAPP Network, LLC (@TappNetwork)"
options:
  server_id:
    description:
      - A unique identifier for the server assigned by AWS.
    required: True
    type: str
  ssh_key:
    description:
      - The Public SSH Key to modify on the user.
    required: True
    type: str
  state:
    description:
      - The Desired State when this operation is complete.
    required: True
    choices: [ 'present', 'absent' ]
    type: str
  user_name:
    description:
      - The User Name to modify.
    required: True
    type: str
  replace_others:
    description:
      - Replace all the other keys with this one.
    type: bool
extends_documentation_fragment:
  - aws
  - ec2
'''

EXAMPLES = '''
'''


from ansible.module_utils.aws.core import AnsibleAWSModule
from ansible.module_utils.ec2 import ec2_argument_spec, AWSRetry, get_aws_connection_info

try:
    import boto3
    from pydash import py_
except ImportError:
    # Pass it straight through to the AnsibleAWSModule
    pass


def create_boto3_client(module):
    """
    Get a boto3 client to interact with the transfer module.
    :param module: AnsibleAWSModule
    :return: boto3.session.Session
    """
    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
    if region in ('us-east-1', '', None):
        # default to US Standard region
        location = 'us-east-1'
    else:
        # Boto uses symbolic names for locations but region strings will
        # actually work fine for everything except us-east-1 (US Standard)
        location = region

    # Get AWS connection information.
    aws_access_token = aws_connect_kwargs.get('aws_access_key_id')
    aws_secret_key = aws_connect_kwargs.get('aws_secret_access_key')
    aws_session_token = aws_connect_kwargs.get('security_token')

    transfer_client = boto3.client(service_name='transfer', region_name=region, aws_access_key_id=aws_access_token,
                                   aws_secret_access_key=aws_secret_key, aws_session_token=aws_session_token)
    return transfer_client


@AWSRetry.exponential_backoff(max_delay=120)
def create_credentials(client, module):
    server_id = module.params.get('server_id')

    user_description = client.describe_user(
        ServerId=server_id,
        UserName=module.params.get('user_name')
    )
    ssh_key = client.params.get('ssh_key')
    if ssh_key_is_present(client, module):
        return dict(changed=False, **user_description)
    else:
        changed = True
        response = client.import_ssh_public_key(ServerId=server_id, UserName=module.params.get('user_name'),
                                                SshPublicKeyBody=ssh_key)
    return dict(changed=changed, **response)


def find_ssh_key_id(client, module):
    if ssh_key_is_present(client, module):
        server_id = module.params.get('server_id')
        user_description = client.describe_user(
            ServerId=server_id,
            UserName=module.params.get('user_name')
        )
        ssh_key = client.params.get('ssh_key')
        return py_.find_index(user_description["User"]["SshPublicKeys"], {"SshPublicKeyBody": ssh_key})['SshPublicKeyId']


@AWSRetry.exponential_backoff(max_delay=120)
def delete_credentials(client, module):
    if not ssh_key_is_present(client, module):
        return dict(changed=False, **module.params)
    else:
        ssh_key_id = find_ssh_key_id(client, module)
        changed = True
        response = client.delete_ssh_public_key(ServerId=module.params.get('server_id'),
                                                UserName=module.params.get('user_name'), SshPublicKeyId=ssh_key_id)
        return dict(changed=changed, **response)


def ssh_key_is_present(client, module):
    server_id = module.params.get('server_id')
    user_description = client.describe_user(
        ServerId=server_id,
        UserName=module.params.get('user_name')
    )
    ssh_key = client.params.get('ssh_key')
    return py_.find_index(user_description["User"]["SshPublicKeys"], {"SshPublicKeyBody": ssh_key}) != -1


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = ec2_argument_spec()
    module_args.update(
        dict(
            server_id=dict(required=True, type='str'),
            ssh_key=dict(required=True, type='str'),
            state=dict(required=True, type='str', choices=['present', 'absent']),
            user_name=dict(required=True, type='str'),
            replace_others=dict(required=False, type='bool')
        )
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleAWSModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    state = module.params.get('state')
    client = create_boto3_client(module)
    if state == 'present':
        result = create_credentials(client, module)
    if state == 'absent':
        result = delete_credentials(client, module)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
