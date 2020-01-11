#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '0.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}

DOCUMENTATION = '''
---
module: transfer
short_description: Manage SFTP Severs in AWS.
description:
    - Manage SFTP Servers in AWS Using AWS Transfer Service.
version_added: "2.0"
requirements: [ boto3, pydash]
author: "Mark J. Horninger (@spam-n-eggs)"
options:
  force:
    description:
      - When trying to delete a bucket, delete all keys (including versions and delete markers)
        in the bucket first (an s3 bucket must be empty for a successful deletion)
    type: bool
    default: 'no'
  name:
    description:
      - Fully Qualified Domain name of the SFTP Server to create
    required: true
    type: str
  url:
    description:
        - The endpoint to use for the SFTP Server Creation
    type: str
  state:
    description:
      - Create or remove the SFTP Server
    required: false
    default: present
    choices: [ 'present', 'absent' ]
    type: str
  tags:
    description:
      - tags dict to apply to the server
    type: dict
  purge_tags:
    description:
      - whether to remove tags that aren't present in the C(tags) parameter
    type: bool
    default: True
    version_added: "2.9"
extends_documentation_fragment:
    - aws
    - ec2
notes:
    - If C(requestPayment), C(policy), C(tagging) or C(versioning)
      operations/API aren't implemented by the endpoint, module doesn't fail
      if related parameters I(requester_pays), I(policy), I(tags) or
      I(versioning) are C(None).
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

'''

import json
import os
import time
import boto3

from ansible.module_utils.six.moves.urllib.parse import urlparse
from ansible.module_utils.six import string_types
from ansible.module_utils.basic import to_text
from ansible.module_utils.aws.core import AnsibleAWSModule, is_boto3_error_code
from ansible.module_utils.ec2 import compare_policies, ec2_argument_spec, boto3_tag_list_to_ansible_dict, \
    ansible_dict_to_boto3_tag_list
from ansible.module_utils.ec2 import get_aws_connection_info, boto3_conn, AWSRetry
from pydash import py_

try:
    from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError, WaiterError
except ImportError:
    pass  # handled by AnsibleAWSModule

SERVER_NAME_KEY = 'aws:transfer:customHostname'


def create_or_update_sftp(client, module, location):
    name = module.params.get("name")
    tags = module.params.get("tags")
    purge_tags = module.params.get("purge_tags")
    versioning = module.params.get("versioning")
    endpoint_type = module.params.get("endpoint_type")
    vpc_id = module.params.get("vpc_id")
    host_key = module.params.get("host_key")
    identity_provider_type = module.params.get("identity_provider_type")
    identity_provider_role = module.params.get("identity_provider_role")
    identity_provider_url = module.params.get("identity_provider_url")
    logging_role = module.params.get("logging_role")
    changed = False
    result = {}
    sftp_server = None
    needs_creation = False

    try:
        sftp_server = find_sftp_server(client, name)
        needs_creation = sftp_server is None
    except EndpointConnectionError as e:
        module.fail_json_aws(e, msg="Invalid endpoint provided: %s" % to_text(e))
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Failed to check Transfer presence")
    if needs_creation:
        sftp_changed = create_sftp_server(client)
    else:
        pass

    module.exit_json(changed=changed, name=name, **result)


def find_sftp_server(client, server_name):
    # Finding a server by name is a little more complicated than I originally expected.  Rather than wasting resources
    # it's much easier to just go find it and then check if the return value of this method is None.
    # Load all of the server IDs in the account
    all_server_ids = py_.map(client.list_servers()['Servers'], 'ServerId')
    all_servers = py_.map_(all_server_ids, (lambda server_id: client.describe_server(ServerId=server_id)))
    host = py_.find(all_servers, {'Server': {'Tags': [{'Key': SERVER_NAME_KEY, 'Value': server_name}]}})
    return host


@AWSRetry.exponential_backoff(max_delay=120)
def create_sftp_server(client, endpoint_details, endpoint_type, host_key, identity_provider_details,
                       identity_provider_type, logging_role, name):
    name_tag = {'Key': SERVER_NAME_KEY, 'Value': name}
    response = client.create_server(endpoint_details, endpoint_type, host_key, identity_provider_details,
                                    identity_provider_type, logging_role, Tags=[name_tag])
    return response


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            tags=dict(type='dict'),
            purge_tags=dict(type='bool', default=True),
            versioning=dict(type='bool'),
            # Default to public because AWS does.  This is probably not the best option.
            endpoint_type=dict(default="PUBLIC", choices=['PUBLIC', 'VPC_ENDPOINT']),
            vpc_id=dict(required=False),
            host_key=dict(),
            identity_provider_type=dict(default='SERVICE_MANAGED', choices=['SERVICE_MANAGED', 'API_GATEWAY']),
            identity_provider_role=dict(),
            identity_provider_url=dict(),
            transfer_endpoint_url=dict(),
            logging_role=dict(),
        )
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
    )

    region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)

    if region in ('us-east-1', '', None):
        # default to US Standard region
        location = 'us-east-1'
    else:
        # Boto uses symbolic names for locations but region strings will
        # actually work fine for everything except us-east-1 (US Standard)
        location = region

    # Get AWS connection information.
    endpoint_url = module.params.get('transfer_endpoint_url')
    aws_access_token = aws_connect_kwargs.get('aws_access_key_id')
    aws_secret_key = aws_connect_kwargs.get('aws_secret_access_key')
    aws_session_token = aws_connect_kwargs.get('security_token')

    state = module.params.get("state")

    transfer_client = boto3.client(service_name='transfer', region_name=location, endpoint_url=endpoint_url,
                                   aws_access_key_id=aws_access_token, aws_secret_access_key=aws_secret_key,
                                   aws_session_token=aws_session_token)

    if state == 'present':
        create_or_update_sftp(transfer_client, module, location)
    elif state == 'absent':
        # destroy_bucket(s3_client, module)
        pass


if __name__ == '__main__':
    main()
