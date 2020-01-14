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
requirements: [ boto3, pydash ]
author: "Mark J. Horninger (@spam-n-eggs); Dominion Solutions LLC (@dominion-solutions); TAPP Network, LLC (@TappNetwork)"
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
        Present will also execute an update if necessary.
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


def create_or_update_sftp(client: boto3.session.Session, module: AnsibleAWSModule):
    name = module.params.get("name")
    tags = module.params.get("tags")
    purge_tags = module.params.get("purge_tags")
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

    # TODO: Eventually, this needs to support all of the endpoint details, including vpc endpoint ids.
    endpoint_details = None
    if identity_provider_type != 'PUBLIC' and vpc_id is not None:
        endpoint_details = {
            # "AddressAllocationIds": [],
            # "SubnetIds": [],
            # "VpcEndpointId": "",
            "VpcId": vpc_id
        }

    identity_provider_details = None
    if identity_provider_url is not None and identity_provider_role is not None:
        identity_provider_details = {
            "InvocationRole": identity_provider_role,
            "Url": identity_provider_url
        }

    name_tag = {'Key': SERVER_NAME_KEY, 'Value': name}
    assigned_tags = [name_tag]

    try:
        sftp_server = find_sftp_server(client, name)
        needs_creation = sftp_server is None
    except EndpointConnectionError as e:
        module.fail_json_aws(e, msg="Invalid endpoint provided: %s" % to_text(e))
    except (BotoCoreError, ClientError) as e:
        module.fail_json_aws(e, msg="Failed to check Transfer presence")
    if needs_creation:
        result = create_sftp_server(client, endpoint_details, endpoint_type, host_key,
                                    identity_provider_details, identity_provider_type, logging_role, name_tag)
        sftp_server_id = result['ServerId']
    else:
        sftp_server_id = sftp_server['ServerId']
        if not purge_tags:
            assigned_tags = sftp_server['Tags']
    # Update SFTP Server Details
    # Update Tags
    for key, value in tags.items():
        item = py_.find(assigned_tags, {'Key': key});
        if item:
            item['Value'] = value
        else:
            item = {'Key': key, 'Value': value }
            assigned_tags.append(item)

    result = client.update_server(sftp_server_id, endpoint_details, endpoint_type, host_key,
                                  identity_provider_details, logging_role)

    module.exit_json(changed=changed, name=name, **result)


def find_sftp_server(client: boto3.session.Session, server_name: str):
    # Finding a server by name is a little more complicated than I originally expected.  Rather than wasting resources
    # it's much easier to just go find it and then check if the return value of this method is None.
    # Load all of the server IDs in the account
    all_server_ids = py_.map(client.list_servers()['Servers'], 'ServerId')
    all_servers = py_.map_(all_server_ids, (lambda server_id: client.describe_server(ServerId=server_id)))
    host = py_.find(all_servers, {'Server': {'Tags': [{'Key': SERVER_NAME_KEY, 'Value': server_name}]}})
    return host


@AWSRetry.exponential_backoff(max_delay=120)
def create_sftp_server(client: boto3.session.Session, endpoint_details, endpoint_type, host_key,
                       identity_provider_details, identity_provider_type, logging_role, name):
    """
    Does the work of actually creating the SFTP Server.
    :arg client: boto3.session.Session the boto3 client that is used to create the connection
    :arg endpoint_details: object The details that are provided to the endpoint - right now vpc_id is the only supported
    information.
    :arg endpoint_type: str The type of endpoint that the created SFTP Server connects to.  AWS Supports PUBLIC, VPC and
    VPC_ENDPOINT
    :arg host_key: str This is the generated ssh key for the host, the result of ssh-keygen.  Do not use this unless you
    are transitioning from another SFTP Server and need to maintain backward compatibility.
    :arg identity_provider_details: object The information for the provided entity type.
    See https://docs.aws.amazon.com/transfer/latest/userguide/API_IdentityProviderDetails.html for more details.
    :arg identity_provider_type: str Currently supports SERVICE_MANAGED or API_GATEWAY - if using API_GATEWAY,
    identity_provider_details becomes required.  SERVICE_MANAGED is the default, and allows AWS to manage the SFTP
    server.
    :arg logging_role: str A value that allows the service to write your SFTP users' activity to your Amazon CloudWatch
    logs for monitoring and auditing purposes.
    :arg name: dict The name of the SFTP server that also becomes the FQDN of it, in tag format.
    :rtype: dict A Single Entry Dictionary that contains the Server ID.
    """
    kwargDict = { 'Tags':[name] }
    if endpoint_details is not None:
        kwargDict['EndpointDetails']= endpoint_details
    if endpoint_type is not None:
        kwargDict['EndpointType'] = endpoint_type
    if host_key is not None:
        kwargDict['HostKey'] = host_key
    if identity_provider_details is not None:
        kwargDict['IdentityProviderDetails'] = identity_provider_details
    if identity_provider_type is not None:
        kwargDict['IdentityProviderType']= identity_provider_type
    if logging_role is not None:
        kwargDict['LoggingRole']= logging_role

    print(kwargDict)
    response = client.create_server(**kwargDict)
    # According to the documentation response should be an object containing a single string like this:
    # {
    #    ServerId: 'string(19)'
    # }
    return response


@AWSRetry.exponential_backoff(max_delay=120)
def add_sftp_user(client: boto3.session.Session, module: AnsibleAWSModule):
    pass


@AWSRetry.exponential_backoff(max_delay=120)
def destroy_sftp_server(client: boto3.session.Session, module: AnsibleAWSModule):
    pass


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

    transfer_client = boto3.client(service_name='transfer', region_name=region, endpoint_url=endpoint_url,
                                   aws_access_key_id=aws_access_token, aws_secret_access_key=aws_secret_key,
                                   aws_session_token=aws_session_token)

    if state == 'present':
        create_or_update_sftp(transfer_client, module)
    elif state == 'absent':
        destroy_sftp_server(transfer_client, module)


if __name__ == '__main__':
    main()
