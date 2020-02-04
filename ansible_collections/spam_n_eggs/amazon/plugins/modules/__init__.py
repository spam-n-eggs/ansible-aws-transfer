from ansible.module_utils.ec2 import get_aws_connection_info
try:
    import boto3
except ImportError:
    # Pass it to the AnsibleAWSModule
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
