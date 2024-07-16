import botocore.session
import http.client as http_client
import logging
import requests
from sign.signature import (
    generate_sigv4_headers,
    generate_sigv4_headers_botocore
)

services = {
    'bedrock': {
        'endpoints': {
            'ap-northeast-1': {},
            'ap-south-1': {},
            'ap-southeast-1': {},
            'ap-southeast-2': {},
            'bedrock-ap-northeast-1': {
                'credentialScope': {'region': 'ap-northeast-1'},
                'hostname': 'bedrock.ap-northeast-1.amazonaws.com',
            },
            'bedrock-ap-south-1': {
                'credentialScope': {'region': 'ap-south-1'},
                'hostname': 'bedrock.ap-south-1.amazonaws.com',
            },
            'bedrock-ap-southeast-1': {
                'credentialScope': {'region': 'ap-southeast-1'},
                'hostname': 'bedrock.ap-southeast-1.amazonaws.com',
            },
            'bedrock-ap-southeast-2': {
                'credentialScope': {'region': 'ap-southeast-2'},
                'hostname': 'bedrock.ap-southeast-2.amazonaws.com',
            },
            'bedrock-ca-central-1': {
                'credentialScope': {'region': 'ca-central-1'},
                'hostname': 'bedrock.ca-central-1.amazonaws.com',
            },
            'bedrock-eu-central-1': {
                'credentialScope': {'region': 'eu-central-1'},
                'hostname': 'bedrock.eu-central-1.amazonaws.com',
            },
            'bedrock-eu-west-1': {
                'credentialScope': {'region': 'eu-west-1'},
                'hostname': 'bedrock.eu-west-1.amazonaws.com',
            },
            'bedrock-eu-west-2': {
                'credentialScope': {'region': 'eu-west-2'},
                'hostname': 'bedrock.eu-west-2.amazonaws.com',
            },
            'bedrock-eu-west-3': {
                'credentialScope': {'region': 'eu-west-3'},
                'hostname': 'bedrock.eu-west-3.amazonaws.com',
            },
            'bedrock-fips-ca-central-1': {
                'credentialScope': {'region': 'ca-central-1'},
                'hostname': 'bedrock-fips.ca-central-1.amazonaws.com',
            },
            'bedrock-fips-us-east-1': {
                'credentialScope': {'region': 'us-east-1'},
                'hostname': 'bedrock-fips.us-east-1.amazonaws.com',
            },
            'bedrock-fips-us-west-2': {
                'credentialScope': {'region': 'us-west-2'},
                'hostname': 'bedrock-fips.us-west-2.amazonaws.com',
            },
            'bedrock-runtime-ap-northeast-1': {
                'credentialScope': {'region': 'ap-northeast-1'},
                'hostname': 'bedrock-runtime.ap-northeast-1.amazonaws.com',
            },
            'bedrock-runtime-ap-south-1': {
                'credentialScope': {'region': 'ap-south-1'},
                'hostname': 'bedrock-runtime.ap-south-1.amazonaws.com',
            },
            'bedrock-runtime-ap-southeast-1': {
                'credentialScope': {'region': 'ap-southeast-1'},
                'hostname': 'bedrock-runtime.ap-southeast-1.amazonaws.com',
            },
            'bedrock-runtime-ap-southeast-2': {
                'credentialScope': {'region': 'ap-southeast-2'},
                'hostname': 'bedrock-runtime.ap-southeast-2.amazonaws.com',
            },
            'bedrock-runtime-ca-central-1': {
                'credentialScope': {'region': 'ca-central-1'},
                'hostname': 'bedrock-runtime.ca-central-1.amazonaws.com',
            },
            'bedrock-runtime-eu-central-1': {
                'credentialScope': {'region': 'eu-central-1'},
                'hostname': 'bedrock-runtime.eu-central-1.amazonaws.com',
            },
            'bedrock-runtime-eu-west-1': {
                'credentialScope': {'region': 'eu-west-1'},
                'hostname': 'bedrock-runtime.eu-west-1.amazonaws.com',
            },
            'bedrock-runtime-eu-west-2': {
                'credentialScope': {'region': 'eu-west-2'},
                'hostname': 'bedrock-runtime.eu-west-2.amazonaws.com',
            },
            'bedrock-runtime-eu-west-3': {
                'credentialScope': {'region': 'eu-west-3'},
                'hostname': 'bedrock-runtime.eu-west-3.amazonaws.com',
            },
            'bedrock-runtime-fips-ca-central-1': {
                'credentialScope': {'region': 'ca-central-1'},
                'hostname': 'bedrock-runtime-fips.ca-central-1.amazonaws.com',
            },
            'bedrock-runtime-fips-us-east-1': {
                'credentialScope': {'region': 'us-east-1'},
                'hostname': 'bedrock-runtime-fips.us-east-1.amazonaws.com',
            },
            'bedrock-runtime-fips-us-west-2': {
                'credentialScope': {'region': 'us-west-2'},
                'hostname': 'bedrock-runtime-fips.us-west-2.amazonaws.com',
            },
            'bedrock-runtime-sa-east-1': {
                'credentialScope': {'region': 'sa-east-1'},
                'hostname': 'bedrock-runtime.sa-east-1.amazonaws.com',
            },
            'bedrock-runtime-us-east-1': {
                'credentialScope': {'region': 'us-east-1'},
                'hostname': 'bedrock-runtime.us-east-1.amazonaws.com',
            },
            'bedrock-runtime-us-west-2': {
                'credentialScope': {'region': 'us-west-2'},
                'hostname': 'bedrock-runtime.us-west-2.amazonaws.com',
            },
            'bedrock-sa-east-1': {
                'credentialScope': {'region': 'sa-east-1'},
                'hostname': 'bedrock.sa-east-1.amazonaws.com',
            },
            'bedrock-us-east-1': {
                'credentialScope': {'region': 'us-east-1'},
                'hostname': 'bedrock.us-east-1.amazonaws.com',
            },
            'bedrock-us-west-2': {
                'credentialScope': {'region': 'us-west-2'},
                'hostname': 'bedrock.us-west-2.amazonaws.com',
            },
            'ca-central-1': {},
            'eu-central-1': {},
            'eu-west-1': {},
            'eu-west-2': {},
            'eu-west-3': {},
            'sa-east-1': {},
            'us-east-1': {},
            'us-west-2': {},
        }
    },
}

http_client.HTTPConnection.debuglevel = 1
logging.getLogger('botocore').setLevel(logging.INFO)
logging.basicConfig()

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

requests_log = logging.getLogger('requests.packages.urllib3')
requests_log.setLevel(logging.INFO)
requests_log.propagate = True

def invoke_model_https(region_name: str, model_id: str, with_botocore: bool = True):
    service = 'bedrock'
    resource = 'bedrock-runtime'
    if not region_name in services[service]['endpoints']:
        logger.error(f'Bedrock endpoint not found in region {region_name}.')
        exit(1)

    host = services[service]['endpoints'][f'{resource}-{region_name}']['hostname']
    path = f'/model/{model_id}/invoke'
    request_url = f'https://{host}{path}'
    method = 'POST'

    payload = model_prompts[model_id]

    credentials = botocore.session.Session().get_credentials()

    headers = {}
    logger.debug(f'with_botocore: {with_botocore}')
    if with_botocore:
        logger.debug('Generating request headers using botocore...')
        headers = generate_sigv4_headers_botocore(credentials, region_name, service, request_url, method, payload)
    else:
        logger.debug('Generating request headers by applying sigv4 algorithm...')
        headers = generate_sigv4_headers(credentials, region_name, service, host, path, method, payload)
    
    del headers['Host']
    headers['Content-Type'] = 'application/json'

    response = requests.post(request_url, headers=headers, data=payload, timeout=15)

    response.raise_for_status()

    # Extract and print the response text.
    response_text = response.text
    logger.debug(f'response_text: {response_text}')


if __name__ == '__main__':
    region_name = 'us-west-2'
    model_prompts = {
        'amazon.titan-text-lite-v1': '{"inputText":"What is the golden ratio?","textGenerationConfig":{"maxTokenCount":4096,"stopSequences":[],"temperature":0,"topP":1}}',
        'anthropic.claude-3-sonnet-20240229-v1:0': '{"anthropic_version":"bedrock-2023-05-31","max_tokens":1000,"messages":[{"role":"user","content":[{"type":"text","text":"What is the golden ratio?"}]}]}',
    }
    model_id = 'amazon.titan-text-lite-v1'
    # model_id = 'anthropic.claude-3-sonnet-20240229-v1:0'
    invoke_model_https(region_name, model_id, True)
