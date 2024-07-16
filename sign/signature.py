import botocore.credentials as credentials
import datetime
import hashlib
import hmac
import logging
import urllib.parse

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.compat import HTTPHeaders

logger = logging.getLogger(__name__)

_ALGORITHM = 'AWS4-HMAC-SHA256'
_AWS4_REQUEST = 'aws4_request'

def generate_sigv4_headers_botocore(
        credentials: Credentials,
        region_name: str,
        service: str,
        url: str,
        method: str,
        payload: str) -> dict[str, str]:
    # Create a datetime object for signing
    t = datetime.datetime.now(datetime.UTC)
    iso_date_timestamp = t.strftime('%Y%m%dT%H%M%SZ')
    logger.debug(f'date_timestamp: {iso_date_timestamp}')

    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    logger.debug(f'payload_hash: {payload_hash}')

    headers = {}

    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.netloc
    
    headers['Host'] = host
    headers['X-Amz-Date'] = iso_date_timestamp
    if credentials.token is not None:
        headers['X-Amz-Security-Token'] = credentials.token

    request = AWSRequest(method=method, url=url, headers=headers, data=payload)
    SigV4Auth(credentials, service, region_name).add_auth(request)
    return {k:v for k,v in request.headers.items()}

def generate_sigv4_headers(
        credentials,
        region_name: str,
        service: str,
        host: str,
        path: str,
        method: str,
        payload: str) -> dict[str, str]:

    # Create a datetime object for signing
    t = datetime.datetime.now(datetime.UTC)
    iso_date_timestamp = t.strftime('%Y%m%dT%H%M%SZ')
    logger.debug(f'date_timestamp: {iso_date_timestamp}')
    iso_date = t.strftime('%Y%m%d')

    payload_hash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    logger.debug(f'payload_hash: {payload_hash}')

    headers = {}

    headers['Host'] = host
    headers['X-Amz-Date'] = iso_date_timestamp
    if credentials.token is not None:
        headers['X-Amz-Security-Token'] = credentials.token

    signing_key = generate_signing_key(region_name, service, iso_date, credentials.secret_key)

    credential_scope = generate_credential_scope(region_name, service, iso_date)

    string_to_sign = generate_string_to_sign(method, path, headers, credential_scope, iso_date_timestamp, payload_hash)
    logger.debug(f'string_to_sign: {string_to_sign}')

    # Sign the string    
    signature = generate_signature(signing_key, string_to_sign)

    # Add signing information to the request
    authorization_header = f'{_ALGORITHM} Credential={credentials.access_key}/{credential_scope}, SignedHeaders={get_signed_headers(headers)}, Signature={signature}'

    headers['Authorization'] = authorization_header.encode('utf-8')

    return headers

def get_signed_headers(headers: dict[str, str]) -> str:
    return ';'.join(sorted([header.lower() for header in headers.keys()]))

def get_canonical_headers(headers: dict[str, str]) -> str:
    return '\n'.join([f'{k.lower()}:{v}' for k,v in headers.items()]) + '\n'

def generate_credential_scope(region_name: str, service: str, iso_date: str) -> str:
    return f'{iso_date}/{region_name}/{service}/{_AWS4_REQUEST}'

def generate_string_to_sign(method: str, path: str, headers: dict[str, str], credential_scope: str, iso_date_timestamp: str, payload_hash: str) -> str:
    # Create the string to sign
    canonical_uri = urllib.parse.quote(path)
    logger.debug(f'canonical_uri: {canonical_uri}')
    canonical_querystring = ''
    canonical_headers = get_canonical_headers(headers)
    logger.debug(f'canonical_headers: {canonical_headers}')
    signed_headers = get_signed_headers(headers)
    logger.debug(f'signed_headers: {signed_headers}')
    canonical_request = f'{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    logger.debug(f'canonical_request: {canonical_request}')
    hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    logger.debug(f'hashed_canonical_request: {hashed_canonical_request}')
    return f'{_ALGORITHM}\n{iso_date_timestamp}\n{credential_scope}\n{hashed_canonical_request}'

def hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def generate_signing_key(region_name: str, service: str, dateStamp: str, secret_key: str) -> bytes:
    key_date = hmac_sha256(f'AWS4{secret_key}'.encode("utf-8"), dateStamp)
    key_date_region = hmac_sha256(key_date, region_name)
    key_date_region_service = hmac_sha256(key_date_region, service)
    return hmac_sha256(key_date_region_service, _AWS4_REQUEST)

def generate_signature(signing_key: bytes, string_to_sign: str) -> str:
    return hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
