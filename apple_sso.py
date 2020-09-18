"""
## Basic Usage

Once the client has obtained a code from apple, you can use this
module to get the users's id token.


```
from apple_sso import get_id_token, deserialize_id_token
payload = get_id_token(
    YOUR APPLE SSO CLIENT ID,
    YOUR APPLE TEAM ID,
    YOUR APPLE PRIVATE KEY ID,
    YOUR APPLE PRIVATE KEY CONTENTS),
    code,  # the code Apple gave you to authenticate with
    redirect_uri  # the redirect uri you gave Apple
)

id_token = deserialize_id_token(payload['id_token'], client_id)
```

## Error Handling

The primary source of error is in verifying the code
with Apple. When this occurs, the module raises a
AppleTokenApiError. For example

```
try:
    payload = get_id_token(...)
except AppleTokenApiError as e:
    response = e.response  # requests response
    error = e.http_error  # HTTPError
    ...
```

There is also a case where the public keyset endpoint fails
to return a valid response. You can catch
ApplePublicKeysetApiError to cover this case.

Finally, you could get a request.exceptions.Timeout.

## Caching

The Apple public keyset should be cached. You can pass this
module a caching object which implements the `get` and `set`
methods.

For example, with django:

```
from django.core.cache import cache
from apple_sso import set_caching_object
```

You can also override the cache key with
`set_apple_auth_pubkeys_cache_key`
"""

import datetime
import json
from typing import Union

import funcy
import requests

from jwcrypto import jwk, jwt
from requests import HTTPError

APPLE_AUTH_TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token"  # nosec
APPLE_AUTH_PUBKEYS_ENDPOINT = "https://appleid.apple.com/auth/keys"
APPLE_AUTH_PUBKEYS_CACHE_KEY = "APPLE_AUTH_PUBKEYS_ENDPOINT"
APPLE_AUTH_JWT_ALGS = ["RS256"]
APPLE_AUTH_ISS = "https://appleid.apple.com"
RETRY_ERRORS = (
    requests.exceptions.ReadTimeout,
    requests.exceptions.Timeout,
    requests.exceptions.ConnectionError
)

cache = None


def set_caching_object(obj):
    global cache
    assert hasattr(obj, 'get')
    assert hasattr(obj, 'set')
    cache = obj


def set_apple_auth_pubkeys_cache_key(key):
    global APPLE_AUTH_PUBKEYS_CACHE_KEY
    APPLE_AUTH_PUBKEYS_CACHE_KEY = key


class AppleSsoApiError(Exception):
    def __init__(self, response, http_error):
        self._response = response
        self._http_error = http_error

    @property
    def response(self):
        return self._response

    @property
    def http_error(self):
        return self._http_error


class AppleTokenApiError(AppleSsoApiError):
    pass


class ApplePublicKeysetApiError(AppleSsoApiError):
    pass


@funcy.retry(5, errors=RETRY_ERRORS, timeout=lambda a: (a * 0.2) ** 2)
def make_get_request(url):
    response = requests.get(url)
    try:
        response.raise_for_status()
    except HTTPError as e:
        raise ApplePublicKeysetApiError(response, e)
    return response.content


def get_apple_public_keyset():
    """
    Retrieve the apple public keyset from apple's servers.
    """
    keyset = cache.get(APPLE_AUTH_PUBKEYS_CACHE_KEY)
    if not keyset:
        keyset = make_get_request(APPLE_AUTH_PUBKEYS_ENDPOINT)
        cache.set(APPLE_AUTH_PUBKEYS_CACHE_KEY, keyset, 60 * 2)
    return keyset


def deserialize_id_token(id_token: str, client_id: str) -> dict:
    """
    Deserialize the id_token that Apple form posts to your redirect_uri.
    Raises JWExceptions such as:
    jwcrypto.jwt.JWTInvalidClaimValue - raised when the iss or aud does not match.
    jwcrypto.jwt.JWTExpired - raised when the token is past expiration.

    :param id_token: id_token field that Apple form posts to your redirect_uri
    :param client_id: your Apple service id
    :return: dictionary containing all claims
    """
    apple_jwk = get_apple_public_keyset()
    apple_jwk_keyset = jwk.JWKSet.from_json(apple_jwk)

    jwt_obj = jwt.JWT(
        key=apple_jwk_keyset, jwt=id_token, algs=APPLE_AUTH_JWT_ALGS,
        check_claims={
            'iss': APPLE_AUTH_ISS,
            'aud': client_id,
            'exp': None,
            'email_verified': 'true'
        })
    # TODO what if the publickey changes? we should have a retry.
    return json.loads(jwt_obj.claims)


def generate_client_secret(client_id: str, team_id: str, pkey_id: str,
                           pkey_contents: Union[bytes, str]) -> str:
    """
    Generate the client_secret that Apple's token endpoint requires.
    https://developer.apple.com/documentation/signinwithapplerestapi/generate_and_validate_tokens
    :param client_id: your Apple service id
    :param team_id: your Apple account's team id
    :param pkey_id: your Apple key id
    :param pkey_contents: the contents of your private key
    :return: encrypted jwt token string
    """
    if isinstance(pkey_contents, str):
        pkey_contents = str.encode(pkey_contents)
    headers = {
        'kid': pkey_id,
        'alg': 'ES256',
    }
    claims = {
        'iss': team_id,
        'iat': int(datetime.datetime.now().timestamp()),
        'exp': int((datetime.datetime.now() + datetime.timedelta(days=180)).timestamp()),
        'aud': APPLE_AUTH_ISS,
        'sub': client_id,
    }

    key = jwk.JWK.from_pem(pkey_contents)
    token = jwt.JWT(header=headers, claims=claims)
    token.make_signed_token(key)
    return token.serialize()


def get_id_token(client_id: str, team_id: str,
                 pkey_id: str, pkey_contents: Union[bytes, str], code: str, redirect_uri: str):
    """
    Use the code that an Apple SSO frontend client obtained from Apple
    to get a token from Apple.
    This is to ensure that we get user information only from Apple and not
    a third party client like the frontend.
    Raises a requests exception on failure to validate.
    :param client_id: your Apple service id
    :param team_id: your Apple account's team id
    :param pkey_id: your Apple key id
    :param pkey_contents: the contents of your private key
    :param code: the code field that you received in the form post
    :param redirect_uri: the original redirect uri given to apple
    :return: dict of response from apple containing id_token
    """
    client_secret = generate_client_secret(client_id, team_id, pkey_id, pkey_contents)
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    }
    response = requests.post(APPLE_AUTH_TOKEN_ENDPOINT, payload, timeout=(2, 4))

    try:
        response.raise_for_status()
    except HTTPError as e:
        raise AppleTokenApiError(response, e)

    return response.json()
