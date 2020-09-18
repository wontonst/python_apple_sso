
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
