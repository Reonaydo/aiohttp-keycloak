Example usage:

```python
#!/usr/bin/env python

import os
import logging
from aiohttp import web
import aiohttp_jinja2
import jinja2
from aiohttp_session.cookie_storage import EncryptedCookieStorage
from aiohttp_cloak import setup_cloak, auth_required, logout_cloak, authorized_user, get_auth_url

VALID_GROUP = 'some_group'

REALM_URL = os.environ.get('REALM_URL', 'https://keycloak.example.com/auth/realms/example.com')
CLIENT_ID = os.environ.get('CLIENT_ID', 'example_client')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET', 'xxxx-xxx-xxx-xxx')

# from cryptography import fernet
# fernet.Fernet.generate_key()
COOKIE_SECRET = os.environ.get('COOKIE_SECRET', 'xxxxxxxxxxxx')


def userinfo_validate(userinfo):
    return VALID_GROUP in userinfo.get('groups', [])


async def errorpages_middleware(app, handler):
    async def middleware_handler(request):
        try:
            return await handler(request)
        except web.HTTPException as ex:
            if ex.status == 401:
                return aiohttp_jinja2.render_template('error.jinja2', request, {'error': ex, 'userinfo': {'name': 'Anonymous'}}, status=401)
    return middleware_handler


async def current_userinfo_ctx_processor(request):
    userinfo = await authorized_user(request)
    if not userinfo:
        userinfo['name'] = 'Anonymous'
        userinfo['logged_in'] = False
    else:
        userinfo['logged_in'] = True
    auth_url = await get_auth_url(request)
    return{'userinfo': userinfo, 'auth_url': auth_url}


middlewares = [
    errorpages_middleware
]
app = web.Application(middlewares=middlewares)
routes = web.RouteTableDef()
setup_cloak(
    app,
    REALM_URL,
    CLIENT_ID,
    CLIENT_SECRET,
    validate_userinfo=userinfo_validate,
    scopes=['some_scope'],
    session_lifetime=86400,  # 1 day
    cookie_storage=EncryptedCookieStorage(COOKIE_SECRET)
)
# Jinja should be setup after session middleware
aiohttp_jinja2.setup(
    app,
    context_processors=[aiohttp_jinja2.request_processor, current_userinfo_ctx_processor],
    loader=jinja2.FileSystemLoader(os.path.join(os.getcwd(), 'templates'))
)


@routes.get('/logout')
@auth_required
async def logout(request: web.Request):
    await logout_cloak(request)
    return web.HTTPTemporaryRedirect(location="/")


@routes.get('/')
@aiohttp_jinja2.template('main.jinja2')
@auth_required
async def root(request):
    return {'data': 'You are authorized'}


app.add_routes(routes)


def main():
    logging.basicConfig(level=logging.INFO)
    web.run_app(app, port=8010)


if __name__ == '__main__':
    main()
```
