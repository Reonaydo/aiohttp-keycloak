#!/usr/bin/env python

import logging
from typing import Optional, Callable, Dict
from functools import wraps
from datetime import datetime
from aiohttp_session import SimpleCookieStorage, session_middleware, Session
from aiohttp_session import get_session as get_real_session
from aiohttp import web, ClientSession
from aiohttp_oauth2 import oauth2_app


class KeycloakSession:
    """ Wrapper to Session from aiohttp_session """
    def __init__(self, session: Session):
        self._session = session
        if not self.updated:
            self.changed()

    def __repr__(self):
        return self._session.__repr__()

    def changed(self):
        self._session['updated'] = datetime.now().timestamp()
        self._session.changed()

    @property
    def updated(self):
        return int(self._session.get('updated', 0))

    def __getattr__(self, attr):
        return self._session.__getattribute__(attr)

    def __setitem__(self, key, value):
        self._session[key] = value
        if key == 'token':
            self._session[key]['created'] = datetime.now().timestamp()
        self.changed()

    def __delitem__(self, key):
        del self._session[key]
        self.changed()

    def update(self, mapping):
        self._session.update(mapping)
        self.changed()


async def get_session(request):
    real_session = await get_real_session(request)
    return KeycloakSession(real_session)


class KeycloakAuth:

    # pylint: disable=too-many-instance-attributes
    # This is class-storage

    def __init__(
            self,
            realm_url,
            client_id,
            client_secret,
            validate_userinfo: Optional[Callable[[dict], bool]] = None,
            prefix: Optional[str] = None,
            session_lifetime: int = 86400,
            default_location: Optional[str] = '/'
    ):
        self.subapp = None
        self._realm_url = realm_url
        self._client_id = client_id
        self._client_secret = client_secret
        # If we need not validate then just True
        # Tis is callable
        self._validate_userinfo = validate_userinfo
        if not prefix:
            prefix = '/cloak/'
        if prefix[0] != '/':
            prefix = '/' + prefix
        if prefix[-1] != '/':
            prefix = prefix + '/'
        self.prefix = prefix
        self._session_lifetime = session_lifetime
        self._default_location = default_location

    def userinfo_validate(self, userinfo):
        if not self._validate_userinfo:
            return True
        return self._validate_userinfo(userinfo)

    @property
    def token_url(self):
        return (self._realm_url + '/protocol/openid-connect/token')

    @property
    def authorize_url(self):
        return (self._realm_url + '/protocol/openid-connect/auth')

    @property
    def userinfo_url(self):
        return (self._realm_url + '/protocol/openid-connect/userinfo')

    @property
    def auth_url(self):
        if self.subapp:
            return self.subapp.router['auth'].url_for()
        return (self.prefix + 'auth')

    @property
    def session_lifetime(self):
        return self._session_lifetime

    @property
    def logout_url(self):
        return (self._realm_url + '/protocol/openid-connect/logout')

    @property
    def default_location(self):
        return (self._default_location or '/')

    async def refresh_token(self, token: Dict[str, str]):
        refresh_token = token.get('refresh_token')
        async with ClientSession() as client:
            params = {
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }
            async with client.post(self.token_url, data=params) as resp:
                return await resp.json()

    async def logout(self, token):
        refresh_token = token.get('refresh_token')
        access_token = token.get('access_token')
        async with ClientSession() as client_session:
            params = {
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'refresh_token': refresh_token
            }
            await client_session.post(
                self.logout_url,
                data=params,
                headers={'Authorization': 'Bearer %s' % access_token}
            )

    async def get_userinfo(self, access_token):
        userinfo_url = self.userinfo_url
        async with ClientSession() as session:
            async with session.get(
                userinfo_url,
                headers={"Authorization": "Bearer %s" % access_token},
            ) as r:
                userinfo = await r.json()
                return userinfo


def auth_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find request. Copypasted from aiohttp_session
        request = (args[-1].request if isinstance(args[-1], web.View) else args[-1])
        session = await get_session(request)
        current_timestamp = datetime.now().timestamp()
        cloak = request.app['keycloak']
        if session.updated + cloak.session_lifetime < current_timestamp:
            logging.debug('Session too old. Revalidate')
            token = session.get('token', {})
            logging.debug('Current token: %s', token)
            # 10 seconds for lag
            t_created = int(token.get('created', 0))
            t_expires_in = int(token.get('expires_in', 0))
            if t_created + t_expires_in < current_timestamp + 10:
                logging.debug('Access token expired')
                token = await cloak.refresh_token(token)
                # token = await refresh_token(token, cloak)
                token['created'] = datetime.now().timestamp()
                logging.debug('Refreshed token: %s', token)
                session['token'] = token

            access_token = token.get('access_token')
            logging.debug('Refreshing userinfo')
            userinfo = await cloak.get_userinfo(access_token)
            session['userinfo'] = userinfo

        userinfo = session.get('userinfo')

        if not userinfo or userinfo.get('error'):
            session.invalidate()
            raise web.HTTPUnauthorized()
        if not cloak.userinfo_validate(userinfo):
            raise web.HTTPForbidden()
        return await func(*args, **kwargs)
    return wrapper


async def logout_cloak(request):
    session = await get_session(request)
    token = session.get('token', {})
    keycloak = request.app['keycloak']
    if token:
        keycloak.logout(token)
    session.invalidate()


async def on_login(request: web.Request, token):
    session = await get_session(request)
    keycloak = request.app['keycloak']
    logging.debug(token)
    userinfo = await keycloak.get_userinfo(token['access_token'])
    if userinfo and keycloak.userinfo_validate(userinfo):
        session['token'] = token
        session['userinfo'] = userinfo
    else:
        return web.HTTPForbidden()
    return web.HTTPTemporaryRedirect(location=keycloak.default_location)


async def authorized_user(request):
    session = await get_session(request)
    userinfo = session.get('userinfo', {})
    return userinfo


async def get_auth_url(request):
    return request.app['keycloak'].auth_url


def setup_cloak(
        app,
        realm_url,
        client_id,
        client_secret,
        scopes=None,
        validate_userinfo: Optional[Callable[[dict], bool]] = None,
        prefix: Optional[str] = None,
        session_lifetime: int = 86400,
        default_location: Optional[str] = '/',
        cookie_storage=None
        ):
    # Append session
    if not cookie_storage:
        cookie_storage = SimpleCookieStorage()
    app.middlewares.insert(0, session_middleware(cookie_storage))

    keycloak = KeycloakAuth(
        realm_url,
        client_id,
        client_secret,
        validate_userinfo=validate_userinfo,
        prefix=prefix,
        session_lifetime=session_lifetime,
        default_location=default_location
    )
    app['keycloak'] = keycloak
    cloak_subapp = oauth2_app(
        authorize_url=keycloak.authorize_url,
        token_url=keycloak.token_url,
        client_id=client_id,
        client_secret=client_secret,
        on_login=on_login,
        json_data=False,  # Need for keycloak
        scopes=scopes
    )
    keycloak.subapp = cloak_subapp
    cloak_subapp['keycloak'] = app['keycloak']
    app.add_subapp(
        keycloak.prefix,
        cloak_subapp
    )
