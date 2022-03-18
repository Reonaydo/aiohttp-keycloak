from setuptools import setup, find_packages

version = '__VERSION__'

setup(
    name='aiohttp_cloak',
    version=version,
    author='Leonid Popov',
    author_email='l.popov@ispsystem.com',
    # pylint: disable=line-too-long
    description='Package for authorization in AioHTTP application through KeyCloak as single method',
    # pylint: disable=line-too-long
    long_description='Package for authorization in AioHTTP application through KeyCloak as single method',
    long_description_content_type='text/markdown',
    url='https://gitlab-dev.ispsystem.net/extutils/aiohttp_cloak',
    packages=find_packages(),
    install_requires=[
        'aiohttp-oauth2',
        'aiohttp-session',
        'aiohttp'
    ],
    include_package_data=True,
    python_requires='>=3.7',
)
