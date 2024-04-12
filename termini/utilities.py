#!/usr/bin/env python
u"""
utilities.py
Written by Tyler Sutterley (04/2024)
Download and management utilities

UPDATE HISTORY:
    Written 04/2024
"""
from __future__ import print_function, division, annotations

import sys
import os
import re
import io
import ssl
import json
import netrc
import shutil
import base64
import getpass
import hashlib
import inspect
import logging
import pathlib
import builtins
import warnings
import posixpath
import traceback
import subprocess
import calendar, time
if sys.version_info[0] == 2:
    from cookielib import CookieJar
    from urllib import urlencode
    import urllib2
else:
    from http.cookiejar import CookieJar
    from urllib.parse import urlencode
    import urllib.request as urllib2

# attempt imports
try:
    import boto3
except (AttributeError, ImportError, ModuleNotFoundError) as exc:
    logging.debug("boto3 not available")
try:
    import s3fs
except (AttributeError, ImportError, ModuleNotFoundError) as exc:
    logging.debug("s3fs not available")

# PURPOSE: get absolute path within a package from a relative path
def get_data_path(relpath: list | str | pathlib.Path):
    """
    Get the absolute path within a package from a relative path

    Parameters
    ----------
    relpath: list, str or pathlib.Path
        relative path
    """
    # current file path
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    filepath = pathlib.Path(filename).absolute().parent
    if isinstance(relpath, list):
        # use *splat operator to extract from list
        return filepath.joinpath(*relpath)
    elif isinstance(relpath, (str, pathlib.Path)):
        return filepath.joinpath(relpath)

# PURPOSE: get the hash value of a file
def get_hash(
        local: str | io.IOBase | pathlib.Path,
        algorithm: str = 'MD5'
    ):
    """
    Get the hash value from a local file or ``BytesIO`` object

    Parameters
    ----------
    local: obj, str or pathlib.Path
        BytesIO object or path to file
    algorithm: str, default 'MD5'
        hashing algorithm for checksum validation

            - ``'MD5'``: Message Digest
            - ``'sha1'``: Secure Hash Algorithm
    """
    # check if open file object or if local file exists
    if isinstance(local, io.IOBase):
        if (algorithm == 'MD5'):
            return hashlib.md5(local.getvalue()).hexdigest()
        elif (algorithm == 'sha1'):
            return hashlib.sha1(local.getvalue()).hexdigest()
    elif isinstance(local, (str, pathlib.Path)):
        # generate checksum hash for local file
        local = pathlib.Path(local).expanduser()
        # if file currently doesn't exist, return empty string
        if not local.exists():
            return ''
        # open the local_file in binary read mode
        with local.open(mode='rb') as local_buffer:
            # generate checksum hash for a given type
            if (algorithm == 'MD5'):
                return hashlib.md5(local_buffer.read()).hexdigest()
            elif (algorithm == 'sha1'):
                return hashlib.sha1(local_buffer.read()).hexdigest()
    else:
        return ''

# PURPOSE: get the git hash value
def get_git_revision_hash(
        refname: str = 'HEAD',
        short: bool = False
    ):
    """
    Get the ``git`` hash value for a particular reference

    Parameters
    ----------
    refname: str, default HEAD
        Symbolic reference name
    short: bool, default False
        Return the shorted hash value
    """
    # get path to .git directory from current file path
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    basepath = pathlib.Path(filename).absolute().parent.parent
    gitpath = basepath.joinpath('.git')
    # build command
    cmd = ['git', f'--git-dir={gitpath}', 'rev-parse']
    cmd.append('--short') if short else None
    cmd.append(refname)
    # get output
    with warnings.catch_warnings():
        return str(subprocess.check_output(cmd), encoding='utf8').strip()

# PURPOSE: get the current git status
def get_git_status():
    """Get the status of a ``git`` repository as a boolean value
    """
    # get path to .git directory from current file path
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    basepath = pathlib.Path(filename).absolute().parent.parent
    gitpath = basepath.joinpath('.git')
    # build command
    cmd = ['git', f'--git-dir={gitpath}', 'status', '--porcelain']
    with warnings.catch_warnings():
        return bool(subprocess.check_output(cmd))

# PURPOSE: recursively split a url path
def url_split(s: str):
    """
    Recursively split a url path into a list

    Parameters
    ----------
    s: str
        url string
    """
    head, tail = posixpath.split(s)
    if head in ('http:','https:','ftp:','s3:'):
        return s,
    elif head in ('', posixpath.sep):
        return tail,
    return url_split(head) + (tail,)

# PURPOSE: returns the Unix timestamp value for a formatted date string
def get_unix_time(
        time_string: str,
        format: str = '%Y-%m-%d %H:%M:%S'
    ):
    """
    Get the Unix timestamp value for a formatted date string

    Parameters
    ----------
    time_string: str
        formatted time string to parse
    format: str, default '%Y-%m-%d %H:%M:%S'
        format for input time string
    """
    try:
        parsed_time = time.strptime(time_string.rstrip(), format)
    except (TypeError, ValueError):
        pass
    else:
        return calendar.timegm(parsed_time)

# NASA on-prem DAAC providers
_daac_providers = {
    'gesdisc': 'GES_DISC',
    'ghrcdaac': 'GHRC_DAAC',
    'lpdaac': 'LPDAAC_ECS',
    'nsidc': 'NSIDC_ECS',
    'ornldaac': 'ORNL_DAAC',
    'podaac': 'PODAAC',
}

# NASA Cumulus AWS providers
_s3_providers = {
    'gesdisc': 'GES_DISC',
    'ghrcdaac': 'GHRC_DAAC',
    'lpdaac': 'LPCLOUD',
    'nsidc': 'NSIDC_CPRD',
    'ornldaac': 'ORNL_CLOUD',
    'podaac': 'POCLOUD',
}

# NASA Cumulus AWS S3 credential endpoints
_s3_endpoints = {
    'gesdisc': 'https://data.gesdisc.earthdata.nasa.gov/s3credentials',
    'ghrcdaac': 'https://data.ghrc.earthdata.nasa.gov/s3credentials',
    'lpdaac': 'https://data.lpdaac.earthdatacloud.nasa.gov/s3credentials',
    'nsidc': 'https://data.nsidc.earthdatacloud.nasa.gov/s3credentials',
    'ornldaac': 'https://data.ornldaac.earthdata.nasa.gov/s3credentials',
    'podaac': 'https://archive.podaac.earthdata.nasa.gov/s3credentials'
}

# NASA Cumulus AWS S3 buckets
_s3_buckets = {
    'gesdisc': 'gesdisc-cumulus-prod-protected',
    'ghrcdaac': 'ghrc-cumulus-dev',
    'lpdaac': 'lp-prod-protected',
    'nsidc': 'nsidc-cumulus-prod-protected',
    'ornldaac': 'ornl-cumulus-prod-protected',
    'podaac': 'podaac-ops-cumulus-protected'
}

# PURPOSE: get AWS s3 client for NSIDC Cumulus
def s3_client(
        HOST: str = _s3_endpoints['nsidc'],
        timeout: int | None = None,
        region_name: str = 'us-west-2'
    ):
    """
    Get AWS s3 client for NSIDC data in the cloud
    https://data.nsidc.earthdatacloud.nasa.gov/s3credentials

    Parameters
    ----------
    HOST: str
        NSIDC AWS S3 credential host
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    region_name: str, default 'us-west-2'
        AWS region name

    Returns
    -------
    client: obj
        AWS s3 client for NSIDC Cumulus
    """
    request = urllib2.Request(HOST)
    response = urllib2.urlopen(request, timeout=timeout)
    cumulus = json.loads(response.read())
    # get AWS client object
    client = boto3.client('s3',
        aws_access_key_id=cumulus['accessKeyId'],
        aws_secret_access_key=cumulus['secretAccessKey'],
        aws_session_token=cumulus['sessionToken'],
        region_name=region_name)
    # return the AWS client for region
    return client

# PURPOSE: get AWS s3 file system for NSIDC Cumulus
def s3_filesystem(
        HOST: str = _s3_endpoints['nsidc'],
        timeout: int | None = None,
        region_name: str = 'us-west-2'
    ):
    """
    Get AWS s3 file system object for NSIDC data in the cloud
    https://data.nsidc.earthdatacloud.nasa.gov/s3credentials

    Parameters
    ----------
    HOST: str
        NSIDC AWS S3 credential host
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    region_name: str, default 'us-west-2'
        AWS region name

    Returns
    -------
    session: obj
        AWS s3 file system session for NSIDC Cumulus
    """
    request = urllib2.Request(HOST)
    response = urllib2.urlopen(request, timeout=timeout)
    cumulus = json.loads(response.read())
    # get AWS file system session object
    session = s3fs.S3FileSystem(anon=False,
        key=cumulus['accessKeyId'],
        secret=cumulus['secretAccessKey'],
        token=cumulus['sessionToken'],
        client_kwargs=dict(
            region_name=region_name
        )
    )
    # return the AWS session for region
    return session

# PURPOSE: get a s3 bucket name from a presigned url
def s3_bucket(presigned_url: str):
    """
    Get a s3 bucket name from a presigned url

    Parameters
    ----------
    presigned_url: str
        s3 presigned url

    Returns
    -------
    bucket: str
        s3 bucket name
    """
    host = url_split(presigned_url)
    bucket = re.sub(r's3:\/\/', r'', host[0], re.IGNORECASE)
    return bucket

# PURPOSE: get a s3 bucket key from a presigned url
def s3_key(presigned_url: str):
    """
    Get a s3 bucket key from a presigned url

    Parameters
    ----------
    presigned_url: str
        s3 presigned url or https url

    Returns
    -------
    key: str
        s3 bucket key for object
    """
    host = url_split(presigned_url)
    # check if url is https url or s3 presigned url
    if presigned_url.startswith('http'):
        # use NSIDC format for s3 keys from https
        parsed = [p for part in host[-4:-1] for p in part.split('.')]
        # join parsed url parts to form bucket key
        key = posixpath.join(*parsed, host[-1])
    else:
        # join presigned url to form bucket key
        key = posixpath.join(*host[1:])
    # return the s3 bucket key for object
    return key

# PURPOSE: get a s3 presigned url from a bucket and key
def s3_presigned_url(
        bucket: str,
        key: str
    ):
    """
    Get a s3 presigned url from a bucket and object key

    Parameters
    ----------
    bucket: str
        s3 bucket name
    key: str
        s3 bucket key for object

    Returns
    -------
    presigned_url: str
        s3 presigned url
    """
    return posixpath.join('s3://', bucket, key)

# PURPOSE: generate a s3 presigned https url from a bucket and key
def generate_presigned_url(
        bucket: str,
        key: str,
        expiration: int = 3600
    ):
    """
    Generate a presigned https URL to share an S3 object

    Parameters
    ----------
    bucket: str
        s3 bucket name
    key: str
        s3 bucket key for object
    expiration: int
        Time in seconds for the presigned URL to remain valid

    Returns
    -------
    presigned_url: str
        s3 presigned https url
    """
    # generate a presigned URL for S3 object
    s3 = boto3.client('s3')
    try:
        response = s3.generate_presigned_url('get_object',
            Params={'Bucket': bucket, 'Key': key},
            ExpiresIn=expiration)
    except Exception as exc:
        logging.error(exc)
        return None
    # The response contains the presigned URL
    return response

def _create_default_ssl_context() -> ssl.SSLContext:
    """Creates the default SSL context
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    _set_ssl_context_options(context)
    context.options |= ssl.OP_NO_COMPRESSION
    return context

def _create_ssl_context_no_verify() -> ssl.SSLContext:
    """Creates an SSL context for unverified connections
    """
    context = _create_default_ssl_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def _set_ssl_context_options(context: ssl.SSLContext) -> None:
    """Sets the default options for the SSL context
    """
    if sys.version_info >= (3, 10) or ssl.OPENSSL_VERSION_INFO >= (1, 1, 0, 7):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1

# default ssl context
_default_ssl_context = _create_ssl_context_no_verify()

# PURPOSE: attempt to build an opener with netrc
def attempt_login(
        urs: str = 'urs.earthdata.nasa.gov',
        context=_default_ssl_context,
        password_manager: bool = True,
        get_ca_certs: bool = False,
        redirect: bool = False,
        authorization_header: bool = False,
        **kwargs
    ):
    """
    attempt to build a ``urllib`` opener for NASA Earthdata

    Parameters
    ----------
    urs: str, default urs.earthdata.nasa.gov
        Earthdata login URS 3 host
    context: obj, default IS2view.utilities._default_ssl_context
        SSL context for ``urllib`` opener object
    password_manager: bool, default True
        Create password manager context using default realm
    get_ca_certs: bool, default False
        Get list of loaded “certification authority” certificates
    redirect: bool, default False
        Create redirect handler object
    authorization_header: bool, default False
        Add base64 encoded authorization header to opener
    username: str, default from environmental variable
        NASA Earthdata username
    password: str, default from environmental variable
        NASA Earthdata password
    retries: int, default 5
        number of retry attempts
    netrc: str, default ~/.netrc
        path to .netrc file for authentication

    Returns
    -------
    opener: obj
        OpenerDirector instance
    """
    # set default keyword arguments
    kwargs.setdefault('username', os.environ.get('EARTHDATA_USERNAME'))
    kwargs.setdefault('password', os.environ.get('EARTHDATA_PASSWORD'))
    kwargs.setdefault('retries', 5)
    kwargs.setdefault('netrc', pathlib.Path.home().joinpath('.netrc'))
    try:
        # only necessary on jupyterhub
        kwargs['netrc'].chmod(mode=0o600)
        # try retrieving credentials from netrc
        username, _, password = netrc.netrc(kwargs['netrc']).authenticators(urs)
    except Exception as exc:
        logging.error(exc)
        # try retrieving credentials from environmental variables
        username, password = (kwargs['username'], kwargs['password'])
        pass
    # if username or password are not available
    if not username:
        username = builtins.input(f'Username for {urs}: ')
    if not password:
        password = getpass.getpass(prompt=f'Password for {username}@{urs}: ')
    # for each retry
    for retry in range(kwargs['retries']):
        # build an opener for urs with credentials
        opener = build_opener(username, password,
            context=context,
            password_manager=password_manager,
            get_ca_certs=get_ca_certs,
            redirect=redirect,
            authorization_header=authorization_header,
            urs=urs)
        # try logging in by check credentials
        try:
            check_credentials()
        except Exception as exc:
            logging.error(exc)
            pass
        else:
            return opener
        # reattempt login
        username = builtins.input(f'Username for {urs}: ')
        password = getpass.getpass(prompt=f'Password for {username}@{urs}: ')
    # reached end of available retries
    raise RuntimeError('End of Retries: Check NASA Earthdata credentials')

# PURPOSE: "login" to NASA Earthdata with supplied credentials
def build_opener(
        username: str,
        password: str,
        context=_default_ssl_context,
        password_manager: bool = True,
        get_ca_certs: bool = False,
        redirect: bool = False,
        authorization_header: bool = False,
        urs: str = 'https://urs.earthdata.nasa.gov'
    ):
    """
    Build ``urllib`` opener for NASA Earthdata with supplied credentials

    Parameters
    ----------
    username: str or NoneType, default None
        NASA Earthdata username
    password: str or NoneType, default None
        NASA Earthdata password
    context: obj, default IS2view.utilities._default_ssl_context
        SSL context for ``urllib`` opener object
    password_manager: bool, default True
        Create password manager context using default realm
    get_ca_certs: bool, default False
        Get list of loaded “certification authority” certificates
    redirect: bool, default False
        Create redirect handler object
    authorization_header: bool, default False
        Add base64 encoded authorization header to opener
    urs: str, default 'https://urs.earthdata.nasa.gov'
        Earthdata login URS 3 host

    Returns
    -------
    opener: obj
        ``OpenerDirector`` instance
    """
    # https://docs.python.org/3/howto/urllib2.html#id5
    handler = []
    # create a password manager
    if password_manager:
        password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
        # Add the username and password for NASA Earthdata Login system
        password_mgr.add_password(None, urs, username, password)
        handler.append(urllib2.HTTPBasicAuthHandler(password_mgr))
    # Create cookie jar for storing cookies. This is used to store and return
    # the session cookie given to use by the data server (otherwise will just
    # keep sending us back to Earthdata Login to authenticate).
    cookie_jar = CookieJar()
    handler.append(urllib2.HTTPCookieProcessor(cookie_jar))
    # SSL context handler
    if get_ca_certs:
        context.get_ca_certs()
    handler.append(urllib2.HTTPSHandler(context=context))
    # redirect handler
    if redirect:
        handler.append(urllib2.HTTPRedirectHandler())
    # create "opener" (OpenerDirector instance)
    opener = urllib2.build_opener(*handler)
    # Encode username/password for request authorization headers
    # add Authorization header to opener
    if authorization_header:
        b64 = base64.b64encode(f'{username}:{password}'.encode())
        opener.addheaders = [("Authorization", f"Basic {b64.decode()}")]
    # Now all calls to urllib2.urlopen use our opener.
    urllib2.install_opener(opener)
    # All calls to urllib2.urlopen will now use handler
    # Make sure not to include the protocol in with the URL, or
    # HTTPPasswordMgrWithDefaultRealm will be confused.
    return opener

# PURPOSE: generate a NASA Earthdata user token
def get_token(
        HOST: str = 'https://urs.earthdata.nasa.gov/api/users/token',
        username: str | None = None,
        password: str | None = None,
        build: bool = True,
        urs: str = 'urs.earthdata.nasa.gov',
    ):
    """
    Generate a NASA Earthdata User Token

    Parameters
    ----------
    HOST: str or list
        NASA Earthdata token API host
    username: str or NoneType, default None
        NASA Earthdata username
    password: str or NoneType, default None
        NASA Earthdata password
    build: bool, default True
        Build opener and check WebDAV credentials
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    urs: str, default 'urs.earthdata.nasa.gov'
        NASA Earthdata URS 3 host

    Returns
    -------
    token: dict
        JSON response with NASA Earthdata User Token
    """
    # attempt to build urllib2 opener and check credentials
    if build:
        attempt_login(urs,
            username=username,
            password=password,
            password_manager=False,
            authorization_header=True)
    # create post response with Earthdata token API
    try:
        request = urllib2.Request(HOST, method='POST')
        response = urllib2.urlopen(request)
    except urllib2.HTTPError as exc:
        logging.debug(exc.code)
        raise RuntimeError(exc.reason) from exc
    except urllib2.URLError as exc:
        logging.debug(exc.reason)
        raise RuntimeError('Check internet connection') from exc
    # read and return JSON response
    return json.loads(response.read())

# PURPOSE: generate a NASA Earthdata user token
def list_tokens(
        HOST: str = 'https://urs.earthdata.nasa.gov/api/users/tokens',
        username: str | None = None,
        password: str | None = None,
        build: bool = True,
        urs: str = 'urs.earthdata.nasa.gov',
    ):
    """
    List the current associated NASA Earthdata User Tokens

    Parameters
    ----------
    HOST: str
        NASA Earthdata list token API host
    username: str or NoneType, default None
        NASA Earthdata username
    password: str or NoneType, default None
        NASA Earthdata password
    build: bool, default True
        Build opener and check WebDAV credentials
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    urs: str, default 'urs.earthdata.nasa.gov'
        NASA Earthdata URS 3 host

    Returns
    -------
    tokens: list
        JSON response with NASA Earthdata User Tokens
    """
    # attempt to build urllib2 opener and check credentials
    if build:
        attempt_login(urs,
            username=username,
            password=password,
            password_manager=False,
            authorization_header=True)
    # create get response with Earthdata list tokens API
    try:
        request = urllib2.Request(HOST)
        response = urllib2.urlopen(request)
    except urllib2.HTTPError as exc:
        logging.debug(exc.code)
        raise RuntimeError(exc.reason) from exc
    except urllib2.URLError as exc:
        logging.debug(exc.reason)
        raise RuntimeError('Check internet connection') from exc
    # read and return JSON response
    return json.loads(response.read())

# PURPOSE: revoke a NASA Earthdata user token
def revoke_token(
        token: str,
        HOST: str = f'https://urs.earthdata.nasa.gov/api/users/revoke_token',
        username: str | None = None,
        password: str | None = None,
        build: bool = True,
        urs: str = 'urs.earthdata.nasa.gov',
    ):
    """
    Generate a NASA Earthdata User Token

    Parameters
    ----------
    token: str
        NASA Earthdata token to be revoked
    HOST: str
        NASA Earthdata revoke token API host
    username: str or NoneType, default None
        NASA Earthdata username
    password: str or NoneType, default None
        NASA Earthdata password
    build: bool, default True
        Build opener and check WebDAV credentials
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    urs: str, default 'urs.earthdata.nasa.gov'
        NASA Earthdata URS 3 host
    """
    # attempt to build urllib2 opener and check credentials
    if build:
        attempt_login(urs,
            username=username,
            password=password,
            password_manager=False,
            authorization_header=True)
    # full path for NASA Earthdata revoke token API
    url = f'{HOST}?token={token}'
    # create post response with Earthdata revoke tokens API
    try:
        request = urllib2.Request(url, method='POST')
        response = urllib2.urlopen(request)
    except urllib2.HTTPError as exc:
        logging.debug(exc.code)
        raise RuntimeError(exc.reason) from exc
    except urllib2.URLError as exc:
        logging.debug(exc.reason)
        raise RuntimeError('Check internet connection') from exc
    # verbose response
    logging.debug(f'Token Revoked: {token}')

# PURPOSE: check that entered NASA Earthdata credentials are valid
def check_credentials():
    """
    Check that entered NASA Earthdata credentials are valid
    """
    try:
        remote_path = posixpath.join('https://n5eil01u.ecs.nsidc.org', 'ATLAS')
        request = urllib2.Request(url=remote_path)
        response = urllib2.urlopen(request, timeout=20)
    except urllib2.HTTPError:
        raise RuntimeError('Check your NASA Earthdata credentials')
    except urllib2.URLError:
        raise RuntimeError('Check internet connection')
    else:
        return True

# PURPOSE: download a file from a NSIDC https server
def from_nsidc(
        HOST: str | list,
        username: str | None = None,
        password: str | None = None,
        build: bool = True,
        timeout: int | None = None,
        urs: str = 'urs.earthdata.nasa.gov',
        local: str | pathlib.Path | None = None,
        hash: str = '',
        chunk: int = 16384,
        verbose: bool = False,
        fid=sys.stdout,
        mode: oct = 0o775
    ):
    """
    Download a file from a NSIDC https server

    Parameters
    ----------
    HOST: str or list
        remote https host
    username: str or NoneType, default None
        NASA Earthdata username
    password: str or NoneType, default None
        NASA Earthdata password
    build: bool, default True
        Build opener and check WebDAV credentials
    timeout: int or NoneType, default None
        timeout in seconds for blocking operations
    urs: str, default 'urs.earthdata.nasa.gov'
        NASA Earthdata URS 3 host
    local: str or NoneType, default None
        path to local file
    hash: str, default ''
        MD5 hash of local file
    chunk: int, default 16384
        chunk size for transfer encoding
    verbose: bool, default False
        print file transfer information
    fid: obj, default sys.stdout
        open file object to print if verbose
    mode: oct, default 0o775
        permissions mode of output local file

    Returns
    -------
    remote_buffer: obj
        BytesIO representation of file
    response_error: str or None
        notification for response error
    """
    # create logger
    loglevel = logging.INFO if verbose else logging.CRITICAL
    logging.basicConfig(stream=fid, level=loglevel)
    # attempt to build urllib2 opener and check credentials
    if build:
        attempt_login(urs, username=username, password=password)
    # verify inputs for remote https host
    if isinstance(HOST, str):
        HOST = url_split(HOST)
    # try downloading from https
    try:
        # Create and submit request.
        request = urllib2.Request(posixpath.join(*HOST))
        response = urllib2.urlopen(request, timeout=timeout)
    except (urllib2.HTTPError, urllib2.URLError) as exc:
        logging.error(exc)
        response_error = 'Download error from {0}'.format(posixpath.join(*HOST))
        return (False, response_error)
    else:
        # copy remote file contents to bytesIO object
        remote_buffer = io.BytesIO()
        shutil.copyfileobj(response, remote_buffer, chunk)
        remote_buffer.seek(0)
        # save file basename with bytesIO object
        remote_buffer.filename = HOST[-1]
        # generate checksum hash for remote file
        remote_hash = hashlib.md5(remote_buffer.getvalue()).hexdigest()
        # compare checksums
        if local and (hash != remote_hash):
            # convert to absolute path
            local = pathlib.Path(local).expanduser().absolute()
            # create directory if non-existent
            local.parent.mkdir(mode=mode, parents=True, exist_ok=True)
            # print file information
            args = (posixpath.join(*HOST), str(local))
            logging.info('{0} -->\n\t{1}'.format(*args))
            # store bytes to file using chunked transfer encoding
            remote_buffer.seek(0)
            with local.open(mode='wb') as f:
                shutil.copyfileobj(remote_buffer, f, chunk)
            # change the permissions mode
            local.chmod(mode=mode)
        # return the bytesIO object
        remote_buffer.seek(0)
        return (remote_buffer, None)

# PURPOSE: build formatted query string for data release
def cmr_query_release(release: str | int | None):
    """
    Build formatted query string for data release

    Parameters
    ----------
    release: str
        data release

    Returns
    -------
    query_params: str
        formatted string for CMR queries
    """
    if release is None:
        return ''
    # maximum length of version in CMR queries
    desired_pad_length = 3
    if len(str(release)) > desired_pad_length:
        raise RuntimeError(f'Release string too long: "{release}"')
    # Strip off any leading zeros
    release = str(release).lstrip('0')
    query_params = ''
    while len(release) <= desired_pad_length:
        padded_release = release.zfill(desired_pad_length)
        query_params += f'&version={padded_release}'
        desired_pad_length -= 1
    return query_params

# PURPOSE: filter the CMR json response for desired data files
def cmr_filter_json(
        search_results: dict,
        endpoint: str = "data",
    ):
    """
    Filter the CMR json response for desired data files

    Parameters
    ----------
    search_results: dict
        json response from CMR query
    endpoint: str, default 'data'
        url endpoint type

            - ``'data'``: NASA Earthdata https archive
            - ``'opendap'``: NASA Earthdata OPeNDAP archive
            - ``'s3'``: NASA Earthdata Cumulus AWS S3 bucket

    Returns
    -------
    granule_urls: list
        granule urls from NSIDC
    """
    # output list of granule urls
    granule_urls = []
    # check that there are urls for request
    if ('feed' not in search_results) or ('entry' not in search_results['feed']):
        return granule_urls
    # descriptor links for each endpoint
    rel = {}
    rel['data'] = "http://esipfed.org/ns/fedsearch/1.1/data#"
    rel['opendap'] = "http://esipfed.org/ns/fedsearch/1.1/service#"
    rel['s3'] = "http://esipfed.org/ns/fedsearch/1.1/s3#"
    # iterate over references and get cmr location
    for entry in search_results['feed']['entry']:
        for link in entry['links']:
            # skip links without descriptors
            if ('rel' not in link.keys()):
                continue
            if ('type' not in link.keys()):
                continue
            # append if selected endpoint and request type
            if (link['rel'] == rel[endpoint]):
                granule_urls.append(link['href'])
    # return the list of urls and granule ids
    return granule_urls

# PURPOSE: cmr queries
def cmr(
        collection_concept_id: str = 'C2565878363-NSIDC_ECS',
        producer_granule_id: str = 'glacier_termini_v01.0',
        release: str | int = 1,
        provider: str = 'NSIDC_ECS',
        endpoint: str = 'data',
        opener = None,
        context: ssl.SSLContext = _default_ssl_context,
        verbose: bool = False,
        fid = sys.stdout
    ):
    """
    Query the NASA Common Metadata Repository (CMR) for MEaSUREs data

    Parameters
    ----------
    release: str or NoneType, default None
        data release
    provider: str, default 'NSIDC_ECS'
        CMR data provider
    endpoint: str, default 'data'
        url endpoint type

            - ``'data'``: NASA Earthdata https archive
            - ``'opendap'``: NASA Earthdata OPeNDAP archive
            - ``'s3'``: NASA Earthdata Cumulus AWS S3 bucket
    opener: obj or NoneType, default None
        ``OpenerDirector`` instance
    context: obj, default IS2view.utilities._default_ssl_context
        SSL context for ``urllib`` opener object
    verbose: bool, default False
        print file transfer information
    fid: obj, default sys.stdout
        open file object to print if verbose

    Returns
    -------
    granule_urls: list
        granule urls from NSIDC
    """
    # create logger
    loglevel = logging.INFO if verbose else logging.CRITICAL
    logging.basicConfig(stream=fid, level=loglevel)
    # attempt to build urllib2 opener
    if opener is None:
        # build urllib2 opener with SSL context
        # https://docs.python.org/3/howto/urllib2.html#id5
        handler = []
        # Create cookie jar for storing cookies
        cookie_jar = CookieJar()
        handler.append(urllib2.HTTPCookieProcessor(cookie_jar))
        handler.append(urllib2.HTTPSHandler(context=context))
        # create "opener" (OpenerDirector instance)
        opener = urllib2.build_opener(*handler)
    # build CMR query
    cmr_query_type = 'granules'
    cmr_format = 'json'
    cmr_page_size = 2000
    CMR_HOST = ['https://cmr.earthdata.nasa.gov', 'search',
        f'{cmr_query_type}.{cmr_format}']
    # build list of CMR query parameters
    CMR_KEYS = []
    CMR_KEYS.append(f'?provider={provider}')
    CMR_KEYS.append('&sort_key[]=start_date')
    CMR_KEYS.append('&sort_key[]=producer_granule_id')
    CMR_KEYS.append('&scroll=true')
    CMR_KEYS.append(f'&page_size={cmr_page_size}')
    # append product string
    CMR_KEYS.append(f'&collection-concept-id={collection_concept_id}')
    CMR_KEYS.append(f'&producer-granule-id={producer_granule_id}')
    # append release strings
    CMR_KEYS.append(cmr_query_release(release))
    # full CMR query url
    cmr_query_url = "".join([posixpath.join(*CMR_HOST), *CMR_KEYS])
    logging.info(f'CMR request={cmr_query_url}')
    # output list of granule names and urls
    granule_urls = []
    cmr_scroll_id = None
    while True:
        req = urllib2.Request(cmr_query_url)
        if cmr_scroll_id:
            req.add_header('cmr-scroll-id', cmr_scroll_id)
        response = opener.open(req)
        # get scroll id for next iteration
        if not cmr_scroll_id:
            headers = {k.lower():v for k, v in dict(response.info()).items()}
            cmr_scroll_id = headers['cmr-scroll-id']
        # read the CMR search as JSON
        search_page = json.loads(response.read().decode('utf-8'))
        urls = cmr_filter_json(search_page, endpoint=endpoint)
        if not urls:
            break
        # extend lists
        granule_urls.extend(urls)
    # return the list of granule ids and urls
    return granule_urls

def download_resources(path: pathlib.Path = get_data_path('data')):
    """
    Query resources from the NASA Common Metadata Repository (CMR)
    and download them to a local path
    """
    # for each url in the CMR query
    for url in cmr():
        # split the url into parts and get the granule name
        *_, file = url_split(url)
        # full path to output local file
        local = path.joinpath(file)
        # check if existing and download if not
        if not local.exists():
            from_nsidc(url, local=local)

