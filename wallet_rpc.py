import hmac
import hashlib
import log_utils
import base64
import urllib.request
import urllib.parse
import json
import time

GET_WALLET_INFO_BODY = bytes('{"method": "getwalletinfo", "params": [] }', encoding='utf-8')

logger = log_utils.get_logger('wallet_rpc')
HOST = 'http://localhost/'


def hmac_sha256_base64_encode(app_key, str_to_sign):
    # hmac_sha256加密
    signature = hmac.new(bytes(app_key, encoding='utf-8'), bytes(str_to_sign, encoding='utf-8'),
                         digestmod=hashlib.sha256).digest()
    logger.debug('signature hex: %s', signature.hex())
    str_base64 = base64.b64encode(signature).decode()
    logger.debug('signature base64: %s', str_base64)
    return str_base64


def call_rpc(url, headers, body):
    logger.debug('call rpc url: %s', url)
    req_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
                      ' snap Chromium/76.0.3809.87 Chrome/76.0.3809.87 Safari/537.36'
    }
    req_headers.update(headers)
    logger.debug('request headers: %s', json.dumps(req_headers, indent=2))
    request = urllib.request.Request(url, body, req_headers)
    try:
        # 访问
        with urllib.request.urlopen(request) as response:
            html = response.read().decode('utf-8')
            # 利用json解析包解析返回的json数据 拿到翻译结果
            logger.info('response = %s', json.dumps(json.loads(html), indent=2))
    except urllib.error.HTTPError as err:
        logger.error('response error: %s', err)
        logger.error('response headers: %s', err.headers)
        err_html = err.read().decode('utf-8')
        if err_html:
            logger.error('response = %s', json.dumps(json.loads(err_html), indent=2))


def call_no_auth():
    logger.debug('--------------- without auth ---------------')
    headers = {'Authorization': 'Basic cmFuZG9tOmJsb2Nr'}
    call_rpc(HOST + 'rpcnokey', headers, GET_WALLET_INFO_BODY)


def call_key_auth():
    logger.debug('--------------- with key-auth ---------------')
    headers = {'Authorization': 'Basic cmFuZG9tOmJsb2Nr', 'apikey': 'block90'}
    call_rpc(HOST + 'rpc', headers, GET_WALLET_INFO_BODY)


def call_hmac_auth():
    logger.debug('--------------- with hmac-auth ---------------')
    app_key = "secret"
    body_digest = 'SHA-256={}'.format(base64.b64encode(hashlib.sha256(GET_WALLET_INFO_BODY).digest()).decode())
    logger.debug('body digest: %s', body_digest)
    gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    str_to_sign = "date: {}\ndigest: {}".format(gm_time, body_digest)
    signature = hmac_sha256_base64_encode(app_key, str_to_sign)
    logger.debug('to_sign: %s', str_to_sign)
    logger.debug('signature: %s', signature)

    headers = {
        'Authorization': 'hmac username=\"alice123\", algorithm=\"hmac-sha256\", headers=\"date digest\", '
                         'signature=\"{}\"'.format(signature),
        'Digest': body_digest,
        'Date': gm_time}
    call_rpc(HOST + 'rpchmac', headers, GET_WALLET_INFO_BODY)


if __name__ == "__main__":
    call_no_auth()
    call_key_auth()
    call_hmac_auth()
