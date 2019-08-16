import hmac
import hashlib
import log_utils
import base64
import urllib.request
import urllib.parse
import urllib.error
import json
import time

KEY_AUTH = 'block90'
GET_WALLET_INFO_BODY = bytes('{"method": "getwalletinfo", "params": [] }', encoding='utf-8')
EMPTY_BODY = bytes('', encoding='utf-8')
HOST = 'http://localhost:8000/'
HMAC_USERNAME = 'block90cred'
HMAC_SECRET = "zkYEGk5KIYfuWgZqCeU6146uctQQVtnc"
BASIC_AUTH = 'Basic dmlyY2xlOjk5OTAwMA=='

logger = log_utils.get_logger('wallet_rpc')


def call_rpc(url, headers, body, req_method='POST'):
    logger.debug('call rpc url: %s', url)
    req_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
                      ' snap Chromium/76.0.3809.87 Chrome/76.0.3809.87 Safari/537.36'
    }
    req_headers.update(headers)
    logger.debug('request headers: %s', json.dumps(req_headers, indent=2))
    request = urllib.request.Request(url, body, req_headers, method=req_method)
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


def hmac_sha256_base64_encode(secret, str_to_sign):
    # hmac_sha256加密
    signature = hmac.new(bytes(secret, encoding='utf-8'), bytes(str_to_sign, encoding='utf-8'),
                         digestmod=hashlib.sha256).digest()
    logger.debug('signature hex: %s', signature.hex())
    str_base64 = base64.b64encode(signature).decode()
    logger.debug('signature base64: %s', str_base64)
    return str_base64


def call_hmac_auth():
    logger.debug('--------------- with hmac-auth ---------------')
    headers = create_hmac_headers(GET_WALLET_INFO_BODY)
    # 调用rpc服务
    call_rpc(HOST + 'rpc', headers, GET_WALLET_INFO_BODY)


def create_hmac_headers(body):
    # 用sha256算法计算请求body的摘要
    body_digest = 'SHA-256={}'.format(base64.b64encode(hashlib.sha256(body).digest()).decode())
    logger.debug('body digest: %s', body_digest)
    # 生成当前GMT时间，注意格式不能改变，必须形如：Wed, 14 Aug 2019 09:09:28 GMT
    gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    # 拼装待签名的数据
    str_to_sign = "date: {}\ndigest: {}".format(gm_time, body_digest)
    # 生成签名
    signature = hmac_sha256_base64_encode(HMAC_SECRET, str_to_sign)
    logger.debug('to_sign: %s', str_to_sign)
    logger.debug('signature: %s', signature)
    # 拼装headers
    headers = {
        'Authorization': 'hmac username=\"{}\", algorithm=\"hmac-sha256\", headers=\"date digest\", '
                         'signature=\"{}\"'.format(HMAC_USERNAME, signature),
        'Digest': body_digest,
        'Date': gm_time}
    return headers


def call_no_auth():
    logger.debug('--------------- without auth ---------------')
    headers = {'Authorization': BASIC_AUTH}
    call_rpc(HOST + 'echo', headers, GET_WALLET_INFO_BODY)


def call_key_auth():
    logger.debug('--------------- with key-auth ---------------')
    headers = {'Authorization': BASIC_AUTH, 'apikey': KEY_AUTH}
    call_rpc(HOST + 'rpc', headers, GET_WALLET_INFO_BODY)


def call_pl_difficulty():
    logger.debug('--------------- pl get difficulty ---------------')
    headers = create_hmac_headers(EMPTY_BODY)
    call_rpc(HOST + 'pl/api/getdifficulty', headers, EMPTY_BODY, 'GET')


if __name__ == "__main__":
    # call_no_auth()
    # call_key_auth()
    call_hmac_auth()
    call_pl_difficulty()
