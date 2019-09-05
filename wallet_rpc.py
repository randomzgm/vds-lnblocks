import hmac
import hashlib
import locale

import log_utils
import base64
import urllib.request
import urllib.parse
import urllib.error
import json
import time

KEY_AUTH = 'block90'
GET_WALLET_INFO_BODY = bytes('{"method": "getwalletinfo", "params": [] }', encoding='utf-8')
SMS_INFO_BODY = bytes('{"companyAddress": "广州市黄埔区护林路1198号6楼618",  "contactName": "刘强星",  '
                      '"contactTel": "1760000716",  "custName": "广州久零区块链",  "custShortName": "广州久零"}', encoding='utf-8')
EMPTY_BODY = bytes('', encoding='utf-8')
DATE_FIELD = 'x-date'
ENV_SYSTEM = 'production'
HOST = 'http://localhost:8000/'
HMAC_USERNAME = 'block90cred'
HMAC_SECRET = "zkYEGk5KIYfuWgZqCeU6146uctQQVtnc"
BASIC_AUTH = 'Basic dmlyY2xlOjk5OTAwMA=='

if ENV_SYSTEM == 'production':
    HOST = 'https://open.vpubchain.info/'
    HMAC_USERNAME = 'HPN0K2UE'
    HMAC_SECRET = "UBXozODI4Pwt1S6XAzRBXkh2JFnmSHqB"
    # HMAC_SECRET = "rg7mu5mhMlNBZfchfgBQZ0Miki32Sl4i"

if ENV_SYSTEM == 'test':
    HOST = 'http://192.168.0.142:8000/'
    # HMAC_SECRET = "zkYEGk5KIYfuWgZqCeU6146uctQQVtnc"

logger = log_utils.get_logger('wallet_rpc')


def call(url, username, secret, body, method='POST'):
    headers = {}
    byteBody = bytes(body, encoding='utf-8')
    if username and secret:
        headers = create_hmac_headers(byteBody)
    call_rpc(url, headers, byteBody, method)


def call_rpc(url, headers, body, req_method='POST'):
    logger.debug('call rpc url: %s by %s', url, req_method)
    req_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)'
                      ' snap PyCharm 2019.2 (Community Edition) Build #PC-192.5728.105, built on July 24, 2019'
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
            try:
                logger.error('response = %s', json.dumps(json.loads(err_html), indent=2))
            except json.decoder.JSONDecodeError:
                logger.error('response = %s', err_html)


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
    # 不同调用方的locale可能不一样，最稳妥的做法是获取时间前设置英文locale，然后还原
    time_locale = locale.setlocale(locale.LC_TIME)
    locale.setlocale(locale.LC_TIME, 'en_US.UTF-8')
    gm_time = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    locale.setlocale(locale.LC_TIME, time_locale)
    # gm_time = 'Tue, 03 Sep 2019 06:54:29 GMT'
    # 拼装待签名的数据
    str_to_sign = "{}: {}\ndigest: {}".format(DATE_FIELD, gm_time, body_digest)
    # 生成签名
    signature = hmac_sha256_base64_encode(HMAC_SECRET, str_to_sign)
    logger.debug('to_sign: %s', str_to_sign)
    logger.debug('signature: %s', signature)
    # 拼装headers
    headers = {
        'Authorization': 'hmac username=\"{}\", algorithm=\"hmac-sha256\", headers=\"{} digest\", '
                         'signature=\"{}\"'.format(HMAC_USERNAME, DATE_FIELD, signature),
        'Digest': body_digest,
        DATE_FIELD: gm_time}
    return headers


def call_no_auth():
    logger.debug('--------------- rpc without auth ---------------')
    headers = {'Authorization': BASIC_AUTH}
    call_rpc(HOST + 'rpc', headers, GET_WALLET_INFO_BODY)


def call_key_auth():
    logger.debug('--------------- rpc with key-auth ---------------')
    headers = {'Authorization': BASIC_AUTH, 'apikey': KEY_AUTH}
    call_rpc(HOST + 'rpc', headers, GET_WALLET_INFO_BODY)


def call_pl_difficulty():
    logger.debug('--------------- pl get difficulty ---------------')
    headers = {}
    call_rpc(HOST + 'ben-pl/api/getdifficulty', headers, EMPTY_BODY, 'GET')


def call_user_test():
    logger.debug('--------------- user test ---------------')
    headers = create_hmac_headers(EMPTY_BODY)
    call_rpc(HOST + 'user/user/test', headers, EMPTY_BODY)


def call_sms_test():
    logger.debug('--------------- sms user register test ---------------')
    headers = create_hmac_headers(EMPTY_BODY)
    headers['Content-Type'] = 'application/form-data;charset=UTF-8'
    call_rpc(HOST + 'sms/user/regist?phone=15197287813', headers, EMPTY_BODY)


def call_sms_production():
    logger.debug('--------------- sms user register production ---------------')
    headers = create_hmac_headers(EMPTY_BODY)
    headers['Content-Type'] = 'application/form-data;charset=UTF-8'
    call_rpc(HOST + 'sms/user/register?phone=15197287884', headers, EMPTY_BODY)


def call_sms_customer_create():
    logger.debug('--------------- sms customer create test ---------------')
    headers = create_hmac_headers(SMS_INFO_BODY)
    call_rpc(HOST + 'sms/customer/create', headers, SMS_INFO_BODY)


def call_nodes_get_node():
    logger.debug('--------------- sms customer create test ---------------')
    headers = create_hmac_headers(SMS_INFO_BODY)
    headers['userToken'] = '33d5541c9a66a007b113cd760f2b6f37'
    call_rpc(HOST + 'nodes/nodes/getUserNode', headers, EMPTY_BODY, 'GET')


if __name__ == "__main__":
    # call_no_auth()
    # call_key_auth()
    # call_hmac_auth()
    # call_user_test()
    call_pl_difficulty()
    # call_sms_test()
    call_sms_production()
    # call_sms_customer_create()
    # call_nodes_get_node()
