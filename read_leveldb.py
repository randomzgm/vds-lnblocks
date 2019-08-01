#!/usr/bin/python
import getopt
import sys
import leveldb
import reverse_hex
import json
import read_file
import binascii
import hashlib
import address_utils
import block_error
import log_utils
import logging

logger = log_utils.get_logger('read_leveldb')


def main(argv):
    path_str = ''
    hash_str = ''
    vid_str = ''
    operation = ''
    try:
        opts, args = getopt.getopt(argv, "hp:a:l:v:o:")
    except getopt.GetoptError:
        missing_arg()
    if len(opts) < 1:
        missing_arg()
    for opt, arg in opts:
        if opt == '-h':
            missing_arg()
        elif opt == "-p":
            path_str = arg
        elif opt == "-a":
            hash_str = arg
        elif opt == "-l":
            try:
                logger.setLevel(arg.upper())
            except (TypeError, ValueError) as err:
                logger.setLevel(logging.INFO)
                logger.error('log level restore to INFO, because %s', err)
        elif opt == "-v":
            vid_str = arg
        elif opt == "-o":
            operation = arg
    logger.info('The block path is: %s', path_str)
    db = leveldb.LevelDB(path_str + '/index')
    if hash_str:
        logger.info('the light node block hash: %s', hash_str)
        key = 'b'.encode() + binascii.a2b_hex(reverse_hex.reverse(hash_str))
        value = db.Get(key)
        resolve_put(key, value, path_str, db)
    elif vid_str:
        logger.info('the vid address: %s', vid_str)
        height_list = []
        for key, value in db.RangeIter():
            if key[:1].decode() == 'V' and key.decode().startswith(vid_str + ':'):
                height_list.append(key.decode().split(':')[1])
                resolve(key, value, path_str)
        logger.info('the height list of address: {}, total: {}'.format(height_list, len(height_list)))
    elif operation.lower() == 'delete':
        delete_count = 0
        for key in db.RangeIter(include_value=False):
            if key[:1].decode() == 'V' and key.decode().find(':') < 0:
                db.Delete(key)
                delete_count += 1
        logger.info('delete keys count: {}'.format(delete_count))
    elif operation.lower() == 'stat':
        stat = {}
        stat_count = 0
        for key in db.RangeIter(include_value=False):
            if key[:1].decode() == 'V' and key.decode().find(':') >= 0:
                stat_count += 1
                vid = key.decode().split(':')[0]
                if vid in stat:
                    stat[vid] += 1
                else:
                    stat.setdefault(vid, 1)
        logger.info('stat vids: {}'.format(json.dumps(stat, indent=2)))
        logger.info('stat keys count: {}, total count: {}'.format(len(stat), stat_count))
    else:
        i = 0
        for key, value in db.RangeIter():
            # if key[:1].decode() == 'L' and key.hex().find('34fb') > 0:
            #     print('key =', key.hex())
            #     print('value =', value.hex())

            # 以字母b开头的key是区块索引
            if key[:1].decode() == 'b':
                resolve_put(key, value, path_str, db)
                i += 1
            if i > 1000000:
                break


def resolve(key, value, path_str):
    filename, offset, height = resolve_index(key, value)
    address = resolve_disk(path_str + filename, offset)
    return '{}:{}'.format(address, height)


def resolve_put(key, value, path_str, db):
    try:
        address = resolve(key, value, path_str)
        db.Put(address.encode(), value)
        logger.info('put address: %s', address)
    except block_error.BlockError as err:
        logger.error('block error: %s', err)


def resolve_index(key, value):
    logger.info('db index key = %s', key.hex())
    logger.debug('db index value = %s', value.hex())

    # block_header_hex = '040000000000000000000000000000000000000000000000000000000000000000000000' \
    #                    '33d16124a9524768748626420167fee9c4094f3c1200b14db4a5eb4862a68e89fbc2f430' \
    #                    '0c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493ef56596133a0e1900' \
    #                    'acdf375cffff0720e965ffd002cd6ad0e2dc402b8044de833e06b23127ea8c3d80aec914' \
    #                    '1077149556e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421' \
    #                    'c1000000000000000000000000000000000000000000000000000000000000004408bc97' \
    #                    '67284a389bf0db4ff042d3c18c7d398b9dede5781b75f4a5deec7d51ad92301ae2c96f9e' \
    #                    '7f3671f3d4cf1b519f88eeab1d31d1c98c82f09fab020e0cdf4ffbb305 '
    # output = hashlib.sha256(hashlib.sha256(binascii.a2b_hex(block_header_hex)).digest()).hexdigest()
    # print('computed block hash =', output)

    block = {}
    block_origin = {}

    value = wrap_var_int(value, block_origin, block, 'height')
    value = wrap_var_int(value, block_origin, block, 'unknown1')
    unknown1_field = block_origin.get('unknown1')
    if unknown1_field != '0d':
        raise block_error.BlockError(
            'the unknown1 field value: {0} is unknown, we expect 0d'.format(unknown1_field))
    value = wrap_var_int(value, block_origin, block, 'nodes')
    value = wrap_var_int(value, block_origin, block, 'file')
    value = wrap_var_int(value, block_origin, block, 'offset')

    value = wrap_fix_char(value, block_origin, block, 'hash', 32)
    value = wrap_fix_char(value, block_origin, block, 'block_hash', 32)
    value = wrap_fix_char(value, block_origin, block, 'prelnblock_hash', 32)
    value = wrap_fix_char(value, block_origin, block, 'merkleroot', 32)
    value = wrap_fix_char(value, block_origin, block, 'time', 4)
    value = wrap_fix_char(value, block_origin, block, 'unknown3', 6)
    value = wrap_fix_char(value, block_origin, block, 'unknown4', 4)
    value = wrap_fix_char(value, block_origin, block, 'address', 20)
    wrap_fix_char(value, block_origin, block, 'unknown6', 2)

    filename = 'blk{:05}.dat'.format(block.get('file'))
    block['file'] = filename
    offset = block.get('offset')
    block['offset'] = '{:X}'.format(offset)
    block['time'] = int(block.get('time'), 16)
    block['address'] = address_utils.base58_encode('101c', binascii.a2b_hex(block_origin.get('address')), False)

    logger.debug('=========== db origin info ===========')
    logger.debug('db_origin = {}'.format(json.dumps(block_origin, indent=2)))
    logger.info('=========== light node block info in db ===========')
    logger.info('db block = {}'.format(json.dumps(block, indent=2)))

    ln_block_header_str = block_origin.get('block_hash') + block_origin.get('prelnblock_hash') + block_origin.get(
        'merkleroot') + block_origin.get('time') + block_origin.get('unknown3') + block_origin.get(
        'unknown4') + block_origin.get('address') + block_origin.get('unknown6')
    logger.debug('input for light node block hash = %s', ln_block_header_str)
    logger.debug('computed light node block hash = %s',
                 hashlib.sha256(hashlib.sha256(binascii.a2b_hex(ln_block_header_str)).digest()).hexdigest())

    return filename, offset, block.get('height')


def resolve_disk(filename, offset):
    file = None
    block = {}
    block_origin = {}
    try:
        file = read_file.ReadFile(filename, offset)
        read_file_hash(file, block_origin, block, 'block_hash', 32)
        read_file_hash(file, block_origin, block, 'preblock_hash', 32)
        read_file_hash(file, block_origin, block, 'merkleroot', 32)
        read_file_int(file, block_origin, block, 'time')
        read_file_string(file, block_origin, block, 'unknown1', 6)
        read_file_string(file, block_origin, block, 'unknown2', 4)
        read_file_string(file, block_origin, block, 'address', 20)
        read_file_string(file, block_origin, block, 'unknown4', 2)

        block['address'] = address_utils.base58_encode('101c', binascii.a2b_hex(block_origin.get('address')), False)
        # the above is light node block header
        read_file_compact_size(file, block_origin, block, 'nodes')
        resolve_nodes(file, block_origin, block, 'light_nodes')
        read_file_string(file, block_origin, block, 'unknown6', 8)
        logger.debug('=========== file origin info ===========')
        logger.debug('disk_origin = {}'.format(json.dumps(block_origin, indent=2)))
        logger.debug('=========== light node block info in file ===========')
        logger.debug('disk block = {}'.format(json.dumps(block, indent=2)))

        return block.get('light_nodes')[0].get('address')
    finally:
        if file:
            file.close()


def resolve_nodes(file, block_origin, block, field):
    nodes_count = block.get('nodes')
    nodes_list = []
    nodes_origin_list = []
    for i in range(nodes_count):
        node_block = {}
        node_block_origin = {}
        read_file_compact_size(file, node_block_origin, node_block, 'pubkey_len')
        read_file_string(file, node_block_origin, node_block, 'pubkey', node_block.get('pubkey_len'))
        read_file_hash(file, node_block_origin, node_block, 'block_hash', 32)
        read_file_compact_size(file, node_block_origin, node_block, 'sig_len')
        read_file_string(file, node_block_origin, node_block, 'sig', node_block.get('sig_len'))
        read_file_compact_size(file, node_block_origin, node_block, 'script_len')
        read_file_string(file, node_block_origin, node_block, 'script', node_block.get('script_len'))
        read_file_hash(file, node_block_origin, node_block, 'txid', 32)
        read_file_string(file, node_block_origin, node_block, 'unknown5', 4)

        node_block.setdefault('address',
                              address_utils.base58_encode('101c', binascii.a2b_hex(node_block.get('script'))[3:23],
                                                          False))

        nodes_list.append(node_block)
        nodes_origin_list.append(node_block_origin)
    block.setdefault(field, nodes_list)
    block_origin.setdefault(field, nodes_origin_list)


def read_file_compact_size(file, block_origin, block, field):
    result_int, origin_bytes = file.read_compact_size()
    block.setdefault(field, result_int)
    block_origin.setdefault(field, origin_bytes.hex())


def read_file_string(file, block_origin, block, field, length):
    bs = file.read(length).hex()
    block.setdefault(field, bs)
    block_origin.setdefault(field, bs)


def read_file_int(file, block_origin, block, field):
    result_int, origin_bytes = file.read_int(4)
    block.setdefault(field, result_int)
    block_origin.setdefault(field, origin_bytes.hex())


def read_file_hash(file, block_origin, block, field, length):
    hash_bytes, origin_bytes = file.read_hash(length)
    block.setdefault(field, hash_bytes.hex())
    block_origin.setdefault(field, origin_bytes.hex())


def wrap_fix_char(bytes_array, block_origin, block, field, length):
    block_origin.setdefault(field, bytes_array[:length].hex())
    block.setdefault(field, reverse_hex.reverse(bytes_array[:length].hex()))
    return bytes_array[length:]


def wrap_var_int(bytes_array, block_origin, block, field):
    int_value, index = read_var_int(bytes_array)
    block_origin.setdefault(field, bytes_array[:index].hex())
    block.setdefault(field, int_value)
    return bytes_array[index:]


def read_var_int(bytes_array):
    n = 0
    i = 0
    while True:
        ch = bytes_array[i]
        i += 1
        n = (n << 7) | (ch & 0x7F)
        if ch & 0x80:
            n += 1
        else:
            return n, i


def missing_arg():
    print('usage: read_leveldb.py -p <path> [-l <log>] [-a <hash>|-v <vid>] [-o delete|stat]')
    sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
