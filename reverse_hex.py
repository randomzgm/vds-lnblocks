#!/usr/bin/python
import getopt
import sys


def main(argv):
    input_str = ''
    split_str = ''
    try:
        opts, args = getopt.getopt(argv, "hx:s:", ["hexstring=", "separator="])
    except getopt.GetoptError:
        missing_arg()
    if len(opts) < 1:
        missing_arg()
    for opt, arg in opts:
        if opt == '-h':
            missing_arg()
        elif opt == "-x":
            input_str = arg
        elif opt == "-s":
            split_str = arg
    input_str = input_str.replace(' ', '')
    print('The input string is:\t', input_str)
    input_str = input_str[:round(len(input_str) / 2) * 2]
    print('To reverse string is:\t', input_str)
    print("The reversed string is:\t", reverse(input_str, split_str))


def reverse(input_str, split_str=''):
    list_input = []
    for i in range(0, round(len(input_str) / 2)):
        list_input.append(split_str + input_str[i * 2: (i + 1) * 2])
    list_input.reverse()
    return "".join(list_input)


def missing_arg():
    print('usage: reverse_hex.py -x <hexstring> [-s <separator>]')
    sys.exit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
