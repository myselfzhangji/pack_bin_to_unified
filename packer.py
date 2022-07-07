#!/usr/bin/env python3
"""
*******************************************************************************
packer.py

Key Features:
    * Pack nn model of all groups into unified NN bin
    * Add header info for the unified NN bin.

History:
    2022/04/13 - [Zhang Ji]
******************************************************************************
"""

import sys, os, yaml, string, shutil
import argparse
import logging
from ctypes import *
from zlib import crc32

# define AMBA AISP Packer Version.
AMBA_AISP_PACKER_VER_MAJOR = 0
AMBA_AISP_PACKER_VER_MINOR = 0
AMBA_AISP_PACKER_VER_PATCH = 1

## the following class should be strictly aligned with the structure "struct aisp_binary_header_info" in C header file

NN_MODEL_VERSION_MAX_LENGTH = 16
NN_MODEL_SENSOR_NAME_MAX_LENGTH = 32
NN_MODEL_GROUP_NUM = 10
NN_MODEL_GROUP_ITEMS = 7
AMBA_AISP_CERT_SIZE = 256

class iav_window(Structure):
    _fields_ = [('width', c_uint), ('height', c_uint)]

class nn_group_items(Structure):
    _fields_ = [('window', iav_window), ('offset', c_uint), ('size', c_uint)]

class gain_range(Structure):
    _fields_ = [('low', c_char), ('high', c_char), ('reserved', c_char * 2)]

class nn_group_info(Structure):
    _fields_ = [('_range', gain_range), ('items', nn_group_items * NN_MODEL_GROUP_ITEMS)]

## amba_aisp_header_info totally 2048 bytes, the same as "struct aisp_binary_header_info" in C header file
class aisp_header_info(Structure):
    _fields_ = [('magic', c_uint), ('header_size', c_uint), ('total_size', c_uint),
                ('version', c_char * NN_MODEL_VERSION_MAX_LENGTH), ('crc32', c_uint),
                ('sensor_name', c_char * NN_MODEL_SENSOR_NAME_MAX_LENGTH), ('img_input', iav_window),
                ('amba_cert', c_byte * AMBA_AISP_CERT_SIZE), ('is_plain', c_char), ('grp_num', c_char),
                ('md_items', c_char), ('c2y_items', c_char), ('reserved0', c_char * 60),
                ('grp_info', nn_group_info * NN_MODEL_GROUP_NUM), ('reserved1', c_char * 496)]

# define usage
def set_parsers():
    parser = argparse.ArgumentParser(
        prog='PROG', formatter_class=argparse.RawDescriptionHelpFormatter,)
    parser.description = 'Description: 1. pack NN models of all groups into a unified bin; 2. Add extra header info for the unified bin.'
    parser.add_argument("-f", "--file", metavar='NN models description',
                        help='specify group NN models description yaml, including NN models name, dgain range, ...', type=str)
    parser.add_argument("-c", "--cert", metavar='ambarella cert bin file',
                        help='specify ambarella cert bin file', type=str)
    parser.add_argument("-o", "--output", metavar='packed bin file name',
                        help='the output packed bin file name', type=str)
    parser.add_argument("-b", "--bin", metavar='the unified NN bin',
                        help='specify the unified NN bin to do unpack', type=str)
    parser.add_argument("-u", "--unpack", help='unpack the unified NN bin to separated bins', action="store_true")
    parser.epilog = ('''
                    version : %d.%d.%d;
                    example:
                    1. AISP amba packer tool : pack NN model bins into unified amaba_aisp.bin:
                        ./amba_aisp_packer.py -f amba_aisp_model_info.yaml -c amba_aisp_cvflow.cert -o imx327_rgb_linear_1920x1080_aisp_nn.bin
                    2. AISP amba packer tool : unpack the unified NN bin to separated bins:
                        ./amba_aisp_packer.py -u -b amba_aisp.bin
                    ''' %(AMBA_AISP_PACKER_VER_MAJOR, AMBA_AISP_PACKER_VER_MINOR, AMBA_AISP_PACKER_VER_PATCH))

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_known_args(sys.argv[1:])[0]

    return args.file, args.cert, args.output, args.bin, args.unpack

#pack all the NN model bin without header
def pack_raw(config_info):
    raw_bin = './raw_tmp.bin'
    print('Start to generate %s, which is packed by all raw NN model bin' %(raw_bin))
    if os.path.exists(raw_bin):
        os.remove(raw_bin)

    newbinfile = open(raw_bin, 'ab+')

    global_info = config_info.get('global_info')

    # get group num
    group_num = int(global_info.get('group_num'))

    # get group item num
    md_item = int(global_info.get('md_item'))
    c2y_item = int(global_info.get('c2y_item'))
    group_item_num = md_item + c2y_item

    if (group_num == 0 or group_num > NN_MODEL_GROUP_NUM or
        group_item_num == 0 or group_item_num > NN_MODEL_GROUP_ITEMS):
        logging.error("Invalid group num(%d), or group_item_num(%d)!" %(group_num, group_item_num))
        sys.exit(1)

    for i in range(group_num):
        grp = 'nn_group' + str(i)
        model_grp = config_info.get(grp)
        items = ['md', 'c2y_r', 'c2y_l']
        for j in range(group_item_num):
            items_info = model_grp.get(items[j])
            filepath = items_info.get('file')
            binfile = open(filepath, 'rb')
            size = os.path.getsize(filepath)
            if size == 0:
                logging.error("%s file is empty!" %(filepath))
                sys.exit(1)
            for k in range(size):
                data = binfile.read(1)
                newbinfile.write(data)
            binfile.close()

    newbinfile.close()

    return raw_bin

def compute_crc32(file_name):
    f = open(file_name, 'rb')
    crc_32 = crc32(f.read())
    f.close()

    return crc_32

# Start from offset : 'sensosr_name' to calculate crc32 for aisp bin, so here use
# header.bin and raw.bin to generate a tmp thin_unified.bin file
def gen_aisp_crc32(header_offset, header_bin, raw_output):
    bins = [header_bin, raw_output]
    bins_offset = [header_offset, 0]
    thin_unified_bin = './thin_unified.bin'
    if os.path.exists(thin_unified_bin):
        os.remove(thin_unified_bin)

    thin_unified_binfile = open(thin_unified_bin, 'ab+')

    # generate a bin file with heaer.bin (offset : header_offset) and raw_tmp.bin
    for i in range(len(bins)):
        #print(bins[i])
        binfile = open(bins[i], 'rb')
        size = os.path.getsize(bins[i])
        offset = bins_offset[i]
        binfile.seek(offset, 0)
        for j in range(offset, size):
            data = binfile.read(1)
            thin_unified_binfile.write(data)
        binfile.close()
        #print('remove temp file :', bins[i])
        #os.remove(bins[i])

    thin_unified_binfile.close()

    crc_32 = compute_crc32(thin_unified_bin)

    print('Remove %s file, which is used to generate crc32' %(thin_unified_bin))
    os.remove(thin_unified_bin)

    return crc_32

# write header info into a temp header.bin
def write_to_header_bin(h_info, header_file_name):
    if os.path.exists(header_file_name):
        os.remove(header_file_name)

    if 0:
        print('Python call c lib to write header info into file following certain structure')
        parse = cdll.LoadLibrary('./lib_nn_model_parse.so')
        parse.gen_unified_binary_header_file.restype = c_int
        ret = parse.gen_unified_binary_header_file(pointer(h_info))
        #print(type(ret))
        #print(ret)
    else:
        print('Python write header info into file following certain structure')
        with open (header_file_name,'ab+') as file_object:
            file_object.write(h_info)

    return

def gen_header_info(config_info, cert_bin, raw_output):
    header_file_name = './header.bin'
    print('Start to generate %s, which is used to store all header info' %(header_file_name))

    global_info = config_info.get('global_info')

    magic_number = 0x41495350 # the ascii of 'AISP', 0x41 : 'A'; 0x49 : 'I'; 0x53 : 'S'; 0x50 : 'P'

    # get version
    version = global_info.get('version')
    version = version.encode('UTF-8')
    '''
    create buffer that will pass version string to c function
    version_str = create_string_buffer(version).value
    '''

    # get sensor name
    sensor = global_info.get('sensor')
    sensor = sensor.encode('UTF-8')
    #print(sensor)
    #print(type(sensor))

    # get NN model image input resolution
    resolution = global_info.get('img_resolution')
    res_w = int(resolution.split('x')[0])
    res_h = int(resolution.split('x')[1])
    '''
    print(res_w)
    print(type(res_w))
    '''

    # get amba certication
    f_cert_bin = open(cert_bin, 'rb')
    size = os.path.getsize(cert_bin)
    if size == 0:
        logging.error("%s file is empty!" %(f_cert_bin))
        sys.exit(1)
    cert = f_cert_bin.read()
    #print(len(cert))
    #print(cert)
    f_cert_bin.close()

    # get NN model type: is plain NN models or encrypted NN models
    is_plain_model = int(global_info.get('is_plain_model'))

    # get group num
    group_num = int(global_info.get('group_num'))

    # get group item num
    md_item = int(global_info.get('md_item'))
    c2y_item = int(global_info.get('c2y_item'))
    group_item_num = md_item + c2y_item

    if group_num == 0 or group_item_num == 0:
        logging.error("Invalid group num(%d), or group_item_num(%d)!" %(group_num, group_item_num))
        sys.exit(1)

    # get group db gain range low / high limit, and each model item info, including offset, size, ...
    NNGroupsArray_10 = nn_group_info * 10
    groups_info = NNGroupsArray_10()
    #print(groups_info[0], groups_info[0].window)
    offset = sizeof(aisp_header_info)
    total_size = offset
    for i in range(group_num):
        grp = 'nn_group' + str(i)
        model_grp = config_info.get(grp)
        gain_range = model_grp.get('gain_range')
        #print(gain_range)
        #print(type(gain_range))
        groups_info[i]._range.low = int(gain_range.split('_')[0])
        groups_info[i]._range.high = int(gain_range.split('_')[1])
        items = ['md', 'c2y_r', 'c2y_l']
        for j in range(group_item_num):
            items_info = model_grp.get(items[j])
            filepath = items_info.get('file')
            size = os.path.getsize(filepath) #获得文件大小
            if size == 0:
                logging.error("%s file is empty!" %(filepath))
                sys.exit(1)
            groups_info[i].items[j].offset = offset
            groups_info[i].items[j].size = size
            offset = offset + size
            total_size = total_size + size

            input_res = items_info.get('input_resolution')
            input_res_w = int(input_res.split('x')[0])
            input_res_h = int(input_res.split('x')[1])
            groups_info[i].items[j].window.width = input_res_w
            groups_info[i].items[j].window.height = input_res_h

    '''
    print(aisp_header_info.sensor_name.offset)
    print(aisp_header_info.magic)
    '''
    ## h_info structure should be strictly same as "struct aisp_binary_header_info" in C header
    h_info = aisp_header_info(magic = magic_number, header_size = sizeof(aisp_header_info),
        total_size = total_size, version = version, sensor_name = sensor, img_input = (res_w, res_h),
        is_plain = is_plain_model, grp_num = group_num,
        md_items = md_item, c2y_items = c2y_item, grp_info = groups_info)

    for i in range(len(cert)):
        h_info.amba_cert[i] = cert[i]
    #print(sizeof(h_info))
    #print(sizeof(aisp_header_info))

    # at this stage, crc32 is not generated yet, write header info except crc32 to header.bin
    write_to_header_bin(h_info, header_file_name)

    # Start from offset : 'sensosr_name' to generate crc32 for the unified bin
    header_offset = aisp_header_info.sensor_name.offset
    crc_32 = gen_aisp_crc32(header_offset, header_file_name, raw_output)

    '''
    print(type(crc_32))
    print('%x' %(crc_32))
    #print(len(crc_32))
    '''

    h_info.crc32 = crc_32

    # at this stage, crc32 is generated, write header info including crc32 to header.bin
    write_to_header_bin(h_info, header_file_name)

    return header_file_name

#generate packed NN bin with header.bin and raw_tmp.bin
def gen_packed_bin(header_bin, raw_output, output_file):
    bins = [header_bin, raw_output]
    if os.path.exists(output_file):
        os.remove(output_file)

    packed_bin_file = open(output_file, 'ab+')
    for i in range(len(bins)):
        #print(bins[i])
        binfile = open(bins[i], 'rb')
        size = os.path.getsize(bins[i])
        if size == 0:
            logging.error("%s file is empty!" %(bins[i]))
            sys.exit(1)
        for j in range(size):
            data = binfile.read(1)
            packed_bin_file.write(data)
        binfile.close()
        print('Remove temp file :', bins[i])
        os.remove(bins[i])

    packed_bin_file.close()
    print('Generate packed NN bin : %s done, which includes header info and all NN model' %(output_file))

    return

def unpack_bin(unified_bin):
    binfile = open(unified_bin, 'rb')
    size = os.path.getsize(unified_bin)
    if size == 0:
        logging.error("%s file is empty!" %(unified_bin))
        sys.exit(1)

    h_info = aisp_header_info()
    header_size = sizeof(aisp_header_info)

    while binfile.readinto(h_info) == header_size:
        break

    magic = h_info.magic
    if (chr((magic >> 24) & 0xFF) != 'A' or chr((magic >> 16) & 0xFF) != 'I' or
        chr((magic >> 8) & 0xFF) != 'S' or chr(magic & 0xFF) != 'P'):
        logging.error("It's not ambarella AISP bin[%c%c%c%c]!" %((magic >> 24) & 0xFF,
            (magic >> 16) & 0xFF, (magic >> 8) & 0xFF, magic & 0xFF))
        sys.exit(1)

    if (h_info.header_size != header_size):
        logging.error("Invalid header size [%d], should be [%d]!" %(h_info.header_size,
            header_size))
        sys.exit(1)

    if (h_info.total_size <= h_info.header_size):
        logging.error("No valid NN model in unified NN bin!")
        sys.exit(1)

    if (h_info.total_size != size):
        logging.error("Invalid total size [%d], should be [%d]!" %(h_info.total_size, size))
        sys.exit(1)

    offset = aisp_header_info.sensor_name.offset
    #print(offset)
    binfile.seek(offset, 0)
    tmp_crc32 = './tmp_crc32.bin'
    if os.path.exists(tmp_crc32):
        os.remove(tmp_crc32)

    f_crc32 = open(tmp_crc32, 'ab+')
    for i in range(offset, size):
        data = binfile.read(1)
        f_crc32.write(data)
    binfile.close()
    f_crc32.close()

    crc_32 = compute_crc32(tmp_crc32)
    if (h_info.crc32 != crc_32):
        logging.error("crc32 is wrong, src[%s], dst[%s]!" %(h_info.crc32, crc_32))
        sys.exit(1)
    os.remove(tmp_crc32)

    grp_num = int.from_bytes(h_info.grp_num, 'little')
    md_items = int.from_bytes(h_info.md_items, 'little')
    c2y_items = int.from_bytes(h_info.c2y_items, 'little')
    grp_items = md_items + c2y_items
    if (grp_num == 0 or grp_num > NN_MODEL_GROUP_NUM or
        grp_items == 0 or grp_items > NN_MODEL_GROUP_ITEMS):
        logging.error("Invalid group num(%d), or group_item_num(%d)!" %(grp_num, grp_items))
        sys.exit(1)

    #print(grp_num, grp_items)
    items = ['md', 'c2y_r', 'c2y_l']
    separated_path = './separated'

    if os.path.exists(separated_path):
        shutil.rmtree(separated_path)

    os.mkdir(separated_path)

    binfile = open(unified_bin, 'rb')

    model_name = (separated_path + '/' + 'license_cert.bin')
    cert_file = open(model_name, 'ab+')
    offset = aisp_header_info.amba_cert.offset
    binfile.seek(offset, 0)
    for i in range(AMBA_AISP_CERT_SIZE):
        data = binfile.read(1)
        cert_file.write(data)
    cert_file.close()
    print('Generate amba cert (%s) from %s' %(model_name, unified_bin))

    for i in range(grp_num):
        low = int.from_bytes(h_info.grp_info[i]._range.low, 'little')
        high = int.from_bytes(h_info.grp_info[i]._range.high, 'little')
        for j in range(grp_items):
            model_name = (separated_path + '/' + 'aisp_group_' + str(i) + '_' +
                items[j] + '_' + str(low) + '_' + str(high) + '.bin')
            model_file = open(model_name, 'ab+')

            offset = h_info.grp_info[i].items[j].offset
            size = h_info.grp_info[i].items[j].size
            if (offset + size > h_info.total_size) :
                logging.error("No valid NN model in unified NN bin!")
                sys.exit(1)

            binfile.seek(offset, 0)
            for k in range(size):
                data = binfile.read(1)
                model_file.write(data)
            model_file.close()
            print('Generate separated model (%s) from %s' %(model_name, unified_bin))

    binfile.close()

    return

if __name__ == '__main__':
    nn_model_info, cert_bin, output_file, unified_bin, unpack = set_parsers()

    if unpack == 0:
        if (nn_model_info == None):
            logging.error('Please specify nn model description yaml first!')
            sys.exit(1)

        if (cert_bin == None):
            logging.error('Please specify amba cert bin!')
            sys.exit(1)

        if (output_file == None):
            logging.error('Please specify output file name for packed NN bin!')
            sys.exit(1)

        with open(nn_model_info, 'r') as f:
            config_info = yaml.load(f, Loader=yaml.FullLoader)

        raw_output = pack_raw(config_info)
        header_bin = gen_header_info(config_info, cert_bin, raw_output)
        gen_packed_bin(header_bin, raw_output, output_file)
    else:
        if (unified_bin == None):
            logging.error('Please specify unified NN bin file to do unpack!')
            sys.exit(1)

        unpack_bin(unified_bin)

