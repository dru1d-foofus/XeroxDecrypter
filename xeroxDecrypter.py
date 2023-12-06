#!/usr/bin/env python3

# Author: tyler.booth@cdw.com (dru1d)
# A tool that leverages the Binary Ninja API to extract Xerox WorkCentre encryption keys from firmware images
# Based on the work of Nicolas Heiniger 
# https://blog.compass-security.com/2021/05/printer-tricks-episode-ii-attack-of-the-clones/

import argparse
import binascii
import gzip
import os
import shutil
import string
import tarfile
import zipfile

from binaryninja import *

def convert_dlm_to_tar(dlm_file_path):
    gzip_offset = 888  # Offset where the actual GZIP content starts; this is based on 7z output
    tar_file_path = dlm_file_path.replace('.DLM', '.tar')

    with open(dlm_file_path, 'rb') as dlm_file:
        # Skip the header bytes
        dlm_file.seek(gzip_offset)
        
        with gzip.open(dlm_file, 'rb') as gzip_file:
            with open(tar_file_path, 'wb') as tar_file:
                shutil.copyfileobj(gzip_file, tar_file)

    return tar_file_path

def unzipFirmware(file_path, root_dir, created_dirs=None):
    if created_dirs is None:
        created_dirs = []

    if not os.path.exists(file_path):
        print(f"[-] File not found: {file_path}")
        return None

    extract_dir = os.path.splitext(file_path)[0]
    if not os.path.exists(extract_dir):
        os.makedirs(extract_dir)
        created_dirs.append(extract_dir)

    if file_path.endswith('.DLM'):
        print(f"[+] Converting .DLM file to .tar: {file_path}")
        tar_file_path = convert_dlm_to_tar(file_path)
        if tar_file_path:
            file_path = tar_file_path
        else:
            return None

    if zipfile.is_zipfile(file_path):
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
    elif tarfile.is_tarfile(file_path):
        with tarfile.open(file_path, 'r') as tar_ref:
            tar_ref.extractall(extract_dir)
    else:
        print(f"[-] Unsupported file format: {file_path}")
        return None

    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            if file.endswith('.zip') or file.endswith('.tar') or file.endswith('.DLM') or file.startswith('NC_'):
                next_file_path = os.path.join(root, file)
                result = unzipFirmware(next_file_path, root_dir, created_dirs)
                if result:
                    return result

    create_clone_path = find_file_in_directory('createClone', extract_dir)
    if create_clone_path:
        destination_path = os.path.join(root_dir, 'createClone')
        shutil.copy(create_clone_path, destination_path)
        print(f"[+] 'createClone' copied to: {destination_path}")
        return destination_path

    return None

def cleanup_directories(dir_list):
    for dir_path in dir_list:
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)

def find_file_in_directory(file_name, directory):
    for root, dirs, files in os.walk(directory):
        if file_name in files:
            return os.path.join(root, file_name)
    return None

def extractEncryptionKey(file):
    disable_default_log()
    print(f"[*] Parsing {file}")
    print("[*] This will take a while...")
    bv = load(file, options={'files.universal.architecturePreference': ['ppc']})
    cryptoFunction = "esscrypto_encryptString"
    for function in bv.functions:
        mlil_function = function.medium_level_il
        for block in mlil_function:
            for mlil_instruction in block:
                if mlil_instruction.operation == binaryninja.MediumLevelILOperation.MLIL_CALL:
                    if mlil_instruction.dest.operation == binaryninja.MediumLevelILOperation.MLIL_CONST_PTR:
                        called_function_address = mlil_instruction.dest.constant
                        called_function = bv.get_function_at(called_function_address)
                        if called_function and called_function.name == cryptoFunction:
                            print(f"[+] Function {function.name} calls {cryptoFunction}")
                            encryptionKey = str(mlil_instruction.params[1]).strip('"')
                            print(f"[+] Encryption Key: {encryptionKey}")
                            key_hex = ''.join(format(ord(c), '02x') for c in encryptionKey)
                            print(f"[+] Encryption Key (Hex): {key_hex}")
    bv.file.close()
    return encryptionKey

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Xerox WorkCentre Encryption Key Extractor")
    parser.add_argument("-f", "--file", required=True, help="Path to the firmware *.zip file that will be parsed.")
    parser.add_argument("-o", "--output", required=True, help="Directory to save the createClone file to.")
    parser.add_argument("-s", "--string", required=False, help="String to be decrypted.")
    parser.add_argument("-b", "--binary", required=False, help="createClone binary file")
    args = parser.parse_args()

    created_dirs = []
    if args.string and args.binary:
        create_clone_path = args.binary
        encryption_key = extractEncryptionKey(create_clone_path)
    else:
        if args.binary:
            create_clone_path = args.binary
        else:
            create_clone_path = unzipFirmware(args.file, args.output, created_dirs)
            cleanup_directories(created_dirs)
        if not create_clone_path:
            print("[-] 'createClone' not found")
        else:
            extractEncryptionKey(create_clone_path)
