#! /usr/bin/env python3

#Name: Cristian Roque
#Class: CSE469
#ID: 1223531036

import argparse
import hashlib
import struct
import json
import os
import sys

# Function to calculate hash
def hash_calculation(filepath, verbose):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(filepath, 'rb') as file:
        while chunk := file.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    filename = os.path.basename(filepath)

    # Write hashes to files
    with open(f"MD5-{filename}.txt", 'w') as f_md5, \
            open(f"SHA-256-{filename}.txt", 'w') as f_sha256, \
            open(f"SHA-512-{filename}.txt", 'w') as f_sha512:
        f_md5.write(md5.hexdigest())
        f_sha256.write(sha256.hexdigest())
        f_sha512.write(sha512.hexdigest())

        if verbose:
            print(f"[INFO] MD5 of {filename}: {md5.hexdigest()}")
            print(f"[INFO] SHA-256 of {filename}: {sha256.hexdigest()}")
            print(f"[INFO] SHA-512 of {filename}: {sha512.hexdigest()}")

# This function was generated with the help of ChatGPT (developed by OpenAI)
# Reference: OpenAI. (2024). ChatGPT. openai.com/chatgpt
# Function to analyze the Master Boot Record
def parse_mbr(image, offsets, typeFilter, verbose):

    #these arrays hold the ascii strings and ascii hex values
    ascii_arr = ["", "", "", ""]
    ascii_hex_arr = ["", "", "", ""]

    #increments after each partition and is used for the index of the above arrays
    count = 0;

    # MBR partition table starts at offset 0x1BE
    partition_table_offset = 0x1BE
    num_partitions = len(offsets)  # There are four partition entries in the MBR

    if verbose:
        print(f"[INFO] Offsets passed:", end= " ")
        for i in range(0, len(offsets)):
            print(offsets[i], end=" ")
        print("\n")

    #open the json file to find the hex and partition type
    with open('PartitionTypes.json') as file:
        if verbose:
            print(f"[INFO] PartitionTypes.json opened.")
        types = json.load(file)

    filter_hex = None
    if typeFilter and 'mbr_type' in typeFilter:
        filter_hex = typeFilter['mbr_type'].lower().replace("0x", "")
        if verbose:
            print(f"[INFO] Type filter:", filter_hex)

    # Loop through each of the four partition entries
    for partition_num in range(1, num_partitions + 1):
        image.seek(partition_table_offset)  #seek to first MBR partition
        partition_table_offset = partition_table_offset + 16
        partition_entry = image.read(16)  # Each partition entry is 16 bytes

        if verbose:
            print(f"[INFO] Partition", partition_num)

        #read bytes 0x08-0x0b for the starting sector
        starting_sector_bytes = partition_entry[8:12]
        starting_sector = struct.unpack("<I", starting_sector_bytes)[0]
        sector_offset = starting_sector * 512

        #read bytes 0x0c-0x0f for the partition size
        partition_size_bytes = partition_entry[12:16]
        partition_size = struct.unpack("<I", partition_size_bytes)[0]
        size = partition_size * 512

        if verbose:
            print(f"[INFO] Starting Sector:", sector_offset, ", Partition Size:", size);

        #byte 4 is read from the entry to determine the mbr partition type
        type_byte = partition_entry[4]
        type_hex = f"{type_byte:02X}".lower()

        #default type description
        type_desc = "Empty"

        #search the json file 'types' for the matching hex and collect the type name
        if verbose:
            print(f"[INFO] Searching for a matching type in JSON File.")

        for partition_type in types:
            if partition_type['hex'] == type_hex:
                if verbose:
                    print(f"[INFO] Match found in JSON Types File:", type_hex)
                type_desc = partition_type['desc']
                break

        if filter_hex and type_hex != filter_hex:
            continue

        #calculate offset with starting sector and seek to that offset
        sector_offset = sector_offset + offsets[count]

        image.seek(sector_offset)
        partition_value = image.read(16)

        # Extract the boot record and convert it to ASCII and Hex representation
        ascii_representation = ' '.join([f"{b:02X}" for b in partition_value])
        ascii_string = '  '.join([chr(b) if 32 <= b <= 126 else '.' for b in partition_value])

        #store the information into the arrays for displaying while ignoring 'Empty' types
        if type_desc != "Empty":
            ascii_arr[count] = ascii_string
            ascii_hex_arr[count] = ascii_representation
            count = count + 1
            #print the type hex, type name, starting sector, and partition size
            print(f"({type_hex}), {type_desc}, {sector_offset}, {size}")

    if verbose:
        print(f"[INFO] MBR Parse Completed.")

    #print the partition information
    for i in range(0, count):
        # Display partition information
        print(f"Partition number: {i+1}")
        print(f"16 bytes of boot record from offset {offsets[i]:03d}: {ascii_hex_arr[i]}")
        print(f"ASCII:\t\t\t\t\t  {ascii_arr[i]}")

# This function was generated with the help of ChatGPT (developed by OpenAI)
# Reference: OpenAI. (2024). ChatGPT. openai.com/chatgpt
# Function to analyze the GUID Partition Table record
def parse_gpt(image, offsets, typeFilter, verbose):
    #offset to the starting LBA
    gpt_header_offset = 0x240

    # Seek to the 8 bytes of the starting LBA
    image.seek(gpt_header_offset)

    starting_LBA = image.read(16)  #read 16 bytes for the starting LBA
    starting_LBA_bytes = starting_LBA[8:16]

    LBA_value = struct.unpack("<Q", starting_LBA_bytes)[0]
    LBA_value = LBA_value * 512

    if verbose:
        print(f"[INFO] Header starting LBA: {LBA_value}\n")

    image.seek(LBA_value)   #seek over to the first gpt partition entry

    for num_entries in range(1, 5):
        partition_type = image.read(16)
        type_bytes = partition_type[0:16]

        #read the partition type GUID bytes
        type_bytes_left = struct.unpack("<QQ", type_bytes)[0]
        type_bytes_right = struct.unpack("<QQ", type_bytes)[1]
        
        #join each half of the bytes together for the partition type GUID
        hex_string = f"{type_bytes_right:016x}{type_bytes_left:016x}".upper()

        image.read(16)  #skip globally unique identifier
        lba = image.read(16)    #read the starting and ending lba's
        start_lba = struct.unpack("<QQ", lba)[0]
        end_lba = struct.unpack("<QQ", lba)[1]

        if verbose:
            print(f"[INFO] Starting LBA: {start_lba}, Ending LBA: {end_lba}")

        image.read(8)   #skip 8 bytes (partition attributes)
        partition_name_bytes = image.read(72)   #read the remaining bytes for the partition name

        #decode the bytes read for the partition name
        partition_name = partition_name_bytes.decode('utf-16le', errors='ignore').rstrip('\x00').strip()

        # Print the information
        print(f"Partition number: {num_entries}")
        print(f"Partition Type GUID : {hex_string}")
        print(f"Starting LBA in hex: {hex(start_lba)}")
        print(f"ending LBA in hex: {hex(end_lba)}")
        print(f"starting LBA in decimal: {start_lba}")
        print(f"ending LBA in decimal: {end_lba}")
        print(f"Partition name: {partition_name}\n")

# This function was generated with the help of ChatGPT (developed by OpenAI)
# Reference: OpenAI. (2024). ChatGPT. openai.com/chatgpt
# Function to analyze the GUID Partition Table record
def parse_filter(filter_str):
    """Parse the filter string into a dictionary."""
    if not filter_str:
        return None  # Return None if no filter is provided
    filter_dict = {}
    try:
        key, value = filter_str.split('=')
        filter_dict[key.strip()] = value.strip()
    except ValueError:
        print("Invalid filter format. Use 'key=value'.")
        sys.exit(1)
    return filter_dict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', nargs='+', required=True, help='Files to process (space-separated)')
    parser.add_argument('-o', '--offsets', nargs='*', type=int, help='MBR offsets (optional)')
    parser.add_argument('--filter', help="Optional filter criteria (e.g., 'mbr_type=0x07')")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    args = parser.parse_args()

    typeFilter = parse_filter(args.filter)

    verbose = False

#    filepath = sys.argv[2]
    for filepath in args.file:
        if not os.path.isfile(filepath):
            print(f"Error: {filepath} does not exist or is not a file.\n")
            continue
        
        filename = os.path.basename(filepath)

        if args.verbose:
            print(f"[INFO] Processing file: {filename}")
            print(f"[INFO] Checking if file exists: {filepath}")

        # Open the image in read-only mode
        with open(filepath, 'rb') as image:
            if args.verbose:
                verbose = True
                print(f"[INFO] File opened: {filepath} in read-only mode")

            # Calculate hashes
            hash_calculation(filepath, verbose)

            if verbose:
                print("[INFO] Hash values calculated.")

            #seek to the type byte
            type_offset = 0x1c2
            image.seek(type_offset)

            type_byte = image.read(1)

            #if the type byte is not EE, then parse MBR
            #otherwise, parse GPT
            if type_byte != b'\xee':
                if verbose:
                    print(f"[INFO] Type Byte is 0x06. Now parsing Master Boot Record.");
                parse_mbr(image, args.offsets, typeFilter, verbose)
            else:
                if verbose:
                    print(f"[INFO] Type Byte is 0xEE. Now parsing GUID Partition Table.");
                parse_gpt(image, args.offsets, typeFilter, verbose)

if __name__ == "__main__":
    main()
