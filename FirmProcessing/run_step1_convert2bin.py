#!/usr/bin/env python3

import os
import re
import binwalk
import sys
import logging
# import IPython
from firmutil import folder_operation
from firmutil import keyword_utility

input_prefix = "originals"
bin_dir = "./step1_bins/"
large_dir = "./step1_largeBins/"

total_count = 0

# these data can be done in step 2
bin_count = 0
hex_count = 0
large_count = 0

def cypress2bin(fp):
    #TODO
    print(f"Turning {fp} Cypress to binary\n")



def isCypress(fp):
    file_formats = [".cyacd", ".cyacd2"]
    for ff in file_formats:
        if fp.endswith(ff):
            return True
    return False

def main():
    '''
    Transform Intel Hex and Motorola SRecord to binary
    '''
    global bin_count
    global total_count

    file_identifier = 'Convert'
    logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format=f'{file_identifier} [%(levelname)s]: %(message)s')

    #clean environment
    folder_operation.delete_folder(bin_dir)

    if not os.path.exists("./" + input_prefix):
        logging.critical(f"The directory {input_prefix} does not exist")
    else:
        for subdi, dirs, files in os.walk(input_prefix):
            for fil in files:

                decompressed = False

                # File size
                size = os.path.getsize(os.path.join(subdi, fil))
               
                i_path = os.path.join(subdi, fil)

                index = subdi.find(input_prefix)
                o_path = bin_dir + subdi[index + len(input_prefix):]

                for module in binwalk.scan('--magic', './magic/archives', '-e', '-M', '--rm', '-cl', '--run-as=root', '-C', o_path, i_path, quiet=True):
                    for result in module.results:

                        # any results leading to extracted files indicates a compressed one
                        if result.file.path in module.extractor.output and len(module.extractor.output[result.file.path].extracted):
                            total_count += 1
                            decompressed = True
                            logging.debug(f"Decompressing file from {i_path} ")
                            logging.debug("to " + o_path)

                            desc = result.description.lower()

                            # Needs improvement

                            if "ti-txt" in desc:
                                rename_file_from_signature(result, module, ".ti-txt.bin", size)
                            elif "intel hex data" in desc:
                                found_condition = False
                                for res in module.results:
                                    if "_microchip,pic24/33" in res.description.lower():
                                        rename_file_from_signature(result, module, ".pic24_32.bin", size)
                                        found_condition = True
                                        break
                                    elif "_microchip,pic18" in res.description.lower():
                                        rename_file_from_signature(result, module, ".pic18.bin", size)
                                        found_condition = True
                                        break
                        
                                if not found_condition:
                                    rename_file_from_signature(result, module, "", size)

                            get_size_from_leaf(result, module, size)
                            break
                    

                # not recgnoized with extractor. consider it as a binary
                if not decompressed and "meta.json" not in i_path:
                    total_count += 1
                    final_path = clean_filename_and_size(i_path, size)
                    folder_operation.copy_file_new_name(input_prefix, i_path, bin_dir, final_path)

        folder_operation.set_current_user_owner_recursive(bin_dir)
        print_stats()

# khgjhg.fs45000fs.bin
        
def get_size_from_leaf(result, module, size):
    hex_suffix = ".hex.bin"
    for index in module.extractor.output[result.file.path].extracted:
        temp = module.extractor.output[result.file.path].extracted[index]
        if temp.files:
            for filepath in temp.files:
                
                index = filepath.rfind("/")
                filepath_extracted_dir = filepath[:index]

                if os.path.isfile(filepath):
                    # If extracted is a file that was not converted from hex (e.g., zip -> bin)
                    # Identify the size now
                    if hex_suffix not in filepath:
                        size = os.path.getsize(filepath)
                    # If extracted is a file converted from hex
                    # Use size identified before conversion
                    #index_dot = filepath.rfind(".") <- remove this because some files after extraction dont keep file format
                    name_plus_size = clean_filename_and_size(filepath, size)
                    if not os.path.exists(name_plus_size):
                        os.makedirs(os.path.dirname(name_plus_size), exist_ok=True)
                    #name_plus_size = filepath + ".fs"+str(size)+"fs."
                    os.rename(filepath, name_plus_size)                   

                # If extracted is a folder -> (e.g., zip -> folder)
                elif os.path.isdir(filepath_extracted_dir):
                    for root, dirs, files in os.walk(filepath_extracted_dir):
                        for filename in files:
                            print(filename)
                            if should_exclude(filename):
                                os.remove(os.path.join(filepath,filename))
                                continue
                            # If files inside folder extracted where not converted from hex
                            # Identify size now
                            if hex_suffix not in filename and not has_size_in_name(filename):
                                old_file_path = os.path.join(root, filename)
                                if os.path.exists(old_file_path):
                                    size = os.path.getsize(old_file_path)

                                #index_dot = filename.rfind(".")
                                #name_plus_size = filename[:index_dot] + ".fs"+str(size)+"fs."+ filename[index_dot+1:]
                                #name_plus_size = filename + ".fs" + str(size) + "fs."
                                    name_plus_size = clean_filename_and_size(old_file_path, size)
                                    if not os.path.exists(name_plus_size):
                                        os.makedirs(os.path.dirname(name_plus_size), exist_ok=True)

                                    os.rename(old_file_path, name_plus_size)


def rename_file_from_signature(result, module, suffix, size):
    for index in module.extractor.output[result.file.path].extracted:
        temp = module.extractor.output[result.file.path].extracted[index]
        if temp.files:
            for filepath in temp.files:
                if(size!=None):
                    new_path = clean_filename_and_size(filepath, size) + suffix
                    # new_path = os.path.join(os.path.dirname(filepath), os.path.basename(filepath) + ".fs"+str(size)+"fs." + suffix)
                else:
                    new_path = clean_filename_and_size(filepath, 0) + suffix
                    # new_path = os.path.join(os.path.dirname(filepath), os.path.basename(filepath) + suffix)

                if not os.path.exists(new_path):
                    os.makedirs(os.path.dirname(new_path), exist_ok=True)
                    
                os.rename(filepath, new_path)
                logging.debug(f"Renaming {filepath} \nto {new_path}")

def clean_filename_and_size(filename, size):
    #index_dot = filename.rfind(".")
    name_plus_size = filename + ".fs"+str(size)+"fs."
    cleaned_filename = "".join(c if c.isalnum() or c in ['_', '.', '/', '-'] else '_' for c in name_plus_size)

    return cleaned_filename

def has_size_in_name(filename):
    pattern = r'\.fs(\d+)fs\.'
    match = re.search(pattern, filename)
    return bool(match)

def print_stats():
    result = "RESULTS:\n"
    result += f"Total number of files: {total_count}\n"
    # result += f"Converted from hex/S-record: {hex_count}\n"
    # result += f"Binaries: {bin_count}\n"
    # result += f"Large binaries: {large_count}"
    with open("output_step1.txt", "w") as f:
        f.write(result)
    logging.debug(result)

def should_exclude(pname):
    for ext in keyword_utility.Keywords.excluded_extentions:
        if pname.endswith(ext):
            return True
    return False

if __name__ == "__main__":
    main()
