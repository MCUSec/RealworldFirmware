#!/usr/bin/env python3

import os
import sys
import re
import subprocess
import binwalk
import json
import logging
from firmutil import folder_operation
from collections import OrderedDict
import argparse
from elftools.elf.elffile import ELFFile


firmxray_path = "../FirmXRay/"

step1_bin_dir = "./step1_bins/"

input_prefix = "temp_step1_bins"

common_prefix = "./"
input_dir = common_prefix + input_prefix

output_prefix = "step2_postSig"

def create_directories(prefix, categories, suffixes):
    return {category: prefix + output_prefix + "/" + category + suffix for category, suffix in zip(categories, suffixes)}

# Directories sets
# Vendor directories
vendors = ("dialog", "ti", "esp", "telink", "qualcomm", "nordic", "microchip", "opulink", "renesas", "cypress", "csr", "samfw", "upg", "silabs", "stm32", "ubisys")
vendor_dirs = create_directories(common_prefix, vendors, [""] * len(vendors))

# Protocol directories
packers = ("zigbee", "mcuboot", "elf", "uf2", "linux", "basic") # elf, uf2 and linux should be treated differently
packers_dirs = create_directories(common_prefix, packers, [""] * len(packers))

# Architecture and ELF directories
specials = ("arm", "msp430", "xtensa", "mips", "pic18", "pic24_33")
special_dirs = create_directories(common_prefix, specials, [""] * len(specials))

# Other directories
others = ("encrypted", "failed")
other_dirs = create_directories(common_prefix, others, [""] * len(others))


# Siganture Sets
vendor_set = tuple("_" + vendor for vendor in vendors)
packer_set = tuple("_" + prot for prot in packers)
special_set = tuple("_" + spec for spec in specials)
vendor_packer_special_set = vendor_set + packer_set + special_set


ti_msp_prefix = "/2/sys"

entr_pattern = r'\((.*?)\)'
entr_threshold = 0.95

apk = ""
chip = ""
size = ""
base = ""


vendor_packer_counts = {vendor: 0 for vendor in vendors + packers}
special_counts = {spec: 0 for spec in specials}
other_counts = {other: 0 for other in others}


enable_firmxray = False


# GL: JSON Elements, each bin file comes with a JSON file (binname.firminfo.json)
# Vendor, Arch, Type (bin, Intel HEX or Moto HEX), Entry, Offset (within file), Base (loaded address), ??

# TODO
def init_json(json_dat):
    json_dat['architecture'] = ''
    json_dat['vendor'] = ''
    json_dat['chip'] = ''
    json_dat['packer'] = ''
    json_dat['base address'] = ''
    json_dat['entry'] = ''
    json_dat['comment'] = ''
    json_dat['file size'] = '-1'
    json_dat['protection'] = ''

def main():
    global other_counts
    global enable_firmxray

    parser = argparse.ArgumentParser(description='Enable firmxray')
    parser.add_argument('--enable-firmxray', action='store_true', help='Enable the firmxray feature')

    args = parser.parse_args()

    if args.enable_firmxray:
        enable_firmxray = True

    file_identifier = 'Sorter'
    logging.basicConfig(stream=sys.stdout,
                    level=logging.DEBUG,
                    format=f'{file_identifier} [%(levelname)s]: %(message)s')

    #clean environment
    folder_operation.delete_folder(common_prefix + output_prefix)
    folder_operation.delete_folder(input_dir)

    #prepare environment
    folder_operation.copy_folder(step1_bin_dir, input_dir)
    print()

    # GL: inside this function, you should fill in info about JSON Vendor info, such as Nordic
    process_folder_signature()

    # GL: For each nordic-like folders, run the signature and FirmXray to get Base, Offset, Entry, etc.
    # this is done in output_prefix
    # TODO
    process_nordic()

    for subdirs, dirs, fnames in os.walk(input_dir):
        for fn in fnames:

            # if we have similar cases we can make this a function to weed out useless files
            if excluded_formats(fn):
                logging.debug(f"Excluded format. No need to analyze: {fn}")
                continue

            json_dat = {}
            init_json(json_dat)

            store_size_in_json(fn, subdirs, json_dat)

            signature_folder = ""
            entropy_result = ""
            path = os.path.join(subdirs, fn)
            if ".ti-txt.bin" in fn:
                process_msp430(path, json_dat)
                continue
            elif "pic18" in fn:
                process_pic(path, json_dat, "pic18")
                continue
            elif "pic24" in fn:
                process_pic(path, json_dat, "pic24_33")
                continue

            try:
                print()
                logging.info("=================== PROCESSING FILE: ===================")
                logging.info(f"Name: {path}")

                # for module in binwalk.scan('--entropy', '--magic', './magic/vendors', '--magic', './magic/fromproject', '--nplot', '--quiet', path):
                #     if module.name == "Signature":
                #         signature_info = module.results
                        
                #     elif module.name == "Entropy":
                #         encrypted_info = module.results

                final_location = ""

                entropy_result, signature_info = run_binwalk('--entropy', '--magic', './magic/vendors', '--magic', './magic/fromproject', '--magic', './magic/rxcores', '--nplot', '--quiet', path=path)

                # Handle entropy first
                #entropy_result = entropy(encrypted_info, path)
                if entropy_result == "encrypted":
                    #Move file to encrypted folder
                    final_location = folder_operation.copy_file_keep_structure(input_prefix, path, other_dirs["encrypted"])
                json_dat['protection'] = entropy_result

                # Now handle signatures
                signature_folder = signatures(signature_info, json_dat)
                if signature_folder != "":
                    logging.debug(f"Signature result: {signature_folder}")

                    if final_location == "":
                        final_location = folder_operation.copy_file_keep_structure(input_prefix, path, signature_folder)

                    # Run firmxray only when architecture is arm
                    if json_dat["architecture"] == "arm":

                        #File offset will only be present when it matches with an arm signature location
                        if "file offset" in json_dat:

                            #Only run firmxray if we have identified a file offset, from the TI description that matches _Arm signature
                            logging.info(f"Running FirmXRay on {final_location}...")
                            abs_final_location = os.path.abspath(final_location)

                            if json_dat["vendor"] == "ti":
                                logging.info("TI used for firmxray")
                                base_address = run_firmxray(abs_final_location, "TI")
                            else:
                                # Create a copy of the file without header or empty bytes (from the hex conversion)
                                file_for_firmxray = create_file_from_offset(abs_final_location, json_dat)

                                logging.info("Raw Arm (including Nordic) used for firmxray")
                                base_address = run_firmxray(file_for_firmxray, "Nordic")

                                # Only remove the file if it was a copy, and not the original file
                                if(file_for_firmxray != abs_final_location):
                                    os.remove(file_for_firmxray)

                            if base_address == "0x-1":
                                json_dat["architecture"] = ""

                            logging.debug(f"Reported base address: {base_address}")
                            json_dat["base address"] = base_address
                else:
                    logging.warning(f"empty signature_folder")
                write_json(final_location, json_dat)

            except binwalk.ModuleException as e:
                logging.error(f"Fail: {e}")
    
    print_stats()
    folder_operation.delete_folder(input_dir)



def process_folder_signature():
    global vendor_packer_counts
    binpattern = r".bin.fs"
    for root, dirs, files in os.walk(input_dir):
        #Chech for MSP432 folder structure
        if root.endswith(ti_msp_prefix):
            logging.info(f"Signature match: MSP432 tar archive in {root}")
            for file in os.listdir(root):
                file_path = os.path.join(root, file)
                match = re.search(binpattern, file_path)
                if match and os.path.getsize(file_path) > 64:
                    data = {}
                    init_json(data)
                    
                    bin_final_path = folder_operation.move_file_keep_structure(input_prefix, file_path, vendor_dirs["ti"])
                    protection, sigs = run_binwalk('--entropy', '--nplot', '--quiet', path=bin_final_path)

                    data["vendor"] = "TI"
                    data["protection"] = protection

                    for item in sigs:
                        data["comment"] += item.description + ", "

                    write_json(bin_final_path, data)
                    vendor_packer_counts["ti"] += 1
            
            # We can delete the remaining of the folder since we extracted the binary
            index = root.find(ti_msp_prefix)
            to_delete = root[:index]
            folder_operation.delete_folder(to_delete)
            print()

        #Check for Nordic manifest.json signature
        for file in files:
            # Find manifest.json files
            filename = file.lower()
            if filename.startswith("manifest") and ".json.fs" in filename:
                data = {}
                path = os.path.join(root, file)
                try:
                    with open(path, 'r') as f:
                        # load manifest content in parsed_data
                        parsed_data = json.load(f)
                        # key_level: pointer to "application" object in manifest
                        if "manifest" in parsed_data:
                            manifest_data = parsed_data["manifest"]
                            if "application" in manifest_data:
                                key_level = manifest_data["application"]
                                print("Found 'application' key:", key_level)
                            elif "bootloader" in manifest_data:
                                key_level = manifest_data["bootloader"]
                                print("Found 'bootloader' key:", key_level)
                            elif "softdevice_bootloader" in manifest_data:
                                key_level = manifest_data["softdevice_bootloader"]
                                print("Found 'softdevice_bootloader' key:", key_level)
                            elif "softdevice_bootloader" in manifest_data:
                                key_level = manifest_data["softdevice"]
                                print("Found 'softdevice' key:", key_level)
                        else:
                            print("The 'manifest' key is not present in the JSON data.")
                        #key_level = parsed_data["manifest"]["application"]
                        # success if all three keys exist in this level
                        if all(key in key_level for key in ["bin_file", "dat_file"]):
                            logging.debug(f"Signature match: Nordic folder in {root}")
                            sibling_files = [f for f in os.listdir(root) if
                                             os.path.isfile(os.path.join(root, f))]
                            for f in sibling_files:
                                if ".bin.fs" in f and ".json" not in f:
                                    init_json(data)

                                    bin_final_path = folder_operation.move_file_keep_structure(input_prefix, os.path.join(root, f), vendor_dirs["nordic"])
                                    protection, sig_results = run_binwalk('--entropy','--magic', './magic/vendors', '--magic', './magic/fromproject', '--magic', './magic/rxcores', '--nplot', '--quiet', path=bin_final_path)

                                    res = signatures(sig_results, data)
                                    logging.info(f"Signature match: {res}")

                                    data["vendor"] = "nordic" 
                                    data["protection"] = protection

                                    write_json(bin_final_path, data)
                                    folder_operation.delete_folder(root)
                                    vendor_packer_counts["nordic"] += 1
                                    break
                            print()

                except Exception as e:
                    # Will be triggered if manifest->application does not exist. 
                    # i.e., We have a manifest.json file that is not a nordic manifest
                    logging.warning(f"Something went wrong: {e}")


def run_binwalk(*args, path):
    ent_result = None
    sig_result = None
    for module in binwalk.scan(*args, path):
        if module.name == "Signature":
            sig_result = module.results
            
        elif module.name == "Entropy":
            ent_result = entropy(module.results, path)

    return (ent_result, sig_result)


def process_nordic():
    for subdirs, dirs, fnames in os.walk(vendor_dirs["nordic"]):
        for fn in fnames:
            if ".json.fs" not in fn and "firminfo.json" not in fn:
                json_dat = {"vendor": "", "arch": "", "file size": "", "base address": ""}
                
                #add size
                size = os.path.getsize(os.path.join(subdirs, fn))
                json_dat["file size"] = size

                in_path = os.path.join(subdirs, fn)

                # try:
                #     print()
                #     logging.info("=================== PROCESSING FILE: ===================")
                #     logging.info(f"Name: {in_path}")
                #     # for module in binwalk.scan('--magic', './magic/vendors', '--magic', './magic/fromproject', '--quiet', in_path):
                #     #     if module.name == "Signature":
                #     _, sig = run_binwalk('--magic', './magic/vendors', '--magic', './magic/fromproject', '--quiet', path=in_path)
                #     res = signatures(sig, json_dat)
                #     logging.debug(f"Signature match: {res}")
                #     if special_dirs["arm"] not in res:
                #         logging.warning(f"Nordic should be Arm arch.")

                # except binwalk.ModuleException as e:
                #     logging.error(f"Fail: {e}")

                #get absolute path of binary to pass it to firmwray
                absolute_path = os.path.abspath(in_path)

                logging.info(f"Running FirmXRay on {absolute_path}...")

                base_address = run_firmxray(absolute_path, "Nordic")

                if base_address == "0x-1":
                    json_dat["architecture"] = ""

                json_dat["base address"] = base_address
                write_json(in_path, json_dat)


def run_firmxray(firmware_path, vendor):
    global enable_firmxray
    print("Run base address")
    if not enable_firmxray:
        print("No FirmXRay")
        return "0x0"
    # Save the current working directory
    original_directory = os.getcwd()
    base_address = ""
    
    os.chdir(firmxray_path)

    command = f"java -cp out:lib/ghidra.jar:lib/json.jar main.Main {firmware_path} {vendor} true"

    try:
        # Run the make command
        result = subprocess.run(command, shell=True, check=True, text=True, capture_output=True)
        print(f"Result: {result}")
        pattern = r'Base: (0x[\-0-9a-fA-F]+)'
        match = re.search(pattern, result.stdout)
        if match:
            # Extract the  base address
            base_address = match.group(1)
            print(f"BaseAddr: {base_address}")
            
        else:
            logging.critical("Base not reported by FirmXRay")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
    finally:
        # Change back to the original working directory
        os.chdir(original_directory)

    return base_address


def has_conflict(results):
    filtered_results = [item for item in results if item.description.lower().startswith(vendor_set)]
    return len(filtered_results) >= 2

def has_info(results):
    filtered_results = [item for item in results if item.description.lower().startswith(vendor_packer_special_set)]
    return len(filtered_results) > 0

def process_pic(filename, json_dat, c_type):
    prot, sig = run_binwalk('--entropy', '--magic', './magic/vendors', '--magic', './magic/fromproject', '--nplot', '--quiet', path=filename)

    if "encrypted" in prot:
        final_path = folder_operation.copy_file_keep_structure(input_prefix, filename, other_dirs["encrypted"])
    else:
        final_path = folder_operation.copy_file_keep_structure(input_prefix, filename, vendor_dirs["microchip"])

    json_dat["vendor"] = "microchip"
    json_dat["chip"] = c_type
    json_dat["architecture"] = c_type
    json_dat["protection"] = prot
    for result in sig:
        json_dat["comment"] += result.description + ", "

    write_json(final_path, json_dat)

    vendor_packer_counts["microchip"] += 1
    special_counts[c_type] += 1

def process_msp430(filename, json_dat):
    global vendor_packer_counts
    global special_counts

    protection, _ = run_binwalk('--entropy', '--nplot', '--quiet', path=final_path)

    if "encrypted" in protection:
        final_path = folder_operation.copy_file_keep_structure(input_prefix, filename, other_dirs["encrypted"])
    else:
        final_path = folder_operation.copy_file_keep_structure(input_prefix, filename, vendor_dirs["ti"])

    json_dat["vendor"] = "ti"
    json_dat["chip"] = "msp430"
    json_dat["architecture"] = "msp430"
    json_dat["protection"] = protection
    write_json(final_path, json_dat)
    
    vendor_packer_counts["ti"] += 1
    special_counts["msp430"] += 1

def create_file_from_offset(file_path, json_dat):
    offset = json_dat.get("file offset", 0)
    if offset > 0:
        ret_file = file_path+"_fxr"
        data = ''
        with open(file_path, 'rb') as file:
            file.seek(offset)
            data = file.read()
        with open(ret_file, 'wb') as file:
            file.write(data)
        return ret_file
    else:
        return file_path


def parse_sig_popular_vendors_packers(filename, desc, json_dat, allresults):
    global vendor_packer_counts

    result_dir = ""
    chip = ""

    description = desc.strip().lower()

    vendor_mapping = {}
    pack_mapping = {}
    
    for v_set in vendor_packer_special_set:
        for vendor in vendors:
            if v_set == "_"+vendor:
                vendor_mapping[v_set] = vendor_dirs[vendor]
        for pack in packers:
             if v_set == "_"+ pack:
                 pack_mapping[v_set] = packers_dirs[pack]

    try:
        desc_array = desc.lower().split(',')
        if len(desc_array) > 3:
            chip = desc_array[1].strip()
            arch = desc_array[3].strip()
        elif len(desc_array) > 1:
            chip = desc_array[1].strip()
    except ValueError:
        logging.error("The input string does not have enough parts.")
    
    header_length = fetch_header_length(desc.lower())

    for prefix, directory in vendor_mapping.items():
        name = prefix[1:]
        if description.startswith(prefix):
            json_dat["vendor"] = name
            json_dat["chip"] = chip
            json_dat["architecture"] = arch

            if name == "ti":
                # If vector table is at the reported file offset location store the value to file offset, else
                # store it to entry, since it is the code entry
                json_dat["entry" if not has_vectortable(allresults, header_length) else "file offset"] = header_length
            else:
                json_dat["file offset"] = header_length

            update_base_and_entry(desc.lower(), json_dat)
            vendor_packer_counts[name] += 1

            result_dir = directory

    for prefix, directory in pack_mapping.items():
        name = prefix[1:]    
        if description.startswith(prefix):
            json_dat["packer"] = name
            result_dir = directory
            if description.startswith("_elf"):
                bin_arch, bin_entry, bin_flags = read_elf(filename)
                        
                json_dat["architecture"] = bin_arch
                json_dat["entry"] = bin_entry
                json_dat["comment"] += f"ELF Flags: {bin_flags}, "
                vendor_packer_counts["elf"] += 1
            
            elif description.startswith("_uf2"):
                process_uf2(desc.lower(), json_dat)

            elif description.startswith("_linux"):
                json_dat["comment"] += desc + ", "
                vendor_packer_counts["linux"] +=1

    return result_dir

def signatures(results, json_dat):

    global special_counts, other_counts

    failed_dir = other_dirs["failed"]
    arm_dir = special_dirs["arm"]

    ret_value = ''

    if len(results) == 0:
        logging.debug("No signatures found")
        other_counts["failed"] += 1
        return failed_dir

    for index, r in enumerate(results):
        print(f">{index}. offset: {hex(r.offset)}: {r.description}\n")

    identify_protection(results, json_dat)

    if len(results) == 1:
        res = results[0]
        desc = res.description
        offset = res.offset

        json_dat["comment"] += f"{desc}, "

        ret_value = parse_sig_popular_vendors_packers(res.file.name, desc, json_dat, None)
        if bool(ret_value):
            return ret_value
        # the only sig is Arm
        if desc.strip().lower().startswith("_arm"):
            special_counts["arm"] += 1
            json_dat["architecture"] = "arm"
            # json_dat["vendor"] = "arm"
            json_dat["file offset"] = offset
            return arm_dir
        else:
            logging.debug(f"Has other signature: {desc}")
            json_dat["packer"] = "basic"
            json_dat["comment"] = desc
            vendor_packer_counts["basic"] += 1
            return packers_dirs["basic"]
        
    elif len(results) > 1:
        logging.debug("Has more than one firmware signatures")

        # Store all signature matches in the json file
        unique_descriptions = set()
        for element in results:
            if element.description not in unique_descriptions:
                json_dat["comment"] += f"{element.description}, "
                unique_descriptions.add(element.description)

        if has_conflict(results):
            logging.warning("and they conflict with each other")
            other_counts["failed"] += 1
            # this is the best we can do for now.
            return failed_dir
        # since they don't conflict, fill in as much info as we can
        # but for Arm, we don't count.
        elif has_info(results):
            for entry in results:
                desc = entry.description
                offset = entry.offset
                r = parse_sig_popular_vendors_packers(results[0].file.name, desc, json_dat, results)
                # avoid overwritting ret with ''.
                # just a valid fold if multiple sigs
                if bool(r):
                    ret_value = r

                if desc.strip().lower().startswith("_arm") and can_be_arm(json_dat) and is_field_empty(json_dat, "architecture"):

                    json_dat["architecture"] = "arm"
                    #json_dat["comment"] += desc
                    special_counts["arm"] += 1

                    # If it's arm the file offset should be the location of the first arm signature (for Firmxray analysis)
                    if "file offset" not in json_dat:
                        json_dat["file offset"] = offset

                    # no other vendor, then use Arm
                    # if not bool(json_dat["vendor"]):
                        #json_dat["vendor"] = "arm"
                    #    ret = arm_dir
                    if ret_value == '':
                        ret_value = arm_dir

                # elif desc.strip().lower().startswith("_elf"):
                #     bin_arch, bin_entry, bin_flags = read_elf(entry.file.name)
                #     json_dat["architecture"] = bin_arch
                #     json_dat["entry"] = bin_entry
                #     json_dat["comment"] += f", ELF Flags: {bin_flags}, "
                #     special_counts["elf"] += 1
                #     if not bool(json_dat["vendor"]):
                #         json_dat["vendor"] = "elf"
                #         ret = elf_dir

                # elif desc.strip().lower().startswith("_uf2"):
                #     process_uf2(desc.lower(), json_dat)
                
                # elif desc.strip().lower().startswith("_linux"):
                #     json_dat["vendor"] = "linux"
                #     json_dat["comment"] = desc
                #     special_counts["linux"] +=1
                #     ret = special_dirs["linux"]

            if bool(json_dat["vendor"]):
                return ret_value
            elif bool(json_dat["packer"]):
                return ret_value
            elif bool(json_dat['architecture']):
                return ret_value
            # this should never happen
            else:
                logging.warning("no valid signature found (Should never happen)")
                other_counts["failed"] += 1
                return failed_dir
        else:
            logging.warning("no valid signature found")
            json_dat["packer"] = "basic"
            vendor_packer_counts["basic"] += 1
            return packers_dirs["basic"]


def has_vectortable(allresults, offset):
    if allresults != None:
        logging.debug(f"File offset reported from description: {offset}")
        for result in allresults:
            if "_arm" in result.description.lower() and result.offset == offset:
                logging.debug(f"Matches with vector table result offset: {result.offset}")
                return True
        return False
    else:
        return False   
    #return any(result.description.lower() == "_arm" and result.offset == offset for result in allresults) if allresults else False
      
def identify_protection(results, json_dat):

    # little endian form
    IMAGE_F_ENCRYPTED_AES128 = 0x04
    IMAGE_F_ENCRYPTED_AES256 = 0x08

    for result in results:
        desc = result.description.lower()
        if "crc: " in desc:
            # Ti, dialog
            match = re.search(r'crc: (0x[0-9a-fA-F]+)', desc)
            if match:
                crc = match.group(1)
                if json_dat["protection"] in ["plaintext", ""]:
                    json_dat["protection"] = "crced: " + crc + ","
                else:
                    json_dat["protection"] += "crced: " + crc + ","
        if "header flags: " in desc:
            # MCUBoot
            match = re.search(r'header flags: (0x[0-9a-fA-F]+)', desc)
            if match:
                try:
                    hex_string = match.group(1)
                    hex_value = int(hex_string, 16)
                    
                    is_aes128_encrypted = hex_value & IMAGE_F_ENCRYPTED_AES128 != 0
                    is_aes256_encrypted = hex_value & IMAGE_F_ENCRYPTED_AES256 != 0

                    if json_dat["protection"] in ["plaintext", ""]:
                        json_dat["protection"] = "encrypted AES128," if is_aes128_encrypted else "encrypted AES256," if is_aes256_encrypted else ""
                    else:
                        json_dat["protection"] += "encrypted AES128," if is_aes128_encrypted else "encrypted AES256," if is_aes256_encrypted else ""

                except Exception as e:
                    logging.error(f"Error parsing header flags {hex_string}")
        if "encrypted image" in desc:
            # Dialog
            if json_dat["protection"] in ["plaintext", ""]:
                json_dat["protection"] = "encrypted"
            else:
                json_dat["protection"] += "encrypted"

        if json_dat["protection"] == "":
            json_dat["protection"] = "plaintext"
        

def process_uf2(desc, json_dat):

    base_pattern = r"base: (0x[0-9a-fA-F]+),"
    b_match = re.search(base_pattern, desc)
    json_dat["base address"] = b_match.group(1)

    index = desc.find("arm,")
    if index != -1:
        substring_after_arm = desc[index + len("arm,"):]
        
        desc_array = substring_after_arm.lower().split(',')
        vendor = desc_array[0].strip()
        chip = desc_array[1].strip()

        json_dat["architecture"] = "arm"
        json_dat["vendor"] = vendor
        json_dat["chip"] = chip


def update_base_and_entry(desc, json):
    entry_pattern = r"entry point: (0x[0-9a-fA-F]+),"
    base_pattern = r"base: (0x[0-9a-fA-F]+),"

    e_match = re.search(entry_pattern, desc)
    b_match = re.search(base_pattern, desc)
    if e_match:
        json["entry"] = e_match.group(1)
    if b_match:
        json["base address"] = b_match.group(1)


def fetch_header_length(desc):
    hex_number = "0"
    pattern = r'file offset: (0x[0-9a-fA-F]+),'
    match = re.search(pattern, desc)
    if match:
        hex_number = match.group(1)

    return int(hex_number, 16)
   

def can_be_arm(json_dat):
    vendor = json_dat["vendor"]
    exclude = ["esp"]
    return not vendor in exclude

def is_field_empty(my_dict, field_name):
    return field_name in my_dict and not my_dict[field_name]


def read_elf(file_path):
    arch = ""
    entry = -1
    flags = 0
    with open(file_path, 'rb') as f:
        try:
            elf_file = ELFFile(f)
            arch = elf_file.get_machine_arch()
            entry = hex(elf_file.header['e_entry'])
            flags = hex(elf_file.header['e_flags'])
        except Exception as e:
            logging.critical(f"Could not read elf file {file_path} because: {e}")
    return arch.lower(), entry, str(flags)

def excluded_formats(file_name):
    formats = {'.apk.', '.so.', '.o.', '.ko.', '.so.bin.', '.o.bin.', '.ko.bin.'}
    for item in formats:
        if item+"fs" in file_name:
            return True
    return False

def store_size_in_json(filename, subdirs, json_dat):
    pattern = r'\.fs(\d+)fs\.'
    match = re.search(pattern, filename)
    if match:
        size = match.group(1)
        json_dat["file size"] = size
    else:
        match = re.search(pattern, subdirs)
        if match:
            size = match.group(1)
            json_dat["file size"] = size
        else:
            logging.error(f"Size not found for {filename}")
    

def entropy(results, filepath):
    global other_counts
    num = 0
    count = 0
    for r in results:
        try:
            num += float(r.description)
            count += 1
        except Exception as e:
            #print("Result contains string, finding number in it...")
            match = re.search(entr_pattern, r.description)
            if match:
                #print(f"Found: {match.group(1)}")
                str = match.group(1)
                num += float(str)
                count += 1
            else:
                logging.warning(f"No match found for {r.description}")
    if count > 0:
        res = num / count
    else:
        res = 0
    #print(f"{filepath}'s average entropy is: {res}")

    if res > entr_threshold:
        other_counts["encrypted"] += 1
        return "encrypted"
    
    return "plaintext"


def write_json(file_path, args):
    json_name = file_path + "_firminfo.json"

    if args:
        if(os.path.exists(json_name)):
            with open(json_name, 'r') as json_file:
                json_data = json.load(json_file)

            for key, value in args.items():
                if key not in json_data:
                    json_data[key] = value
                else:
                    if key == "comment":
                        json_data[key] += value
                    elif key == "file size" or key == "protection" or json_data[key] == "" or json_data[key] == 0:
                        json_data[key] = value                        
                    else:
                        logging.warning(f"Warning: Key '{key}' already exists in the json file. Skipping update from '{json_data[key]}' to '{value}'.")

        else:
            json_data = OrderedDict(list(args.items()))

        with open(json_name, 'w') as json_file:
            json.dump(json_data, json_file, indent=2)
    else:
        logging.error("Json data to write cannot be empty")


def print_stats():
    global vendor_packer_counts
    global special_counts
    global other_counts

    result = "RESULTS:\n"
    for key in set(special_counts):
        result += f"{key}: {special_counts.get(key)}\n"
    for key in set(vendor_packer_counts):
        result += f"{key}: {vendor_packer_counts.get(key)}\n"
    for key in set(other_counts):
        result += f"{key}: {other_counts.get(key)}\n"

    with open("output_step2.txt", "w") as f:
        f.write(result)  

    print(result)

if __name__ == "__main__":
    main()
