import sys
import json
import os
from collections import defaultdict

vendors = ("dialog", "ti", "esp", "telink", "qualcomm", "nordic", "microchip", "opulink", "cypress", "csr", "samfw", "upg", "arm", "n/a")
vendor_counts = {vendor: 0 for vendor in vendors}


archs = ("arm", "msp430", "xtensa", "mips", "pic18", "pic24_33", "csr", "x64", "x86", "aarch64", "others", "n/a")

archs_counts = {arch: 0 for arch in archs}

prots = ("plaintext", "crced", "encrypted", "n/a")
prot_counts = {prot: 0 for prot in prots}

packers = ("zigbee", "mcuboot", "elf", "uf2", "linux", "basic", "n/a")
packer_counts = {packer: 0 for packer in packers}

comb_counters = defaultdict(int)

# def generate_triples(set1, set2):
#     return {(item1, item2, 0) for item1 in set1 for item2 in set2}

# combined_counts = generate_triples(archs, vendors)


def parse_archs(directory):
    global vendor_counts, archs_counts, packer_counts, prot_counts
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith("_firminfo.json"):
                json_path = os.path.join(root, file)
                arch = ""
                vendor = ""
                packer = ""
                protection = ""
                try:
                    with open(json_path, 'r') as json_file:
                        data = json.load(json_file)

                        arch = data['architecture'] if 'architecture' in data and data['architecture'] else 'n/a'
                        archs_counts[arch] += 1
                        
                        vendor = data['vendor'] if 'vendor' in data and data['vendor'] else 'n/a'
                        vendor_counts[vendor] += 1

                        packer = data['packer'] if 'packer' in data and data['packer'] else 'n/a'
                        packer_counts[packer] += 1
                        print()
                        if 'protection' in data:
                            for element in prot_counts:
                                if element in data['protection']:
                                    if protection != "":
                                        print(protection)
                                        print(element)
                                    protection = element
                                    prot_counts[protection] += 1

                    comb_counters[(arch, vendor, packer)] += 1
                        
                    # print(f"{arch}, {vendor}, {packer}")

                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON in {json_path}: {e}")

def find_arm_arch_paths(directory):
    arm_paths = ["filename. vector table offset (hex), vector table offset (dec), base address"]
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith("_firminfo.json"):
                json_path = os.path.join(root, file)
                base_filename =json_path[:-len("_firminfo.json")]
                json_path = os.path.join(root, file)

                with open(json_path, 'r') as json_file:
                    offset = ""
                    hexoffset = ""
                    base= ""
                    try:
                        data = json.load(json_file)
                        if 'architecture' in data and data['architecture'] == 'arm':

                            if 'file offset' in data:
                                offset = data['file offset']
                                hexoffset = hex(offset)

                            if 'base address' in data:
                                base = data['base address']

                            arm_paths.append(f"{base_filename}, {hexoffset}, {offset}, {base}")

                    except json.JSONDecodeError as e:
                        print(f"Error decoding JSON in {json_path}: {e}")

    return arm_paths

def main():
    global vendor_counts, archs_counts, packer_counts, prot_counts
    directory_path = sys.argv[1]
    print(directory_path)
    #arm_arch_paths = find_arm_arch_paths(directory_path)
    parse_archs(directory_path)

    print("TOTALS:")
    print("\n  Architectures:")
    total_arch = 0
    for name in archs:
        print(f"    {name:<12} {archs_counts[name]}")
        total_arch += archs_counts[name]
    print(f"    Total:       {total_arch}")

    total_vendor = 0
    print("\n  Vendors:")
    for name in vendors:
        print(f"    {name:<12} {vendor_counts[name]}")
        total_vendor += vendor_counts[name]
    print(f"    Total:       {total_vendor}")

    total_packer = 0
    print("\n  Packers:")  
    for name in packers:
        print(f"    {name:<12} {packer_counts[name]}") 
        total_packer += packer_counts[name]
    print(f"    Total:       {total_packer}")

    total_prot = 0
    print("\n  Protection:")
    for name in prots:
        print(f"    {name:<12} {prot_counts[name]}")
        total_prot += prot_counts[name]
    print(f"    Total:       {total_prot}")

      

    print("\nCOMBINED:\n")
    print(f"  Architecture    Vendor       Packer      Number")
    for arch, vendor, pack in sorted(comb_counters):
        count = comb_counters[(arch, vendor, pack)]
        print(f"  {arch:<13} - {vendor:<10} - {pack:<12} {count}")

    # if arm_arch_paths:
    #     print("Files with 'arch' field set to 'arm':")
    #     with open("arm_files.txt", 'a') as out:
    #         for path in arm_arch_paths:
    #             out.write(path+"\n")
    # else:
    #     print("No files found with 'arch' field set to 'arm'.")
        
if __name__ == "__main__":
    main()