import re
import os
import sys
import glob
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

script_dir = os.path.dirname(os.path.realpath(__file__))

dataset_dir = os.path.join(script_dir, "../../apk-dataset")
extracted_dir = os.path.join(script_dir, "../../apk-dataset-extracted")

dataset_dir = os.path.normpath(dataset_dir)
extracted_dir = os.path.normpath(extracted_dir)

output_dir = "./"

pattern = r'(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s"\\]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s"\\]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s"\\]{2,}|www\.[a-zA-Z0-9]+\.[^\s"\\]{2,})'


def store_to_file(apk_path, urls):
    if urls:
        apk_name = os.path.basename(apk_path)
        output_file = os.path.join(output_dir, apk_name+"-resources.json")
        with open(output_file, 'w') as out:
            out.write("{\"ValuePoints\":[{\"ValueSet\":[{\"0\":[")
            for i, u in enumerate(urls):
                if i == len(urls)-1:
                    out.write("\"" + str(u) + "\"")
                else:
                    out.write("\"" + str(u) + "\",")
            out.write("]}]}],\"packagename\": \"" + apk_name + "\"}")

def extract_apk(apk_path, out_dir):
    print(f"\nFor {apk_path}")

    if os.path.isdir(out_dir):
        print("Already decompressed, proceding to extract URLs")
    else:
        print("Decompressing APK")
        result = subprocess.run(['apktool', 'd', apk_path, '-o', out_dir],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    
        if result.returncode != 0:
            print(f"Failed to decompile {apk_path}")
            return

    try:
        string_files = glob.glob(f'{out_dir}/**/strings.xml', recursive=True)

        if string_files:
            process(string_files, apk_path)
        else:
            print(f"No strings.xml files found in {out_dir}")

    except Exception as e:
        print(f"There was an error: {e}")

def process(files, apk_path):
    urls = []
    for f in files:

        try:
            tree = ET.parse(f)
            root = tree.getroot()
            res = root.findall('string')
        except ET.ParseError:
            print(f"Error parsing file: {f}")
            continue

        res1 = [(elem.attrib, elem.text) for elem in res]

        for att, val in res1:
            name = name = att.get('name', "No name attribute")

            for match in re.finditer(pattern, str(val)):
                matched_text = match.group()
                if matched_text not in urls:
                    urls.append(matched_text)
                print(f"Found {matched_text} with name [{name}]")

    store_to_file(apk_path, urls)
    urls.clear()


def main():
    global output_dir
    if len(sys.argv) > 1:
        output_dir = sys.argv[1]

    print("\nStart")
    for apk in os.listdir(dataset_dir):

        apk_path = os.path.join(dataset_dir, apk)
        extracted_path = os.path.join(extracted_dir, apk)

        extract_apk(apk_path, extracted_path+".out")

if __name__ == "__main__":
    main()
