import os
import subprocess

script_dir = os.path.dirname(os.path.realpath(__file__))

dataset_dir = os.path.join(script_dir, "../apk-dataset")
extracted_dir = os.path.join(script_dir, "../apk-dataset-extracted")

dataset_dir = os.path.normpath(dataset_dir)
extracted_dir = os.path.normpath(extracted_dir)

def extract_apk(apk_path, out_dir):
    print(f"\nFor {apk_path}")

    if os.path.isdir(out_dir):
        print("Already decompressed")
    else:
        result = subprocess.run(['apktool', 'd', apk_path, '-o', out_dir],
                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    
        if result.returncode != 0:
            print(f"Failed to decompile {apk_path}")
            return

for apk in os.listdir(dataset_dir):

    apk_path = os.path.join(dataset_dir, apk)
    extracted_path = os.path.join(extracted_dir, apk)

    extract_apk(apk_path, extracted_path+".out")