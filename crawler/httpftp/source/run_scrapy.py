import os
import re
import sys
import json
import time

sys.path.insert(0,os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import config

output = config.get_folder("crawler.output_folder")

def process_set(filepath, urls):
    global output

    filename = os.path.basename(filepath)

    preprocessed_urls = preprocess_urls(list(dict.fromkeys(urls)))

    start_time = time.time()

    for item in preprocessed_urls:
        command = f"scrapy crawl ota-scrape -a \"apkname={filename}\" -a \"urls={item}\" -o \"{output}/{filename}-urls.json\""
        print(f"\n\nPROCESSING URL FROM {filename} \n\n" + command)
        os.system(command)

        elapsed_time = time.time() - start_time
        if elapsed_time > 900:
            print(f"Processing for {filename}'s ValueSet took more than 15 minutes.")
            break

def get_urls_json(filepath):
    data = ""
    with open(filepath, "r") as json_data:
        data = json.load(json_data)

    start_time = time.time()

    for vp in data["ValuePoints"]:

        elapsed_time = time.time() - start_time

        if "ValueSet" in vp:
            result = []
            for resList in vp["ValueSet"]:
                for key in resList.keys():
                    individualResult = resList[key]
                    if isinstance(individualResult, list):
                        print(individualResult)
                        for element in list(individualResult):
                            result.append(element.replace(chr(0), ""))
                    else:
                        print(f"!!!! ------- !!!! {type(individualResult)}")
            process_set(filepath, result)

        if elapsed_time > 7200:
            filename = os.path.basename(filepath)
            print(f"Processing for {filename}'s ValueSet took more than 15 minutes.")
            break

    return result

def preprocess_urls(urls):
    url_list = []
    regex_http = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>\\\",]+|\(([^\s()<>\\\"]+|(\([^\s()<>\\\",]+\)))*\))+(?:\(([^\s()<>\\\",]+|(\([^\s()<>\\\",]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’\\]))"
    url_list.extend([x[0] for item in urls for x in re.findall(regex_http, item)])
    return url_list

def run_command_on_files():
    global output

    directory = config.get_folder("crawler.input_folder")
    already_analyzed = os.listdir(output)

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        print(filepath)
        
        if os.path.isfile(filepath) and filename.endswith(".json") and filename+"-urls.json" not in already_analyzed:
        #if os.path.isfile(filepath) and filename.endswith(".json") and filename+"-urls.json" and "motorola" in filename:
            try:
                get_urls_json(filepath)
            except Exception as e:
                print(e)    
        else:
            print("Already analyzed or not a good input file")


run_command_on_files()
