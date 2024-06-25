import os
import re
import sys
import subprocess

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from config import config

sys.path.insert(0, config.get_folder("crawler.http_folder"))
from utility import Keywords

# Run this inside the scrapy virtual environment 

def http_urls(text):
    url_list = []
    regex_http = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>\\\",]+|\(([^\s()<>\\\"]+|(\([^\s()<>\\\",]+\)))*\))+(?:\(([^\s()<>\\\",]+|(\([^\s()<>\\\",]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’\\]))"
    url_list.extend([x[0] for x in re.findall(regex_http, text)])
    return url_list

def ftp_urls(text):
    url_list = []
    regex_ftp = r"(?i)\b((?:ftps?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>\\\",]+|\(([^\s()<>\\\"]+|(\([^\s()<>\\\",]+\)))*\))+(?:\(([^\s()<>\\\",]+|(\([^\s()<>\\\",]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’\\]))"
    url_list.extend([x[0] for x in re.findall(regex_ftp, text)])
    return url_list

def has_keyword(text):
    lowered = text.lower()
    print(lowered)
    for keyword in Keywords.keyword_list:
        if keyword in lowered:
            return True
        
    for sm_keyword in Keywords.small_keywords:
        if sm_keyword in lowered:
            if lowered.find(sm_keyword) > 0 and lowered.find(sm_keyword)+len(sm_keyword) < len(lowered):
                # ensure that the surrounding characters are not letters
                if lowered[lowered.find(sm_keyword)-1] not in Keywords.normal_characters and lowered[lowered.find(sm_keyword)+len(sm_keyword)] not in Keywords.normal_characters:
                    return True
                
    for keyword in Keywords.file_extension_list:
        # does it match any of the extensions
        if keyword[1:] in lowered:
            to_match = keyword[1:]
            # To ensure we will not go out of bounds of the string when looking for surrounding characters
            if lowered.find(to_match) > 0 and lowered.find(to_match)+len(to_match) < len(lowered):
                # ensure that the surrounding characters are not letters
                if lowered[lowered.find(to_match)-1] not in Keywords.normal_characters and lowered[lowered.find(to_match)+len(to_match)] not in Keywords.normal_characters:
                    return True
    return False
        

def get_urls(topic, payload):
    http = []
    ftp = []
    if has_keyword(topic):
        http = http_urls(payload)
        ftp = ftp_urls(payload)
    elif has_keyword(payload):
        http = http_urls(payload)
        ftp = ftp_urls(payload)

    return http + ftp

def main():
    # file that has the mqtt results
    input_folder = config.get_folder("crawler.intermediate_folder")
    # folder to store the results of scrapy 
    output_folder = config.get_folder("crawler.output_folder")

    for file in os.listdir(input_folder):

        file_path = os.path.join(input_folder, file)

        urls = []
        
        print("Starting URL extraction...")

        with open(file_path, "r") as data:
            for line in data:
                if ",pl:" in line:
                    istart = line.find(",pl:")
                    iend = line.find("<|>")
                    topic = line[:istart]
                    payload = line[istart:iend]
                    if len(payload) < 1024:
                        urls = get_urls(topic, payload)
                        og = os.getcwd()
                        os.chdir(config.get_folder("crawler.http_folder"))
                        for url in urls:
                            command = f"scrapy crawl ota-scrape -a \"apkname={file}\" -a \"urls={url}\" -o \"{output_folder}/{file}-urls.json\""
                            print(f"Running command: {command}")
                            subprocess.run(command, shell=True)
                        os.chdir(og)
                    else:
                        # try to process the chunks as the found format
                        subprocess.run(f"python3 bytes_to_file.py {file_path}", shell=True)


if __name__ == "__main__":
    main()