import os
import sys
import json
import subprocess
from itertools import product

import utility
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import config

def extract_data(file):
    categories_data = {
        "server": [],
        "port": [],
        "username": [],
        "password": [],
        "topic": [],
        "payload": [],
        "client": [],
        "multiple": []
    }

    with open(file) as input:
        data = json.load(input)

    if data:
        vps = data.get("ValuePoints", [])
        for point in vps:
            sink = point.get("Unit", "")
            result_set = point.get("ValueSet", [])
            for category, keywords in utility.sink_cats.items():

                for (keyword, index) in keywords:

                    if keyword in sink:
                        for res_list in result_set:
                            if index in res_list.keys():
                                single_result = res_list[index]
                                for item in single_result:
                                    categories_data[category].append(item) 
                                        
    print("\n ------------ CATEGORIES ---------------")
    print(file)
    print(categories_data)
    return categories_data

def extract_server_port(server_param):
    server_string = server_param.strip()

    port_int = -1
    transport = ""

    if server_string.startswith(("tcp://", "ssl://", "wss://", "ws://")):
        for prefix in ["tcp://", "ssl://", "wss://", "ws://"]:
            if server_string.startswith(prefix):
                server_string = server_string[len(prefix):]
                if prefix == "ws://":
                    port_int = 80
                    transport = "ws"
                elif prefix == "wss://":
                    port_int = 443
                    transport = "ws"


    elif any(prefix in server_string for prefix in ["tcp://", "ssl://", "wss://", "ws://"]):
        for prefix in ["tcp://", "ssl://", "wss://", "ws://"]:
            if prefix in server_string:
                server_string = server_string[server_string.find(prefix) + len(prefix):]
                if prefix == "ws://":
                    port_int = 80
                    transport = "ws"
                elif prefix == "wss://":
                    port_int = 443
                    transport = "ws"

    if ":" in server_string:
        srv = server_string[:server_string.rfind(":")]
        port = server_string[server_string.rfind(":") + 1:]
        try:
            port_int = int(port)
        except ValueError as e:
            print(e)

        if port_int >= 0:
            return srv, port_int, transport
        else:
            return srv, "", transport
    else:
        return server_string, "", transport
        



def clean_password(password):
    if password.strip().startswith("[") and password.strip().endswith("]"):
        return password.strip().replace("[", "").replace("]", "").replace(", ", "")
    else:
        return password
    
def is_in_list(item, list_str):
    if list_str.startswith(item+" ") or " " + item + " " in list_str:
        return True
    return False
                                    
def clean_lists(thelist):
    result = ""
    for item in thelist:
        # Check if the item is not an empty string or that is not in the list already
        if item != "" and not is_in_list(item, result):
            result += item + " "
    return result

def process_file(file):

    default_values = {
        "port": "",
        "client": "",
        "username": "",
        "password": ""
    }

    apk = file[file.rfind("/")+1:]

    data = extract_data(file)
    data_topics = clean_lists(data["topic"])
    data_payloads = clean_lists(data["payload"])

    

    combinations = product(
        list(dict.fromkeys(data["server"])),
        list(dict.fromkeys(data["port"])) or [default_values["port"]],
        list(dict.fromkeys(data["client"])) or [default_values["client"]],
        list(dict.fromkeys(data["username"])) or [default_values["username"]],
        list(dict.fromkeys(data["password"])) or [default_values["password"]]
    )

    for server, port_og, client, user, pwd in combinations:
        if "mosquitto" in server:
            continue
        pwd = clean_password(pwd)
        srv, port, transport = extract_server_port(server)
        command = f"python3 connect-mqtt.py --apk {apk} --server \"{srv}\""
        if port:
            command += f" --port {port}"
        elif port_og:
            command += f" --port {port_og}"
        if client:
            command += f" --client \"{client}\""
        if user:
            command += f" --username \"{user}\""
        if pwd:
            command += f" --password \"{pwd}\""
        command += f" --subtopic {data_topics} --pubtopic {data_topics} --payloads {data_payloads} --transport {transport}"
        print(command)
        subprocess.run(command, shell=True)
        

def main():
    input_dir = config.get_folder("crawler.input_folder")

    for root, subdirs, files in os.walk(input_dir):
        for filename in files:
            file = os.path.join(root, filename)
            process_file(file)

if __name__ == "__main__":
    main()