# -*- coding: utf-8 -*-
from pathlib import Path
import scrapy
import re
import os
import ftplib

from source.items import UrlItem
from source.utility import Keywords

from scrapy.http.response.html import HtmlResponse
from scrapy.http.response.text import TextResponse
from scrapy.http.response import Response

from scrapy.http import Request

import time
import ftplib
import random
import datetime

import ollama
import json

from pathlib import Path

def has_hex_value(str):
        pattern = r"[a-fA-F0-9]{16}"
        match = re.match(pattern, str)
        return bool(match)
    
def hasKeyword(name, ext_only):
    for keyword in Keywords.file_extension_list:
        if name.lower().endswith(keyword) or has_hex_value(name):
            print(f"{name} ^ Has file extension")
            return True
    if not ext_only:
        for keyword in Keywords.keyword_list:
            if keyword in name.lower():
                print(f"{name} ^ Has long keyword")
                return True
            
        for small_keyword in Keywords.small_keywords:
            # does it match any of the small keywords
            if small_keyword in name.lower():
                # To ensure we will not go out of bounds of the string when looking for surrounding characters
                if name.find(small_keyword) > 0 and name.find(small_keyword)+len(small_keyword) < len(name):
                    # ensure that the surrounding characters are not letters
                    if name[name.find(small_keyword)-1] not in Keywords.normal_characters and name[name.find(small_keyword)+len(small_keyword)] not in Keywords.normal_characters:
                        print(f"{name} ^ Has small keyword")
                        return True
                    
        # To include all extensions as keywords
        for keyword in Keywords.file_extension_list:
            # does it match any of the extensions
            if keyword[1:] in name.lower():
                to_match = keyword[1:]
                # To ensure we will not go out of bounds of the string when looking for surrounding characters
                if name.find(to_match) > 0 and name.find(to_match)+len(to_match) < len(name):
                    # ensure that the surrounding characters are not letters
                    if name[name.find(to_match)-1] not in Keywords.normal_characters and name[name.find(to_match)+len(to_match)] not in Keywords.normal_characters:
                        print(f"{name} ^ Has extension as keyword")
                        return True
    print(f"{name} ^ NO keyword")
    return False

def should_exclude_download(name):
    for keyword in Keywords.excluded_extension_list:
        if name.lower().endswith(keyword):
            print(f"{name} ^ Should exclude")
            return True
    print(f"{name} ^ Should NOT exclude")
    return False

def depth(x):
    if type(x) is dict and x:
        return 1 + max(depth(x[a]) for a in x)
    if type(x) is list and x:
        return 1 + max(depth(a) for a in x)
    return 0

class FtpRequest(Request):

    def __init__(self, *args, **kwargs):
        username = kwargs.pop('username_p', None)
        password = kwargs.pop('password_p', None)

        super(FtpRequest, self).__init__(*args, **kwargs)
        
        anon_meta = {'ftp_user': username,
            'ftp_password': password}
        
        self.meta.update(anon_meta)

class OTAScrapeSpider(scrapy.Spider):
    name = "ota-scrape"
    
    def __init__(self, *args, **kwargs):
        apkname = kwargs.pop('apkname') 
        if apkname:
            self.apk = apkname
        urls = kwargs.pop('urls')
        if urls:
            self.start_urls = urls.split(',')
            self.logger.info(self.start_urls)

        super(OTAScrapeSpider, self).__init__(*args, **kwargs)


    def start_requests(self):
        s_url = self.start_urls[0]
        v, info_dict = self.is_ftp(s_url)

        if v:

            download_dir = self.settings['FILES_STORE']
            apk_dir = self.apk

            domain = info_dict.get('domain', None)
            user = info_dict.get('user', None)
            pwd = info_dict.get('pwd', None)
            
            download_from_ftp(domain, user, pwd, os.path.join(download_dir, apk_dir))         
                
        else:
            yield Request(s_url)


    def is_ftp(self, url):
        type1_pattern = r'^ftp://\S+:\S+@'
        type2_pattern = r'^ftp://'

        if re.match(type1_pattern, url):
            print("Type 1 URL (with username and password)")

            # Extracting user, password, and domain
            ftp_parts = re.match(r'^ftp://(.*?):(.*?)@(.*?)/', url)
            if ftp_parts:
                user, pwd, domain = ftp_parts.groups()
            else:
                # Handle invalid format
                return False, {}

            prefix = f"ftp://{user}:{pwd}@{domain}"

            return True, {'user': user, 'pwd': pwd, 'domain': domain, 'prefix': prefix}
        
        elif re.match(type2_pattern, url):
            print("Type 2 URL (without username and password)")

            domain_match = re.match(r'^ftp://(.*?)/', url)
            if domain_match:
                domain = domain_match.group(1)
            else:
                # Handle invalid format
                return False, {}

            prefix = f"ftp://{domain}"

            return True, {'user': None, 'pwd': None, 'domain': domain, 'prefix': prefix}
        return False, {}
            
    def divide_url(self, url):
        path = url
        name = url.split("/")[-1]
        if name == '':
            print("Name is empty: " + url)
            name = url.split("/")[-2]
            page = url
        else:
            page = url.split("/")[-2]

        return path, name, page

    def process_parent(self, parent_url):
        print("---------------- PROCESSING PARENT") 
        folder_requests = []
        v, _ = self.is_ftp(parent_url)
        if not v:
            folders = []

            folders = parent_url.split("/")
            if folders is not None:
                folders.reverse()
                for folder in folders:
                    index = parent_url.rfind(folder) + len(folder)
                    folder_url = parent_url[:index]
                    print(folder_url)
                    if hasKeyword(folder_url, ext_only=False):
                        folder_requests.append(folder_url)
                        #yield Request(folder_url, callback=self.parse)
        return folder_requests

    def parse(self, response):

        print("---------------- PARSING") 
        path, name, page = self.divide_url(response.url)
        parent_url = path[:path.find(name)]

        print(path + ", " +name +", "+page+", "+ parent_url)
        print(self.__dict__)

        requests = []
        bad_type = False
        if 'headers' in response.__dict__:
            if 'Content-Type' in response.__dict__['headers']:
                content_type = response.__dict__['headers']['Content-Type']
                if content_type.startswith(b"text/html") or content_type.startswith(b"application/pdf") or content_type.startswith(b"font/") or content_type.startswith(b"message/") or content_type.startswith(b"image/") or content_type.startswith(b"video/") or content_type.startswith(b"video/") or content_type.startswith(b"audio/"):
                    print(content_type)
                    print("parent: "+ parent_url)
                    bad_type = True
                    requests = self.process_parent(parent_url)
                    for r in requests:
                        yield Request(r, callback=self.parse)

        if not bad_type:
            print("---------------- PROCESSING URL") 
            #Checking if it ends with one of the known extensions
            if name and not should_exclude_download(name) and hasKeyword(name, ext_only = True):
                urlItem = UrlItem()
                urlItem["apk"] = self.apk
                urlItem["name"] = name
                urlItem["file_urls"] = [path]
                # for ftp only
                v, dict = self.is_ftp(path)
                if v:
                    urlItem["ftp_user"] = dict["user"]
                    urlItem["ftp_pwd"] = dict["pwd"]

                print(f"\n\nITEM: {urlItem}")
                yield urlItem

            # it checks if it has one of the 
            if hasKeyword(path, ext_only = False):
                
                if isinstance(response, HtmlResponse):
                    yield from response.follow_all(css="[href]", callback=self.parse)
                    
                elif isinstance(response, TextResponse):

                    regex_ftp = r"[^a-zA-Z0-9]S?FTP|[^a-zA-Z0-9]s?ftp"
                    match = re.search(regex_ftp, response.text)
                    if match:
                        ftp_text = response.text
                        content = '''I have some unstructured text. It might contain information about some FTP sites and their username and password. Can you extract this information from it? If you can, please answer only in JSON valid format (This is extremely important), and do not change the case of the words. Like this: 

{
    "server": "xx",
    "username": "xx",
    "password": "xx"
}

Otherwise, just say no.
'''
                        content += str(ftp_text)
                        print(content)
                        ollama.pull("llama3")
                        answer = ollama.generate(model='llama3', 
                                                prompt= content, 
                                                format= "json",
                                                stream= False)

                        try:

                            download_dir = self.settings['FILES_STORE']
                            apk_dir = self.apk

                            json_result = json.loads(answer['response'])

                            full_download_dir = os.path.join(download_dir, apk_dir)

                            if depth(json_result) == 1:
                            
                                server = json_result.get('server', None)
                                username = json_result.get('username', None)
                                password = json_result.get('password', None)

                                if not download_from_ftp(server, username, password, full_download_dir):
                                    if (password == None or password == '') and (username != None or username != ''):
                                        # use username as password
                                        download_from_ftp(server, username, username, full_download_dir)
                            else:
                                for entry in json_result:
                                    server = entry.get('server', None)
                                    username = entry.get('username', None)
                                    password = entry.get('password', None)

                                    if download_from_ftp(server, username, password, full_download_dir):
                                        break
                                    else:
                                        if (password == None or password == '') and (username != None or username != ''):
                                            # use username as password
                                            if download_from_ftp(server, username, username, full_download_dir):
                                                break
                        except Exception as e:
                            print(e)

                        # recover FTP credentials


                    regex_http = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>\\\",]+|\(([^\s()<>\\\"]+|(\([^\s()<>\\\",]+\)))*\))+(?:\(([^\s()<>\\\",]+|(\([^\s()<>\\\",]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’\\]))"
                    url_list =  [x[0] for x in re.findall(regex_http, response.text)]

                    for url in url_list:
                        if hasKeyword(url, ext_only=False):
                            yield scrapy.Request(url, callback=self.parse)
                        

                elif isinstance(response, Response):
                    # get the root directory where the files are downloaded
                    down_path = self.settings['FILES_STORE']
                    print(down_path)

                    # get the file name from the response headers
                    if 'Content-Disposition' in response.__dict__['headers']:
                        file_name_text = response.__dict__['headers']['Content-Disposition']
                        file_name = file_name_text[file_name_text.find(b"filename=")+len(b"filename="):]
                        file_name_str = file_name.decode("utf-8")

                        if not should_exclude_download(file_name_str) and hasKeyword(file_name_str, ext_only=False):
                            print(file_name_str)

                            # join them both to create the file to store the content of the binary
                            file_path = os.path.join(down_path, self.apk, file_name_str)
                            print(file_path)

                            # create the apk directory for the downloaded files if not created already
                            os.makedirs(os.path.dirname(file_path), exist_ok=True)

                            # save the content of the binary from request header to file in downloaded apk folder
                            with open(file_path, "wb") as out:
                                out.write(response.__dict__['_body'])

                            # Get the json output path
                            attributes_dict = self.settings.attributes['FEEDS'].__dict__['value'].__dict__['attributes']
                            last_accessed_key = list(attributes_dict.keys())[-1]

                            # store the information in the output json file
                            with open(last_accessed_key, "a") as out:
                                out.write(f"[\"{self.apk}\": \"{file_path}\"]\n")

                    elif '_body' in response.__dict__:
                        _, file_name, _ = self.divide_url(response.__dict__['_url'])

                        if hasKeyword(file_name, ext_only=False):

                            _url = response.__dict__['_url']
                            yield scrapy.Request(_url, callback=self.parse)

            self.process_parent(parent_url) 


class FTPConnection(object):
    username = ''
    password = ''
    def __init__(self, host, parser=None):
        self.host = host
        self.failed_attempts = 0
        self.max_attempts = 5
        self.connected = self.stop_when_connected()
        if not self.connected:
            return
        
        if parser is None:
            # try to guess on first access
            self._listfn = None
        elif callable(parser):
            # supply a custom listing parser
            self._listfn = parser
        elif parser == 'mlsd':
            self._listfn = self._list_mlsd
        elif parser == 'unix':
            self._listfn = self._list_unix
        elif parser == 'windows':
            self._listfn = self._list_windows
    
    def _connect(self):
        # attempt an anonymous FTP connection
        global username, password
        self.ftp = ftplib.FTP(self.host, timeout=60)
        if username and password:
            self.ftp.login(username, password)
        elif username:
            self.ftp.login(username, "")
        else:
            self.ftp.login()

    
    def stop_when_connected(self, max_retries=3):
        # continually tries to reconnect ad infinitum
        retries = 0
        while retries < max_retries:
            try:
                self._connect()
                return True
            except ftplib.all_errors:
                time.sleep(5 * random.uniform(0.5, 1.5))
                retries += 1
        return False
    
    def _list(self, path):
        # public fn to get a path listing
        # guesses the format if it's not explicitly set
        try:
            return self._listfn(path)
        #except AttributeError:
        except Exception:
            # self._listfn is not defined;
            # try to guess it
            self._listfn = self._guess_parser(path)
            return self._listfn(path)
    
    def _guess_parser(self, path):
        try:
            lines = []
            self.ftp.retrlines('MLSD %s' % path, lines.append)
            return self._list_mlsd
        except ftplib.all_errors:
            print("Guessing parser: MLSD fail")
        
        # not MLSD, so:
        # get a listing and check a few properties
        dir_in_3rd = lambda line: "<DIR>" in line.split()[2]
        numeric_first_letter = lambda line: line[0] >= '0' and line[0] <= '9'
        unix_first_letter = lambda line: line[0] in 'd-lpsbc'
        
        lines = []
        self.ftp.retrlines('LIST %s' % path, lines.append)
        
        # check for windows
        if (any(map(dir_in_3rd, lines)) and
                all(map(numeric_first_letter, lines))):
            return self._list_windows
        
        # check for unix
        if all(map(unix_first_letter, lines)):
            return self._list_unix
        
        raise RuntimeError("Failed to guess parser.")
    
    # these functions interact with the FTP with no error checking
    # they just take a path and try to return properly-formatted data
    def _list_mlsd(self, path):
        # copy of MLSD impl from Python 3.3 ftplib package that returns
        # listing data in a machine-readable format
        cmd = 'MLSD %s' % path
        lines = []
        self.ftp.retrlines(cmd, lines.append)
        results = []
        for line in lines:
            facts_found, _, name = line.rstrip('\r\n').partition(' ')
            # print()
            # print(name)
            entry = {}
            for fact in facts_found[:-1].split(";"):
                key, _, value = fact.partition("=")
                entry[key.lower()] = value
            results.append((name, entry))
            # print(entry)
        return results
    
    def _list_windows(self, path):
        lines = []
        self.ftp.dir(path, lines.append)
        results = []
        for line in lines:
            fields = line.split()
            name = ' '.join(fields[3:])
            size = -1
            if fields[2].strip() == '<DIR>':
                type_ = 'dir'
            else:
                type_ = 'file'
                size = int(fields[2])
            results.append((name, {'type': type_, 'size': size}))
        return results
    
    def _list_unix(self, path):
        lines = []
        self.ftp.dir(path, lines.append)
        results = []
        for line in lines:
            fields = line.split()
            name = ' '.join(fields[8:])
            size = -1
            if line[0] == 'd':
                type_ = 'dir'
            elif line[0] == '-':
                type_ = 'file'
                size = int(fields[4])
            elif line[0] == 'l':
                continue
            else:
                raise ValueError("Don't know what kind of file I have: %s" % line.strip())
            results.append((name, {'type': type_, 'size': size}))
        return results
    
    # this function actually handles the logic of pulling data
    # it tries a max of max_attempts times
    def process_path(self, path):
        while self.failed_attempts < self.max_attempts:
            try:
                results = self._list(path)
                self.failed_attempts = 0
                return results
            except ftplib.all_errors:
                self.failed_attempts += 1
                self.ftp.close()
                time.sleep(2 * random.uniform(0.5, 1.5))
                self.stop_when_connected()
        
        # if I get here, I never succeeded in getting the data
        self.failed_attempts = 0
        return False
        

def download_from_ftp(domain, user, pwd, local_path):
    downloaded_something = False
    if domain is None:
        return downloaded_something

    links = run_tree_crawl(domain, user, pwd)

    if links:
        with ftplib.FTP(host=domain) as ftpconn:
            if user and pwd:
                ftpconn.login(user=user, passwd=pwd)
            elif user:
                ftpconn.login(user=user, passwd="")
            else:
                ftpconn.login()
        
            for link in links:
                try:
                    downloaded_something = True
                    if not should_exclude_download(link) and hasKeyword(link, ext_only=False):
                        file_path = os.path.join(local_path, link[2:])
                        dir_path = os.path.dirname(file_path)
                        Path(dir_path).mkdir(parents=True, exist_ok=True)
                        with open (file_path, "wb") as file:
                            ftpconn.retrbinary(f"RETR {link}", file.write)
                except ftplib.error_perm as e:
                    print(e)
                except Exception as e:
                    print(e)
    return downloaded_something


# BEGGINING OF FTPTREE CODE

# Recursive building of FTP tree
def crawltree(ftp, tree):
    path = os.path.join(tree['ancestors'], tree['name'])
    results = ftp.process_path(path)
    if results == False:
        return tree
    
    for result in results:
        name = result[0]
        type_ = result[1]['type']
        if type_ == 'file':
            size = int(result[1]['size'])
            tree['children'][name] = {'name': name, 'ancestors': path, 'size': size, 'children': {}}
        elif type_ == 'dir':
            tree['children'][name] = crawltree(ftp, {'name': name, 'ancestors': path, 'size': -1, 'children': {}})
    
    return tree

def get_file_paths(node, current_path="", paths=[]):
    # Concatenate the current node's name to the current path
    current_path = f"{current_path}/{node['name']}" if current_path else node['ancestors'] + node['name']

    # If the node is a file, add its full path to the list of paths
    if 'children' not in node:
        paths.append(current_path)
    elif len(node['children']) == 0:
        paths.append(current_path)
    else:
        # If the node has children, recursively call the function for each child
        for child_name, child_node in node['children'].items():
            get_file_paths(child_node, current_path, paths)
    
    return paths

def run_tree_crawl(domain, user, pwd):
    global username, password
    
    username = user
    password = pwd

    try:
        ftp = FTPConnection(domain)    
        if ftp.connected:
            tree = crawltree(ftp, {'name': '', 'ancestors': '/', 'size': -1, 'children': {}})
            tree['date'] = str(datetime.date.today())

            file_paths = get_file_paths(tree)

            # Print the result
            for path in file_paths:
                print(path)
            
            return file_paths
        else:
            return None
    
    except Exception as e:
        print(e)
        return None

