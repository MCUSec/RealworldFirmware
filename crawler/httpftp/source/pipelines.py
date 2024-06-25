# -*- coding: utf-8 -*-

# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: http://doc.scrapy.org/en/latest/topics/item-pipeline.html

import hashlib
from scrapy.utils.python import to_bytes
from scrapy.pipelines.files import FilesPipeline

import scrapy
from itemadapter import ItemAdapter

class QuotesbotPipeline(object):
    def process_item(self, item, spider):
        return item

class DownFilesPipeline(FilesPipeline):
    def file_path(self, request, response=None, info=None, item=None): 
        media_guid = hashlib.sha1(to_bytes(request.url)).hexdigest()
        file_name: str = request.url.split("/")[-1] 
        if file_name == '':
            file_name: str = request.url.split("/")[-2] 
        item_name = item["apk"] + "/" + media_guid + "_" + file_name
        return item_name
    
    # def process_item(self, item, spider):
    #     return item
    def get_media_requests(self, item, info):
        adapter = ItemAdapter(item)
        for file_url in adapter["file_urls"]:
            if "ftp_user" in item:
                yield scrapy.Request(file_url, meta={
                    "ftp_user": item["ftp_user"],
                    "ftp_password": item["ftp_pwd"],
                    # "ftp_local_filename": item["name"]
                })
            else:
                yield scrapy.Request(file_url)