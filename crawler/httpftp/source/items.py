# -*- coding: utf-8 -*-

# Define here the models for your scraped items
#
# See documentation in:
# http://doc.scrapy.org/en/latest/topics/items.html

import scrapy


class QuotesbotItem(scrapy.Item):
    # define the fields for your item here like:
    # name = scrapy.Field()
    pass


class UrlItem(scrapy.Item):
    apk = scrapy.Field()
    name = scrapy.Field()
    ftp_user = scrapy.Field()
    ftp_pwd = scrapy.Field()
    file_urls = scrapy.Field()
    files = scrapy.Field()