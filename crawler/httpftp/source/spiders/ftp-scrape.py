import scrapy
from scrapy.http import Request


class FtpSpider(scrapy.Spider):
    name = "ftp-scrape"
    #allowed_domains = ["ftp.mozilla.org"]
    handle_httpstatus_list = [404]

    custom_settings = {
        "FTP_USER": "dension_mobile",
        "FTP_PASSWORD": "hvSDFWew32"
    }

    def update_settings(cls, settings):
        print(f"SETTINGS = {settings}")
        super().update_settings(settings)
        settings.set("SOME_SETTING", "some value", priority="spider")

    def __init__(self, *args, **kwargs):
        print("@@@@@@@@@@@ Is this running? ")
        self.custom_settings = {
            "FTP_USER": "dension_mobile",
            "FTP_PASSWORD": "hvSDFWew32"
        }

        self.update_settings(self, self.custom_settings)

        self.logger.info(self.custom_settings)
        super(FtpSpider, self).__init__(*args, **kwargs)

    def start_requests(self):
        yield Request('ftp://dension_mobile:hvSDFWew32@dension.com/htc/update/update.txt') 

    def parse(self, response):
        print(response.body)