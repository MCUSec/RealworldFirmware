#!/bin/bash

# Run MQTT crawler 
cd mqtt
python3 main.py
# Process MQTT messages
cd scripts
python3 extract-urls.py

cd ../..

# Run HTTP Crawler
cd httpftp/source/
python3 run_scrapy.py

cd ..

# Move files to FirmProcessing
cp -r httpftp/results/files/* ../../FirmProcessing/originals