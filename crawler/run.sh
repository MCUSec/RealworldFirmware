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
#cp -r httpftp/results/files/* ../../FirmProcessing/originals


if [ "$(ls -A results/files)" ]; then
    echo "Files found, proceeding with copy."
    # Move files to FirmProcessing
    cp -r results/files/* ../../FirmProcessing/originals
else
    echo "No files found, skipping copy."
fi
