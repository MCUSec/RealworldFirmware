#!/bin/bash

echo "Running step 1"
sudo python3 run_step1_convert2bin.py

echo "Running step 2"
python3 run_step2_binsorter.py --enable-firmxray

