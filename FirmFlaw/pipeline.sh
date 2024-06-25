#!/bin/bash
set -e

green="\033[32m"
reset="\033[0m"

if [ $# -eq 0 ]; then
    echo "Usage: $0 <firmware_path>"
    #echo "Options:"
    #echo "  -h, --help     Display this help and exit"
    #echo "  -v, --verbose  Enable verbose output"
    #echo "  -f FILE        Specify input file"
    exit 0
fi

# prepare environments 
./prepare.sh

# build 
echo "${green}Build Ghidra Projects${reset}"
./build.sh $1

# Mitigation Method check
echo "${green}Mitigation Metchod Detection process${reset}"
python3 Mitigation.py ./ghidra_projects arm_bins

# FunctionID
echo "${green}Library Match using FunctionID${reset}"
./FunctionID.sh

# SimMatch 
echo "${green}Library Match Using SimMatch${reset}"
./SimMatch.sh


# generate results
echo "${green}Generate Final Results${reset}"
python3 ResGen.py


echo "${green}Finish, please check ./res/results.md"
