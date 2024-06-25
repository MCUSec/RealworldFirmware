#!/bin/bash
set -e

if [ $# -eq 0 ]; then
    echo "Usage: $0 <firmwares_path>"
    #echo "Options:"
    #echo "  -h, --help     Display this help and exit"
    #echo "  -v, --verbose  Enable verbose output"
    #echo "  -f FILE        Specify input file"
    exit 0
fi

red="\033[31m"
green="\033[32m"
reset="\033[0m"

# change the java version for ghidra
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/

# firmware dataset after signature recognition
dir_path=$1

if [ ! -d "$dir_path" ]; then
  echo -e "${red}[ERROR]: $dir_path folder not exist, maybe FirmProcessing fails, exit${reset}"
  exit 1
fi

echo "${green}Build Ghidra Project for ARM firmwares${reset}"
python3 buildProject.py -s ./utils/arm_valid.py ./ghidra_projects arm_bins $dir_path &
pid1=$!

echo "${green}Build Ghidra Project for ARM Database${reset}"
python3 buildProject.py ./ghidra_projects arm_db ./match_base/arm &
pid2=$!

echo "${green}Build Ghidra Project for Xtensa firmwares${reset}"
python3 buildProject.py -s ./utils/xtensa_valid.py ./ghidra_projects xtensa_bins  $dir_path &
pid3=$!

echo "${green}Build Ghidra Project for ARM Database${reset}"
python3 buildProject.py ./ghidra_projects xtensa_db ./match_base/xtensa &
pid4=$!

# Wait for all commands to complete
wait $pid1 $pid2 $pid3 $pid4
