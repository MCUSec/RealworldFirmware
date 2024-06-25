#!/bin/bash
set -e

red="\033[31m"
green="\033[32m"
reset="\033[0m"

# change the java version for ghidra
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/

echo "${green}create arm FunctionID database${reset}"
python3 Fid.py -c ./ghidra_projects arm_db arm_db &
pid1=$!

echo "${green}search ARM firmwares using database${reset}"
python3 Fid.py -s ./ghidra_projects arm_bins arm_db &
pid2=$!

echo "${green}create Xtensa FunctionID database${reset}"
python3 Fid.py -c ./ghidra_projects xtensa_db xtensa_db &
pid3=$!

echo "${green}search Xtensa firmwwares using database${reset}"
python3 Fid.py -s ./ghidra_projects xtensa_bins xtensa_db &
pid4=$!

# Wait for all commands to complete
wait $pid1 $pid2 $pid3 $pid4
