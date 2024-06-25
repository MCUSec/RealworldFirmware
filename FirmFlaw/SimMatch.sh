#!/bin/bash
set -e

red="\033[31m"
green="\033[32m"
reset="\033[0m"

# change the java version for ghidra
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/

echo "${green}generate arm database${reset}" 
python3 MatchDB.py ./ghidra_projects arm_db &
pid1=$!

echo "${green}genereate arm bins database${reset}"
python3 MatchDB.py ./ghidra_projects arm_bins &
pid2=$!

echo "${green}Match ARM firmwares process${reset}"
python3 SimMatch.py ./db/binfunc_arm_bins.db ./db/binfunc_arm_db.db &
pid3=$!

echo "${green}genereate xtensa database${reset}"
python3 MatchDB.py ./ghidra_projects xtensa_db &
pid4=$!

echo "${green}genereate xtensa bins database${reset}" 
python3 MatchDB.py ./ghidra_projects xtensa_bins &
pid5=$!

echo "${green}Match Xtensa firmware process${reset}"
python3 SimMatch.py ./db/binfunc_xtensa_bins.db ./db/binfunc_xtensa_db.db &
pid6=$!

# Wait for all commands to complete
wait $pid1 $pid2 $pid3 $pid4 $pid5 $pid6
