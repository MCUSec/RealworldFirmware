# FirmFlaw

If you do not want to know the detailed commands, just use the shell script.

```shell
./pipeline.sh <firmware_path>
```

`firmwares_path` is the folder containing the firmwares recognized by our signatures

## Details

The whole process could be seperate into 5 steps, 

0. setup 
1. generate ghidra project and import firmwares
2. generate the FunctionID database
3. generate the SimMatch database
4. run the FunctionID match process
5. run the SimMatch match process

The detail commands of each step will be shown in different sections 

## Docker

The docker image can help you skip the setup process and directly jump to ghidra project creation step.

```shell
# build docker image
docker build -t otacap/FirmFlaw .
# run and link the firmwares folder
docker run -it --name firmflaw -v </path/to/firmwares>:/FirmFlaw/firmwares otacap/firmflaw /bin/bash
```

Change the `</path/to/firmwares>` to where you store the firmwares after process.

## Setup
In this step, we need to setup the environment, mkdir some necessary folders and put the FirmwareURL generated firmwares in the right way.
Our project is based on pyhidra and ghidra, so we need to download them first 

```shell
# install pyhidra 
pip install pyhidra
# download ghidra
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
# unzip it 
unzip ghidra_11.0.3_PUBLIC_20240410.zip
# add to path
export GHIDRA_INSTALL_DIR=./ghidra_11.0.3_PUBLIC
```

Mkdirs
```shell
mkdir logs
# result folder
mkdir res
# SimMatch database folder
mkdir db
# FunctionID database folder
mkdir fidb 
# ghidra projects folder
mkdir ghidra_projects 
# firmwares folder
mkdir firmwares
```

Now you can put all of your firmwares into the `firmwares` folder.

## Ghidra project 

In this part, there are four different ghira projects need to be created
* ARM: the arm firmwares collected by FirmwareURL
* ARM database: self-collected ARM firmwares database used for match
* Xtensa(or esp): the xtensa firmwares collected by FirmwareURL
* Xtensa database: similar

```shell
# create ghidra project and import arm firmwares
# ./firmwares is where you put FimwareURL firmwares
python3 buildProject.py -s ./utils/arm_valid.py ./ghidra_projects arm_bins ./firmwares
# arm database 
python3 buildProject.py ./ghidra_projects arm_db ./match_base/arm
# xtensa firmwares 
python3 buildProject.py -s ./utils/xtensa_valid.py ./ghidra_projects xtensa_bins ./firmwares
# xtensa database
python3 buildProject.py ./ghidra_projects xtensa_db ./match_base/xtensa
```

> Note: -h can be used to check the meaning of differenct parameters, for example python3 buildProject.py -h

## Mitigation

In this part, We will detect the Mitigation usage in firmwares 

```shell
python3 Mitigation.py ./ghidra_projects arm_bins

## FunctionID 

In this part, We will create the FunctionID database and run the match process 

```shell
# create arm FunctionID database
python3 Fid.py -c ./ghidra_projects arm_db arm_db
# search using database
python3 Fid.py -s ./ghidra_projects arm_bins arm_db

# create xtensa FunctionID database
python3 Fid.py -c ./ghidra_projects xtensa_db xtensa_db
# search using database
python3 Fid.py -s ./ghidra_projects xtensa_bins xtensa_db
```

Two files are generated of each search which is placed in `res` directory 

* functionID_xxx.csv: the number of match for each firmware
* functionID_xxx.json: the details - functions and programs been matched

## SimMatch

Similar as before, we need to generate the database and run the match process

```shell
# generate arm database 
python3 MatchDB.py ./ghidra_projects arm_db
# genereate arm bins database
python3 MatchDB.py ./ghidra_projects arm_bins
# Match process 
python3 SimMatch.py ./db/binfunc_arm_bins.db ./db/binfunc_arm_db.db
# genereate xtensa database
python3 MatchDB.py ./ghidra_projects xtensa_db
# genereate xtensa bins database 
python3 MatchDB.py ./ghidra_projects xtensa_bins
# Match process
python3 SimMatch.py ./db/binfunc_xtensa_bins.db ./db/binfunc_xtensa_db.db
```

## Result Generation

In this part, we will generate the library adoption results 

I'm improving the script now.



## TODO

The `esp_ot_br.elf` is larger than 50MB, so it cannot be uploaded to github.
However the number of match result related to this firmware is not significant - SimMatch 102, functionID 1, so currently not upload it.
