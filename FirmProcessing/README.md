# FirmProcessing: firmware identification pipeline

## Run in docker
After running our crawler  

1. cd /FirmProcessing  
2. ./pipeline.sh  


## Run locally
The scripts assumes 

1. Firmware images are in their respective subdirs inside ```"./originals/"``` folder.
2. FirmXRay compiled project is in the same folder as this project. For example:
```
-Tools
--- FirmProcessing 
--- FirmXRay
--- binwalk
```

3. ghidra.jar has been added to the lib folder in ```FirmXRay``` project.
You can find a precompiled version of ghidra.jar [here]()

4. Inside the ```FirmXRay``` folder
`$ make`

5. Inside the ```binwalk``` folder:
`pip3 install -r requirements.txt`
`python3 setup.py install`



To run step 1:
```
sudo python3 run_step1_convert2bin.py
```
Ru step 2:
```
python3 run_step2_binsorter.py
```

To run the complete execution:
```
bash pipeline.bash
```


```convert2bin.py``` transforms Intel Hex, Motorola S-Record and Cypress (TODO) to binaries and moves them to "./step1_bins/" folder

```binsorter.py``` uses the binwalk interface to evaluate the signature and entropy of the binaries in the "./temp_step1_bins/" folder (copy of step1_bins), the moves the files to the corresponding vendor/architecture folder inside ./step2_postSig, keeping the original folder structure.

The scripts will create the folders, no need to create them before hand (Except for ./originals/ which is the input folder)
