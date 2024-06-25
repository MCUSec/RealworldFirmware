# crawler  

## Run in Docker container  

ollama serve &   
ollama pull llama3 && pip3 install ollama  

After running OTACap:  
cd crawler  
./run.sh  

## Run locally
### Requirements
run in virtual environment python 3.8   
Inside the virtual environment install:  
1. pip3 install scrapy  
2. ollama serve  
3. ollama pull llama3  
4. pip3 install ollama  
3. ollama pull llama3  

cd crawler  
./run.sh  

The `input_folder_path` would tipicaly be the output folder of `otacap`.  