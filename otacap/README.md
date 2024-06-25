# OTACap
We build OTACap on top of [IoTFlow](https://github.com/SecPriv/iotflow)'s VSA analysis. We introduce improvements aimed at firmware URL reconstruction
such as Async implicit call handling, extraction of global variables' values by cross references, loop unrolling, support for additional methods in backwards analysis and 
forward simulation.  


## Local
### Requirements
Java 11 installed  
Android SDK installed  
apktool installed  
Z3 installed  


### Build:
cd VSA  
./gradlew build -Dorg.gradle.java.home=/usr/lib/jvm/java-11-openjdk-amd64/  

### Run:
java -Xms5g -Xmx16g -jar VSA/build/libs/IoTScope-1.0-SNAPSHOT-all.jar -d config/endpoints.json -p ~/Android/Sdk/platforms/ -o ./output-jsons/ -t config/taintrules.json -a app.apk -dj dex-tools-2.1/d2j-dex2jar.sh


## Docker
### Run
Inside docker container  
cd otacap  
./run.sh  