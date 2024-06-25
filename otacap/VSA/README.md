# Value Set Analysis

* [Dockerized](docker/) analysis, for simpler execution.


Example usage:
```
java -Xms5g -Xmx16g -jar IoTScope.jar -d config/xmpp.json -p ~/Android/Sdk/platforms/ -o /outputPath/ -t config/taintrules.json -a app.apk -dj dex-tools-2.1/d2j-dex2jar.sh
```

IoTScope -a <apk to analyse> -d <description of methods (sources)> -dj <dex2jar path>  -p <Android jar file or platform directory>  -t <taint rule file> [-o <output folder>] [-e <exclusion list file>] [-mb <number of steps it should trace backward>] [-mbc <number of backward context it should create>] [-og [-ogp <output path for dot files>]]  [-tb <Timeout backward tracing in minutes>] [-tf <Timeout forward computation in minutes>] [-do] [-obc]  [-oj]

Required arguments:
-a Apk file to analyze
-d list of signatures to trace
-dj dex2jar analysis path. Dex2Jar can be downloaded from there repository: https://github.com/pxb1988/dex2jar
-p Android jar file path, or Android platforms directory path.
-t taint rule file, a minimal file only contains

Option arguments
-o output folder path
-e list of paths in apk to exclude
-mb maximum steps backward per context
-mbc maximum number of backward context, each branch is an own context
-tb timeout backward in minutes
-tf timeout forward computation in minutes
-do don't overwrite results flag
-obc output backward context to results flag
-oj output jimple flag
-og output the call graph flag
    -ogp output paths for the graphs dot files

If the analysis run out of memory, reduce the number of backward context `-mbc`, and steps back `-mb`, the available memory to the jvm can be controlled via `-Xmx`.

## Building with Gradle and Java 11

` ./gradlew build -Dorg.gradle.java.home=/usr/lib/jvm/java-11-openjdk/`

## Instrumentation Agent
The instrumentation agent is optional. It can add `toString`, `equals`, and `hashCode` methods to classes during the analysis execution. That can help to remove duplicates and reduce the required memory. To execute the value set analysis with the agent add `-javaagent:[path_to_instrumentation_agent.jar]` to the command
