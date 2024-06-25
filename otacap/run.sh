#!/bin/bash

# Define the constants
JAR_PATH="VSA/build/libs/IoTScope-1.0-SNAPSHOT-all.jar"
ENDPOINTS_CONFIG="config/combined.json"
PLATFORMS_PATH="../Android/Sdk/platforms/"
OUTPUT_DIR="./output-jsons/"
TAINTRULES_CONFIG="config/taintrules.json"
DEX_TOOLS_PATH="dex_tools_2.1/d2j-dex2jar.sh"
APK_DIR="../apk-dataset"

TIMEOUT_DURATION="1h"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Extract urls from resources
python3 scripts/extract_from_resources.py "$OUTPUT_DIR"

# Loop through each apk file in the dataset folder
for apk_file in "$APK_DIR"/*; do
    if [ -f "$apk_file" ]; then

        # Run VSA analysis
        timeout "$TIMEOUT_DURATION" java -Xms5g -Xmx16g -jar "$JAR_PATH" \
            -d "$ENDPOINTS_CONFIG" \
            -p "$PLATFORMS_PATH" \
            -o "$OUTPUT_DIR" \
            -t "$TAINTRULES_CONFIG" \
            -a "$apk_file" \
            -dj "$DEX_TOOLS_PATH"

        if [ $? -eq 124 ]; then
            echo "VSA analysis for $apk_file timed out"
        fi
    fi
done