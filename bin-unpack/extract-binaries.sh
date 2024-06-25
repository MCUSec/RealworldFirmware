#!/bin/bash

# Specify the input and output directories
input_folder="../apk-dataset-extracted"
abs_input_folder="$(cd "$input_folder"; pwd)"
output_folder="fw_images"

# Loop through each folder ending with "apk/" in the input directory
echo "$input_folder"
COUNTER=1
for apk_folder in "$abs_input_folder"/*/; do
    if [[ "$(basename "$apk_folder")" != "jarFiles" ]]; then
        echo "$apk_folder"
        echo " $COUNTER "
        # Define a list of file formats to search for (case-insensitive)
        file_formats=("hex" "mcs" "int" "ihex" "ihe" "ihe" "ihx" "h80" "h86" "a43" "a90"
        "hxl" "hxh" "h00" "h01" "h02" "h03" "h04" "h05" "h06" "h07" "h08" "h09"
        "h0a" "h0b" "h0c" "h0d" "h0e" "h0f" "h10" "h11" "h12" "h13" "h14"
        "h15" "p00" "p01" "p02" "p03" "p04" "p05" "p06" "p07" "p08"
        "p09" "p0a" "p0b" "p0c" "p0d" "p0e" "p0f" "p10" "p11" "p12" "p13"
        "p14" "p15" "p16" "p17" "p18" "p19" "p1a" "p1b" "p1c" "p1d" "p1e"
        "p1f" "p20" "p21" "p22" "p23" "p24" "p25" "p26" "p27" "p28" "p29"
        "p2a" "p2b" "p2c" "p2d" "p2e" "p2f" "p30" "p31" "p32" "p33" "p34"
        "p35" "p36" "p37" "p38" "p39" "p3a" "p3b" "p3c" "p3d" "p3e" "p3f"
        "p40" "p41" "p42" "p43" "p44" "p45" "p46" "p47" "p48" "p49" "p4a"
        "p4b" "p4c" "p4d" "p4e" "p4f" "p50" "p51" "p52" "p53" "p54" "p55"
        "p56" "p57" "p58" "p59" "p5a" "p5b" "p5c" "p5d" "p5e" "p5f" "p60"
        "p61" "p62" "p63" "p64" "p65" "p66" "p67" "p68" "p69" "p6a" "p6b"
        "p6c" "p6d" "p6e" "p6f" "p70" "p71" "p72" "p73" "p74" "p75" "p76"
        "p77" "p78" "p79" "p7a" "p7b" "p7c" "p7d" "p7e" "p7f" "p80" "p81"
        "p82" "p83" "p84" "p85" "p86" "p87" "p88" "p89" "p8a" "p8b" "p8c"
        "p8d" "p8e" "p8f" "p90" "p91" "p92" "p93" "p94" "p95" "p96" "p97"
        "p98" "p99" "p9a" "p9b" "p9c" "p9d" "p9e" "p9f" "pa0" "pa1" "pa2"
        "pa3" "pa4" "pa5" "pa6" "pa7" "pa8" "pa9" "paa" "pab" "pac" "pad"
        "pae" "paf" "pb0" "pb1" "pb2" "pb3" "pb4" "pb5" "pb6" "pb7" "pb8"
        "pb9" "pba" "pbb" "pbc" "pbd" "pbe" "pbf" "pc0" "pc1" "pc2" "pc3"
        "pc4" "pc5" "pc6" "pc7" "pc8" "pc9" "pca" "pcb" "pcc" "pcd" "pce"
        "pcf" "pd0" "pd1" "pd2" "pd3" "pd4" "pd5" "pd6" "pd7" "pd8" "pd9"
        "pda" "pdb" "pdc" "pdd" "pde" "pdf" "pe0" "pe1" "pe2" "pe3" "pe4"
        "pe5" "pe6" "pe7" "pe8" "pe9" "pea" "peb" "pec" "ped" "pee" "pef"
        "pf0" "pf1" "pf2" "pf3" "pf4" "pf5" "pf6" "pf7" "pf8" "pf9" "pfa"
        "pfb" "pfc" "pfd" "pfe" "pff" "obj" "obl" "obh" "rom" "eep" "bex"
        "s19" "s28" "s37" "s1" "s2" "s3" "s" "sx" "srec" "exo" "mot" "mxt"
        "tek" "cyacd" "cyacd2" "csr" "rsu" "uf2" "bin" "fw" "img" "upg"
        "lpf" "inst" "alp" "hui" "dfu" "dat" "cbn" "upd" "4dh" "fmw" "almpd"
        "gz" "tgz" "bz2" "tbz2" "xz" "rar" "7z" "tar" "zip")

        # Loop through the specified file formats and copy matching files
        for format in "${file_formats[@]}"; do
            find "$apk_folder" -iname "*.$format" -exec rsync --relative {} "$output_folder" \;
        done
    fi
    ((COUNTER++))
done

cp -r fw_images/* ../FirmProcessing/originals
