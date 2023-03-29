# !/bin/bash
cd tools/
python3 pre_analysis.py

cd ..
./fuzz -g -p -r 2 -d 60 -m 1 -o 0 && chmod +x fuzzMe && ./fuzzMe
