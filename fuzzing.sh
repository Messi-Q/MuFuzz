# !/bin/bash

./fuzz -g -r 2 -d 540 -t 5 -m 1 -o 0 && chmod +x fuzzMe && ./fuzzMe