# !/bin/bash
mkdir source_code clean_souce_code contracts logs branch_msg sFuzz/build

cd sFuzz/build/
cmake ..
cd fuzzer/
make -j 32
cp fuzzer ../../../fuzz

cd ../../../bran/
go build -v -o ../analyse_prefix
