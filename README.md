# MuFuzz

MuFuzz: Sequence-Aware Mutation and Seed Mask Guidance for Blockchain Smart Contract Fuzzing

## Requirements

MuFuzz is executed on Linux (ideally Ubuntu 18.04).

Dependencies: 

* [CMake](https://cmake.org/download/): >=[3.5.1](sFuzz/CMakeLists.txt#L5)
* [Python](https://www.python.org/downloads/): >=3.5（ideally 3.6）
* Go: 1.15
* leveldb
* [Geth & Tools](https://geth.ethereum.org/downloads/)
* solc: 0.4.26
* numpy


## Architecture

```shell
$(MuFuzz)
├── sFuzz
│   ├── fuzzer
│   ├── libfuzzer
│   ├── liboracle
│   └── ...
├── bran
│   └── ...
├── tools
│   ├── requirements.txt
│   └── ...
├── assets
│   ├── ReentrancyAttacker_model.sol
│   ├── ReentrancyAttacker.sol
│   └── ...
├── source_code
│   └── ...
├── clean_source_code
│   └── ...
├── contracts
│   └── ...
├── branch_msg
│   └── ...
├── logs
│   └── ...
├── fuzz
├── initial_.sh
├── rename_src.sh
├── run.sh
└── README.md
```

* `sFuzz`: The basic fuzzing module of MuFuzz
* `bran`: The abstract interpreter for path analysis
* `tools`: The static analysis tools for extracting vulnerability-specific patterns
  * `requirements.txt`：Required python dependencies
* `assets`:
  * `ReentrancyAttacker_model.sol`: The template for constructing an attacker contract
  * `ReentrancyAttacker.sol`: The attacker contract generated based on the template
* `source_code`: Store the source code (`.sol`) of a contract
* `clean_source_code`: Store the clean source code (`.sol`) of a contract
* `contracts/example1`: Store the compiled results of a contract
* `branch_msg`: Store the intermediate representations of a contract
* `logs`: Store the execution report during fuzzing
* `fuzz`: The complied executable fuzzer file (if you want to re-compile a fuzz file, you can refer to the following *complete execution*)


## Quick Start

Rename contract under test
```
./rename_src.sh
```

Execute the fuzzer
```
./run.sh
```


## Complete Execution

- Initialization and Install system dependencies (This step will consume a lot of time.)

```bash
./initial_.sh
```


- Make workspace for the contract in directory `source_code` and `clean_source_code`

```bash
./rename_src.sh
```

- Run MuFuzz

```bash
./run.sh
```

- Note: if you download the boost version >= 1.7.0, you may need to update the ".get_io_service()" (in sFuzz/libp2p/RLPxHandshake.h) to ".get_executor()".


### Parameters Illustration
* -p: prefuzz (path searching)
* -r: report
* -d: duration (fuzzing time)
* -m: mode (1: mask, 0: default) 
* -o: order (1: new sequence, 0: default)


### Dataset
We make all three datasets used in our paper publicly available. [Download](https://drive.google.com/file/d/1h_XYXcKqfKuN7ArsXDwFq52V_mH3GQ5w/view?usp=sharing)
