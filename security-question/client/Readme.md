# Introduction
This is a bundle of software that can be used to benchmark the security question smart contract.

Please note that the software is made as a benchmarking tool and is not meant to be used in production.

Note: The Benchmarking program will automatically deploy the precompiled smart contract ("SecurityQuestionContract.json") in this folder. If you want to modify the smart contract, you need to modify it in the contract folder and then switch the precompiled version.

# Dependencies
The code relies on the awesome py_ecc repository of the Ethereum project and web3. You will need a blockchain emulator (e.g. ganache) to execute this program.

# Setup
All the tools require Python3 and have dependencies on py_ecc and web3.
* First install Python 3
* Next the dependencies:
  * pip3 install --user git+https://github.com/ethereum/py_ecc.git
  * pip3 install --user web3
  
Now install [Ganache ](https://github.com/trufflesuite/ganache-cli).

# Execution
The program can be executed by following these two steps:
* Start ganache with `ganache-cli --accounts=1000`
* Execute the Benchmarking tool `python3 Benchmark.py`

The program will create a csv file with the execution cost in Dollar.
