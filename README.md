# cocotbext-fcov examples for DVCon 

This repository provides examples of using the cocotbext-fcov package and aims to aid in understanding the paper titled "Functional Coverage Closure with Python" presented at DVCon US 2024.

For more detailed information, please refer to the paper.

## Installation

```bash
git clone https://github.com/furiosa-ai/dvcon2024-functional-coverage-closure-with-python.git
cd dvcon2024-functional-coverage-closure-with-python
git submodule update --init --recursive 
pip install ./cocotbext-fcov
```

## Quick Start

To generate SystemVerilog coverage

```
cd examples
make coverage.sv
```

To measure functional coverage

```
cd examples
make sim.coverage
```