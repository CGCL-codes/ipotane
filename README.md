[![rustc](https://img.shields.io/badge/rustc-1.50.0+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![python](https://img.shields.io/badge/python-3.9-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/release/python-390/)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

# Ipotane

State-of-the-art asynchronous Byzantine Fault Tolerance (BFT) protocols integrate a partially-synchronous optimistic
path. Their ultimate goal is to match the performance of a
partially-synchronous protocol in favorable situations and that of
a purely asynchronous protocol in unfavorable situations. While
prior works have excelled in favorable situations, they fall short
when conditions are unfavorable. To address these shortcomings,
a recent work, Abraxas (CCS'23), retains stable throughput
in all situations but incurs very high worst-case latency in
unfavorable situations due to slow detection of optimistic path
failures. Another recent work, ParBFT (CCS'23) ensures good
latency in all situations but suffers from reduced throughput
in unfavorable situations due to the use of extra Asynchronous
Binary Agreement (ABA) instances.

To address the above issues, we propose Ipotane, which has been accepted in NDSS'26. The conference version of our paper [PDF version](https://github.com/CGCL-codes/ipotane/blob/main/NDSS2026-Ipotane.pdf) is available in this repository. 

## Environment Setup

You have two options to set up the development environment:

### Option 1: Using Docker (Recommended)

If you prefer not to manually configure the development environment, you can use the provided Dockerfile which includes all necessary dependencies:

```bash
# Build the Docker image
docker build -t ipotane .

# Run the container
docker run -it --name ipotane-dev ipotane /bin/bash
```

The Docker image includes:
- Rust toolchain with nightly version
- RISC-V cross-compilation tools
- All development dependencies (clang, tmux, cmake, etc.)
- Python 3 and other required tools

### Option 2: Manual Setup

Alternatively, you can manually install the required dependencies on your local machine. You'll need:
- Rust (nightly version)
- Clang
- tmux
- Python 3.9+
- Other development tools as specified in the Dockerfile

## Quick Start

### 

Ipotane is written in Rust, but all benchmarking scripts are written in Python and run with [Fabric](http://www.fabfile.org/).
To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:

```
$ git clone https://github.com/CGCL-codes/ipotane
$ cd ipotane/benchmark
$ pip install -r requirements.txt
```

You also need to install Clang (required by rocksdb) and [tmux](https://linuxize.com/post/getting-started-with-tmux/#installing-tmux) (which runs all nodes and clients in the background). Finally, run a local benchmark using fabric:

```
$ fab local
```

This command may take a long time the first time you run it (compiling rust code in `release` mode may be slow) and you can customize a number of benchmark parameters in `fabfile.py`. When the benchmark terminates, it displays a summary of the execution similarly to the one below.

```
Starting local benchmark
Setting up testbed...
Running Ipotane
0 faults
Timeout 1000 ms, Network delay 10000 ms
DDOS attack False
Waiting for the nodes to synchronize...
Running benchmark (30 sec)...
Parsing logs...

-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: 1 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 10,000 tx/s
 Transaction size: 512 B
 Faults: 0 nodes
 Execution time: 31 s

 Consensus timeout delay: 1,000 ms
 Consensus sync retry delay: 10,000 ms
 Consensus max payloads size: 1,000 B
 Consensus min block delay: 0 ms
 Mempool queue capacity: 100,000 B
 Mempool max payloads size: 500,000 B
 Mempool min block delay: 0 ms

 + RESULTS:
 Consensus TPS: 10,020 tx/s
 Consensus BPS: 5,130,155 B/s
 Consensus latency: 6 ms

 End-to-end TPS: 10,000 tx/s
 End-to-end BPS: 5,120,084 B/s
 End-to-end latency: 19 ms
-----------------------------------------
```

## AWS Benchmarks

The following steps will explain that how to run benchmarks on AWS cloud across multiple data centers (WAN).

**1. Set up your AWS credentials**

Set up your AWS credentials to enable programmatic access to your account from your local machine. These credentials will authorize your machine to create, delete, and edit instances on your AWS account programmatically. 

**2. Add your SSH public key to your AWS account**

You must now [add your SSH public key to your AWS account](https://help.AWS.com/document_detail/201472.html). This operation is manual and needs to be repeated for each AWS region that you plan to use. Upon importing your key, AWS requires you to choose a 'name' for your key; ensure you set the same name on all AWS regions. This SSH key will be used by the python scripts to execute commands and upload/download files to your AWS instances. If you don't have an SSH key, you can create one using [ssh-keygen](https://www.ssh.com/ssh/keygen/):

```
ssh-keygen -f ~/.ssh/AWS
```

**3. Configure the testbed**

The file [settings.json](https://github.com/CGCL-codes/ipotane/blob/main/benchmark/settings.json) located in [Ipotane/benchmark](https://github.com/CGCL-codes/ipotane/blob/main/benchmark) contains all the configuration parameters of the testbed to deploy.


**4. Create a testbed**

The AWS instances are orchestrated with [Fabric](http://www.fabfile.org/) from the file [fabfile.py](https://github.com/CGCL-codes/ipotane/blob/main/benchmark/fabfile.py) (located in [ipotane/benchmark](https://github.com/CGCL-codes/ipotane/blob/main/benchmark)) you can list all possible commands as follows:

The command `fab create` creates new AWS instances; open [fabfile.py](https://github.com/CGCL-codes/ipotane/blob/main/benchmark/fabfile.py) and locate the `create` task:

```python
@task
def create(ctx, nodes=2):
    ...
```

The parameter `nodes` determines how many instances to create in _each_ AWS region. That is, if you specified 4 AWS regions as in the example of step 3, setting `nodes=2` will creates a total of 8 machines:

```shell
$ fab create

Creating 8 instances |██████████████████████████████| 100.0%
Waiting for all instances to boot...
Successfully created 8 new instances
```

You can then clone the repo and install rust on the remote instances with `fab install`:

```shell
$ fab install

Installing rust and cloning the repo...
Initialized testbed of 10 nodes
```

**5. Run a benchmark**

```shell
$ fab remote
```

## Project Structure

This project is organized into several modules, each serving a specific purpose in the Byzantine Fault Tolerance (BFT) consensus protocol implementation:

### Core Modules

- **`consensus/`** - Core consensus protocol implementation
  - Contains the main BFT consensus logic including HotStuff, ParBFT, and SMVBA protocols
  - Implements leader election, aggregation, synchronization, and message handling
  - Key files: `core.rs` (main consensus engine), `leader.rs` (leader election), `aggregator.rs` (vote aggregation)

- **`mempool/`** - Transaction mempool management
  - Handles transaction buffering, ordering, and payload management
  - Provides interface between consensus layer and transaction pool
  - Key files: `mempool.rs` (main mempool logic), `core.rs` (transaction processing)

- **`network/`** - Network communication layer
  - Manages TCP connections, message serialization/deserialization
  - Handles peer-to-peer communication between nodes
  - Implements reliable message delivery and connection management

- **`crypto/`** - Cryptographic primitives and services
  - Provides digital signatures, hash functions, and threshold signatures
  - Implements Ed25519 signatures and threshold cryptography support
  - Key components: signature service, key generation, batch verification

- **`store/`** - Persistent storage layer
  - Built on RocksDB for reliable data persistence
  - Provides async read/write operations with notification system
  - Handles block storage, state persistence, and recovery

- **`node/`** - Main node implementation
  - Orchestrates all modules and runs the complete BFT node
  - Handles configuration, initialization, and inter-module communication
  - Entry point: `main.rs` for running a consensus node

### Benchmarking and Testing

- **`benchmark/`** - Performance benchmarking tools
  - Python-based benchmarking framework using Fabric
  - Supports both local and AWS cloud deployments
  - Provides comprehensive performance metrics and analysis
  - Key files: `fabfile.py` (benchmark commands), `local.py` (local testing), `aws/` (cloud deployment)

### Configuration and Build

- **`Cargo.toml`** - Rust workspace configuration defining all modules
- **`dockerfile`** - Docker container setup for consistent development environment
- **`benchmark/settings.json`** - AWS deployment and testing configuration

Each module is designed to be modular and testable, with comprehensive test suites located in the `tests/` directories within each module. The project uses Rust's async/await for high-performance concurrent operations and implements state-of-the-art BFT consensus algorithms.

## License

This software is licensed as [Apache 2.0](./LICENSE).

## Reference

- [ParBFT](https://dl.acm.org/doi/10.1145/3576915.3623101)
- [Jolteon and Ditto](https://arxiv.org/pdf/2106.10362)
- [Abraxas](https://dl.acm.org/doi/abs/10.1145/3576915.3623191)
