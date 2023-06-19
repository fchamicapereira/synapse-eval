# SyNAPSE Evaluation

## Setup the Testbed

To run the experiments you will need a Tofino switch and a host to be used as a packet generator.

### Setting up the Tofino Switch

### Setting up the Packet Generator

Make sure you can run DPDK Pktgen with the `pktgen` command and that DPDK Pktgen was compiled with Lua support: `meson build -Denable_lua=true`.


## Running the Experiments

To run the experiments first need to set the configuration file. To automatically generate the config file run the following command at the root of the repository:

```bash
./setup.sh
```

This will create a file named `experiment_config.toml` in the root of the repository. Edit this file to according to your setup. The file contains comments explaining each parameter.

You only need to run the setup script once. After that you can run the experiments with the following command:

```bash
./experiment.py DATA_DIR
```

Replace `DATA_DIR` with the directory where you want to store the results.

You may also check other available options with `./experiment.py --help`.

## Producing the Plots

