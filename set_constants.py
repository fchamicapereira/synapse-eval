#!/usr/bin/env python3
# Use this script to automatically set helper environment variables based on
# the `experiment_config.toml` file.

from pathlib import Path

import click
import tomli


def set_constants(config_file: Path, print_shell_vars: bool = False) -> dict:
    """Set constants for the experiments."""

    with open(config_file, "rb") as f:
        config = tomli.load(f)

    CONTROLLER_HOSTNAME = config["hosts"]["controller"]
    PKTGEN_HOSTNAME = config["hosts"]["pktgen"]

    if len(CONTROLLER_HOSTNAME) == 0:
        raise RuntimeError(f"Must define hosts.controller in {config_file}")

    if len(PKTGEN_HOSTNAME) == 0:
        raise RuntimeError(f"Must define hosts.pktgen in {config_file}")

    if print_shell_vars:
        print(f"export CONTROLLER_HOSTNAME={CONTROLLER_HOSTNAME}")
        print(f"export PKTGEN_HOSTNAME={PKTGEN_HOSTNAME}")

    PKTGEN_PATH = config["paths"]["pktgen_path"]

    if len(PKTGEN_PATH) == 0:
        raise RuntimeError(f"Must define paths.pktgen_path in {config_file}")

    if print_shell_vars:
        print(f"export PKTGEN_PATH={PKTGEN_PATH}")

    CONTROLLER_PATH = config["paths"]["controller_path"]

    if len(CONTROLLER_PATH) == 0:
        raise RuntimeError(
            f"Must define paths.controller_path in {config_file}")

    if print_shell_vars:
        print(f"export CONTROLLER_PATH={CONTROLLER_PATH}")

    DPDK_MEM_CHANNELS = config["extra"]["dpdk_mem_channels"]

    if print_shell_vars:
        print(f"export DPDK_MEM_CHANNELS={DPDK_MEM_CHANNELS}")

    CONTROLLER_LOG_FILE = config["logs"]["controller_log"]
    PKTGEN_LOG_FILE = config["logs"]["pktgen_log"]

    if print_shell_vars:
        print(f"export CONTROLLER_LOG_FILE={CONTROLLER_LOG_FILE}")
        print(f"export PKTGEN_LOG_FILE={PKTGEN_LOG_FILE}")

    return config


@click.command()
@click.option(
    "--config-file",
    "-c",
    type=click.Path(exists=True),
    default="experiment_config.toml",
    show_default=True,
    help="Path to config file.",
)
def main(config_file) -> None:
    set_constants(config_file, print_shell_vars=True)


if __name__ == "__main__":
    main()
