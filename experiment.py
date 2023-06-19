#!/usr/bin/env python3

import asyncio
import itertools
import re
import sys
import time

from collections import defaultdict
from enum import Enum
from pathlib import Path
from typing import Any, TextIO, Union

import click

from rich.console import Group, Console
from rich.live import Live
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from netexp.helpers import LocalHost, RemoteHost, get_host_from_hostname
from netexp.pktgen import Pktgen
from netexp.pktgen.dpdk import DpdkConfig, DpdkPktgen

from set_constants import set_constants

console = Console()

if sys.version_info < (3, 9, 0):
    raise RuntimeError("Python 3.9 or a more recent version is required.")

MAX_ACCEPTABLE_LOSS = 0.001  # Must be in [0, 1).
PKT_SIZES = [64, 128, 256, 512, 1024, 1518]
NFS = ["timeouts"]
DEFAULT_PRECISION = 100_000_000  # in bps (100 Mbps).

CONTROLLER_CMD_ENV = 'LD_LIBRARY_PATH=“/usr/local/lib/:$SDE_INSTALL/lib/”'
CONTROLLER_CMD = "controller_exe $timeout_ms --hw --bench"

P4_COMP_CMD = "build_tools/p4_build.sh"
# NF_DATAPLANE_PATH = # TODO(sadok)


def validate_pcie_dev(
    host: Union[LocalHost, RemoteHost],
    pcie_dev: str,
    log_file: Union[bool, TextIO] = False,
) -> None:
    cmd = ["lspci", "-mm"]

    cmd = host.run_command(cmd, print_command=log_file)
    info = cmd.watch(stdout=log_file, stderr=log_file)

    info = info.split("\n")

    for line in info:
        line = line.split(" ")
        device = line[0]

        if device in pcie_dev:
            return

    print(f'Invalid PCIe device "{pcie_dev}"', file=sys.stderr)
    exit(1)


def get_device_numa_node(
    host: Union[LocalHost, RemoteHost],
    pcie_dev: str,
    log_file: Union[bool, TextIO] = False,
) -> int:
    cmd = ["lspci", "-s", pcie_dev, "-vv"]
    cmd = host.run_command(cmd, print_command=log_file)
    info = cmd.watch(stdout=log_file, stderr=log_file)

    result = re.search(r"NUMA node: (\d+)", info)

    if not result:
        return 0

    assert result
    return int(result.group(1))


def get_all_cpus(
    host: Union[LocalHost, RemoteHost], log_file: Union[bool, TextIO] = False
) -> list[int]:
    cmd = ["lscpu"]
    cmd = host.run_command(cmd, print_command=log_file)
    info = cmd.watch(stdout=log_file, stderr=log_file)

    result = re.search(r"CPU\(s\):\D+(\d+)", info)

    assert result
    total_cpus = int(result.group(1))

    return [x for x in range(total_cpus)]


def get_numa_node_cpus(
    host: Union[LocalHost, RemoteHost],
    node: int,
    log_file: Union[bool, TextIO] = False,
):
    cmd = ["lscpu"]
    cmd = host.run_command(cmd, print_command=log_file)
    info = cmd.watch(stdout=log_file, stderr=log_file)
    info = [line for line in info.split("\n") if "NUMA" in line]

    assert len(info) > 0
    total_nodes_match = re.search(r"\D+(\d+)", info[0])

    assert total_nodes_match
    total_nodes = int(total_nodes_match.group(1))

    if node > total_nodes:
        print(
            f"Requested NUMA node ({node}) >= available nodes ({total_nodes})",
            file=sys.stderr,
        )
        exit(1)

    if total_nodes == 1:
        return get_all_cpus(host, log_file=log_file)

    assert len(info) == total_nodes + 1
    node_info = info[node + 1]

    if "-" in node_info:
        cpus_match = re.search(r"\D+(\d+)\-(\d+)$", node_info)
        assert cpus_match

        min_cpu = int(cpus_match.group(1))
        max_cpu = int(cpus_match.group(2))

        return [cpu for cpu in range(min_cpu, max_cpu + 1)]

    cpus_match = re.search(r"\D+([\d,]+)$", node_info)
    assert cpus_match
    return [int(i) for i in cpus_match.groups(0)[0].split(",")]


def get_pcie_dev_cpus(
    host: Union[LocalHost, RemoteHost],
    pcie_dev: str,
    log_file: Union[bool, TextIO] = False,
) -> list[int]:
    numa = get_device_numa_node(host, pcie_dev, log_file=log_file)
    cpus = get_numa_node_cpus(host, numa, log_file=log_file)
    if log_file is True:
        log_file = sys.stdout

    if log_file:
        log_file.write(f"[*] PCIe={pcie_dev} NUMA={numa} CPUs={cpus}\n")

    return cpus


class Controller:
    config_keys = ["nf"]  # Add any new config keys here.

    State = Enum("State", ["STOP", "WARMUP", "SNAPSHOT", "BENCH", "ROLLBACK"])

    next_states = {
        State.STOP: State.WARMUP,
        State.WARMUP: State.SNAPSHOT,
        State.SNAPSHOT: State.BENCH,
        State.BENCH: State.ROLLBACK,
        State.ROLLBACK: State.BENCH,
    }

    def __init__(
        self,
        hostname: str,
        config: dict[str, Any],
        log_file: Union[bool, TextIO] = False,
    ) -> None:
        self.log_file = log_file
        self.config = config
        self._hostname = hostname
        self.controller_path = self.config["paths"]["controller_path"]

        self.config = config

    def compile(self, config: dict[str, Any]) -> None:
        # TODO(sadok): Run SyNAPSE to produce source codes for the controller
        # and the switch.

        # TODO(sadok): Set correct command.
        controller_comp_cmd = f"{self.controller_path}/{CONTROLLER_COMP_CMD}"
        cmd = self.host.run_command(controller_comp_cmd)
        cmd.watch(stdout=self.log_file, stderr=self.log_file)

        # TODO(sadok): Set correct command.
        nf = config["nf"]
        nf_path = f"{NF_DATAPLANE_PATH}/{nf}.p4"
        p4_comp_cmd = f"{self.controller_path}/{P4_COMP_CMD} {nf_path}"
        cmd = self.host.run_command(p4_comp_cmd)
        cmd.watch(stdout=self.log_file, stderr=self.log_file)

        self.controller_cmd = None
        self.controller_state = self.State.STOP

    def start(self, config: dict[str, Any]) -> None:
        # Config must contain all the required keys and nothing else.
        if set(config.keys()) != set(self.config_keys):
            raise ValueError(f"Required config keys: {self.config_keys}")

        self.compile(config)

        cmd = f"{CONTROLLER_CMD_ENV} {self.controller_path}/{CONTROLLER_CMD}"
        # TODO(sadok): Use config["nf"] to set the right NF.

        self.controller_cmd = self.host.run_command(
            cmd, dir=dir, print_command=self.log_file
        )

        self.controller_state = self.State.WARMUP

    def wait_ready(self) -> State:
        """Wait for the current state to be ready.

        Returns:
            The next state.
        """
        if self.controller_cmd is None:
            raise RuntimeError("Controller not started")

        output = self.controller_cmd.watch(
            stop_pattern="Press <Enter> to enter .* state",
            stdout=self.log_file,
            stderr=self.log_file,
        )

        for line in output.splitlines():
            match = re.search(
                r"Press <Enter> to enter (?P<state>\w+) state", line
            )
            if match:
                state = match.group("state")
                state = self.State[state.upper()]
                assert state == self.next_states[self.controller_state]
                return state

        raise RuntimeError("Could not find next state")

    def advance_state(self) -> None:
        if self.controller_cmd is None:
            raise RuntimeError("Controller not started")

        self.controller_state = self.next_states[self.controller_state]

        # Send ENTER to controller to advance state.
        self.controller_cmd.send("\n")

    def stop(self) -> None:
        self.controller_state = self.State.STOP

        if self.controller_cmd is None:
            return

        # Send CTRL+C to controller to stop it.
        self.controller_cmd.send("\x03")
        self.controller_cmd.watch(stdout=self.log_file, stderr=self.log_file)
        self.controller_cmd = None

    @classmethod
    def get_config_str(cls, config: dict[str, Any]) -> str:
        return ",".join(str(config[key]) for key in cls.config_keys)

    @classmethod
    def get_config_header(cls) -> str:
        return ",".join(cls.config_keys)

    @property
    def host(self) -> Union[LocalHost, RemoteHost]:
        if self._host is None:
            self._host = get_host_from_hostname(self.hostname)
        return self._host

    @property
    def hostname(self) -> str:
        return self._hostname

    # We had to adapt netexp's function to be able to transition the controller
    # state *after* we start sending packets.
    def zero_loss_throughput(
        self,
        pktgen: Pktgen,
        mean_pkt_size: Union[float, int],
        max_throughput: int = 100_000_000_000,
        precision: int = DEFAULT_PRECISION,
        target_duration: int = 5,
        max_loss: float = MAX_ACCEPTABLE_LOSS,
    ) -> int:
        """Find zero-loss throughput using a binary search.

        This assumes that the DUT is connected to the packet generator and the
        controller's next state is `BENCH`. The DUT should try to send back all
        packets that it receives and should not introduce new ones. The DUT is
        allowed to drop packets if it cannot keep up with the input throughput.

        Args:
            pktgen: Packet generator.
            mean_pkt_size: Mean packet size (in bytes) that will be sent.
            max_throughput: Maximum throughout to try (in bps).
            precision: Throughput precision (in bps).
            target_duration: Target experiment duration (in seconds). The
                number of packets to be sent will be adjusted base on this and
                the current attempted throughput.
            log_file: Log file to write to. If True, write to stdout. If False,
                don't write anything. If a file object, write to it.
            max_loss: Maximum acceptable loss rate, must be in [0, 1).
            cleanup: Function to call to clean up the DUT after every run.

        Returns:
            The zero loss throughput found (in bps).
        """
        log_file = pktgen.log_file

        if log_file is True:
            log_file = sys.stdout

        if not (0 <= max_loss < 1):
            raise ValueError("max_loss must be in [0, 1).")

        self.wait_ready()

        def get_nb_pkts_for_throughput(throughput):
            pps = throughput / ((mean_pkt_size + 20) * 8)
            return int(pps * target_duration)

        tpt_lower = 0  # Lower bound.
        tpt_upper = max_throughput  # Upper bound.

        # We start from the maximum.
        current_throughput = max_throughput

        # We iteratively refine the bounds until the difference between them is
        # less than the specified precision.
        while (tpt_upper - tpt_lower) > precision:
            nb_pkts = get_nb_pkts_for_throughput(current_throughput)

            if log_file:
                tpt_mbps = current_throughput // 1e6
                log_file.write(f"Trying {tpt_mbps} Mbps with {nb_pkts} pkts\n")

            assert self.next_states[self.controller_state] == self.State.BENCH

            pktgen.clean_stats()
            pktgen.start(current_throughput, nb_pkts)

            # Change DUT state to BENCH.
            self.advance_state()

            pktgen.wait_transmission_done()

            nb_rx_pkts = pktgen.get_nb_rx_pkts()

            if nb_rx_pkts > nb_pkts:
                raise RuntimeError(
                    "Received more packets than sent. Unreliable measurement."
                )

            loss = 1 - nb_rx_pkts / nb_pkts
            if loss > max_loss:
                tpt_upper = current_throughput
            else:
                tpt_lower = current_throughput

            current_throughput = (tpt_upper + tpt_lower) // 2

            self.advance_state()
            state = self.wait_ready()
            assert state == self.State.BENCH

        # Found a rate.
        return tpt_lower


class Experiment:
    def __init__(self, name: str, iterations: int) -> None:
        self.name = name
        self.iterations = iterations

    def run(self, step_progress: Progress, current_iter: int) -> None:
        raise NotImplementedError

    def run_many(self, progress: Progress, step_progress: Progress) -> None:
        task_id = progress.add_task("", total=self.iterations, name=self.name)
        for iter in range(self.iterations):
            self.run(step_progress, iter)
            progress.update(task_id, advance=1)

        progress.update(task_id, description="[bold green] done!")


class ThroughputExperiment(Experiment):
    def __init__(
        self,
        name: str,
        iterations: int,
        save_name: Path,
        dut: Controller,
        pktgen: DpdkPktgen,
        pcaps: list[str],
        dut_configs: list[dict[str, Any]],
        precision: int = DEFAULT_PRECISION,
    ) -> None:
        super().__init__(name, iterations)
        self.save_name = save_name
        self.dut = dut
        self.pktgen = pktgen
        self.pcaps = pcaps
        self.dut_configs = dut_configs
        self.precision = precision

        config_header = self.dut.get_config_header()
        header = f"pcaps,{config_header},throughput\n"

        self.experiment_tracker = defaultdict(int)

        # If file exists, continue where we left off.
        if self.save_name.exists():
            with open(self.save_name) as f:
                read_header = f.readline()
                assert header == read_header
                for row in f.readlines():
                    end = row.rfind(",")
                    self.experiment_tracker[row[:end]] += 1
        else:
            with open(self.save_name, "w") as f:
                f.write(header)

    def warmup(self, dut_config: dict[str, Any]) -> None:
        if self.dut.controller_state != Controller.State.STOP:
            self.dut.stop()

        self.dut.start(dut_config)
        state = self.dut.wait_ready()
        assert state == Controller.State.SNAPSHOT

        time.sleep(1)  # TODO(sadok): How to determine when to move on here?

        self.dut.advance_state()
        state = self.dut.wait_ready()
        assert state == Controller.State.BENCH

    def run(self, step_progress: Progress, current_iter: int) -> None:
        experiments = list(
            itertools.product(
                self.pcaps,
                self.dut_configs,
            )
        )

        task_id = step_progress.add_task(self.name, total=len(experiments))

        last_pcap = None
        last_dut_config = None
        for pcap, dut_config in experiments:
            config_str = self.dut.get_config_str(dut_config)
            exp_str = f"{pcap},{config_str}"

            exp_str_with_precision = f"{exp_str},{self.precision}"

            if self.experiment_tracker[exp_str_with_precision] > current_iter:
                console.log(f"[orange1]Skipping: {exp_str_with_precision}")
                step_progress.update(task_id, advance=1)
                continue

            step_progress.update(task_id, description=f"({exp_str})")

            self.pktgen.set_pcap(pcap)

            if pcap != last_pcap or dut_config != last_dut_config:
                self.warmup(dut_config)

            last_pcap = pcap
            last_dut_config = dut_config

            mean_pkt_size = self.pktgen.get_mean_pkt_size()

            throughput = self.dut.zero_loss_throughput(
                self.pktgen, mean_pkt_size, precision=self.precision
            )

            self.dut.stop()

            with open(self.save_name, "a") as f:
                f.write(f"{exp_str_with_precision},{throughput}\n")

            step_progress.update(task_id, advance=1)

        step_progress.update(task_id, visible=False)


class ExperimentTracker:
    def __init__(self) -> None:
        self.overall_progress = Progress(
            TimeElapsedColumn(),
            BarColumn(),
            TimeRemainingColumn(),
            TextColumn("{task.description}"),
        )
        self.experiment_iters_progress = Progress(
            TextColumn("  "),
            TextColumn(
                "[bold blue]{task.fields[name]}: " "{task.percentage:.0f}%"
            ),
            BarColumn(),
            TimeRemainingColumn(),
            TextColumn("{task.description}"),
        )
        self.step_progress = Progress(
            TextColumn("  "),
            TimeElapsedColumn(),
            TextColumn("[bold purple]"),
            BarColumn(),
            TimeRemainingColumn(),
            TextColumn("{task.description}"),
        )
        self.progress_group = Group(
            Group(self.step_progress, self.experiment_iters_progress),
            self.overall_progress,
        )
        self.experiments: list[Experiment] = []

    def add_experiment(self, experiment: Experiment) -> None:
        self.experiments.append(experiment)

    def run_experiments(self):
        with Live(self.progress_group):
            nb_exps = len(self.experiments)
            overall_task_id = self.overall_progress.add_task("", total=nb_exps)

            for i, exp in enumerate(self.experiments):
                description = (
                    f"[bold #AAAAAA]({i} out of {nb_exps} experiments)"
                )
                self.overall_progress.update(
                    overall_task_id, description=description
                )
                exp.run_many(
                    self.experiment_iters_progress, self.step_progress
                )
                self.overall_progress.update(overall_task_id, advance=1)

            self.overall_progress.update(
                overall_task_id, description="[bold green] All done!"
            )


async def load_pktgen(
    pktgen_log_file: TextIO,
    config: dict[str, Any],
) -> DpdkPktgen:
    with console.status("Loading Pktgen NIC"):
        rx_pcie_device = config["devices"]["pktgen"]["rx_dev"]
        tx_pcie_device = config["devices"]["pktgen"]["tx_dev"]

        nb_rx_cores = config["devices"]["pktgen"]["nb_rx_cores"]
        nb_tx_cores = config["devices"]["pktgen"]["nb_tx_cores"]

        max_throughput = config["devices"]["pktgen"]["tx_line_rate"]

        rx_port_nb = 0
        tx_port_nb = 1
        pcie_devices = [rx_pcie_device, tx_pcie_device]

        hostname = config["hosts"]["pktgen"]
        host = get_host_from_hostname(hostname)

        validate_pcie_dev(host, rx_pcie_device, log_file=pktgen_log_file)
        validate_pcie_dev(host, tx_pcie_device, log_file=pktgen_log_file)

        all_cores = get_all_cpus(host, log_file=pktgen_log_file)
        rx_core_candidates = set(
            get_pcie_dev_cpus(host, rx_pcie_device, log_file=pktgen_log_file)
        )
        tx_core_candidates = set(
            get_pcie_dev_cpus(host, tx_pcie_device, log_file=pktgen_log_file)
        )

        if len(rx_core_candidates) < nb_rx_cores:
            raise Exception(
                f"Cannot find {nb_rx_cores} cores for rx on {hostname}"
            )

        # Needs and extra core for the main thread.
        if len(all_cores) < (nb_rx_cores + nb_tx_cores + 1):
            raise Exception(f"Cannot find enough cores on {hostname}")

        rx_cores = list(itertools.islice(rx_core_candidates, nb_rx_cores))

        # Remove rx cores from the set of possible tx cores.
        tx_core_candidates -= set(rx_cores)

        if len(tx_core_candidates) < nb_tx_cores:
            raise Exception(
                f"Cannot find {nb_tx_cores} cores for tx on {hostname}"
            )

        tx_cores = list(itertools.islice(tx_core_candidates, nb_tx_cores))

        remaining_cores = set(all_cores) - set(rx_cores) - set(tx_cores)
        main_core = list(remaining_cores)[0]

        rx_cores_str = "/".join(str(c) for c in rx_cores)
        tx_cores_str = "/".join(str(c) for c in tx_cores)

        rx_map = f"[{rx_cores_str}:].{rx_port_nb}"
        tx_map = f"[:{tx_cores_str}].{tx_port_nb}"

        port_map = f"{rx_map},{tx_map}"

        dpdk_config = DpdkConfig(
            cores=[main_core] + rx_cores + tx_cores,
            mem_channels=config["extra"]["dpdk_mem_channels"],
            proc_type="auto",
            pci_allow_list=pcie_devices,
        )
        pktgen = DpdkPktgen(
            host,
            dpdk_config,
            port_map,
            max_throughput,
            rx_port=rx_port_nb,
            tx_port=tx_port_nb,
            promiscuous=True,
            numa_support=True,
            log_file=pktgen_log_file,
        )

    console.log("[green]Done loading Pktgen")
    return pktgen


async def load_controller(
    controller_log_file: TextIO,
    config: dict[str, Any],
) -> Controller:
    controller_hostname = config["hosts"]["controller"]
    controller = Controller(
        controller_hostname,
        config,
        controller_log_file,
    )
    console.log("[green]Done loading Controller")
    return controller


async def get_experiments(
    data_dir: Path,
    iterations: int,
    controller_log_file: TextIO,
    pktgen_log_file: TextIO,
    config: dict[str, Any],
) -> list[Experiment]:
    load_controller_task = asyncio.create_task(
        load_controller(controller_log_file, config)
    )
    load_pktgen_task = asyncio.create_task(
        load_pktgen(pktgen_log_file, config)
    )

    controller = await load_controller_task
    pktgen = await load_pktgen_task

    pcap_path = config["paths"]["pcap_path"]

    experiments: list[Experiment] = []

    for nf in NFS:
        experiments.append(
            ThroughputExperiment(
                f"{nf} throughput",
                iterations=iterations,
                save_name=data_dir / Path(f"{nf}_throughput.csv"),
                dut=controller,
                pktgen=pktgen,
                pcaps=[
                    f"{pcap_path}/pcap.pcap"  # TODO(sadok): Set pcap here.
                ],
                dut_configs=[
                    {
                        "nf": nf,
                    }
                ],
                precision=DEFAULT_PRECISION,
            ),
        )

    return experiments


@click.command()
@click.argument("data_dir")
@click.option(
    "--filter",
    "-f",
    multiple=True,
    help="Filter experiments by name. Multiple filters are treated as OR.",
)
@click.option(
    "--iters",
    "-i",
    type=int,
    default=1,
    show_default=True,
    help="Number of iterations to run each experiment.",
)
@click.option(
    "--config-file",
    "-c",
    type=click.Path(exists=True),
    default="experiment_config.toml",
    show_default=True,
    help="Path to config file.",
)
def main(
    data_dir,
    filter,
    iters,
    config_file,
):
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    config = set_constants(config_file)

    controller_log_file = open(config["logs"]["controller_log"], "a")
    pktgen_log_file = open(config["logs"]["pktgen_log"], "a")

    experiments = asyncio.run(
        get_experiments(
            data_dir,
            iters,
            controller_log_file,
            pktgen_log_file,
            config,
        )
    )

    exp_tracker = ExperimentTracker()

    for exp in experiments:
        if filter:
            for f in filter:
                if f in exp.name:
                    break
            else:
                continue
        exp_tracker.add_experiment(exp)

    exp_tracker.run_experiments()


if __name__ == "__main__":
    main()
