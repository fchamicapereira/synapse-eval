#!/usr/bin/env python3

import sys
import time

import click

from typing import Optional

if sys.version_info < (3, 9):
    print('This script requires Python 3.9 or higher', file=sys.stderr)
    sys.exit(1)


def get_all_children(pid: int) -> list[int]:
    children = []
    try:
        with open(f'/proc/{pid}/task/{pid}/children', 'r') as f:
            line = f.readline()
    except FileNotFoundError:
        return children

    if not line:
        return children

    children = [int(pid) for pid in line.split()]

    for child in children:
        children.extend(get_all_children(child))

    return children


def get_cpu_ticks(core_id: Optional[int] = None) -> Optional[int]:
    if core_id is None:
        cpu_str = 'cpu '
    else:
        cpu_str = f'cpu{core_id} '

    with open('/proc/stat', 'r') as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith(cpu_str):
            cpu_ticks = line.split()[1:]
            cpu_ticks = sum(int(t) for t in cpu_ticks)
            return cpu_ticks

    return None


def get_process_ticks(pid: int) -> Optional[int]:
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            line = f.readline()
    except FileNotFoundError:
        return None

    if not line:
        return None

    fields = line.split()
    utime = int(fields[13])
    stime = int(fields[14])

    return utime + stime


@click.command()
@click.argument('pid', type=int)
@click.option('--interval', type=float,
              help='Run forever, printing CPU ticks every INTERVAL seconds')
def main(pid: int, interval: Optional[float]) -> None:
    """Print CPU ticks for PID and all its children as well as for all CPUs.
    """
    children = get_all_children(pid)

    def print_ticks() -> None:
        cpu_ticks = get_cpu_ticks()

        if cpu_ticks is None:
            print('Failed to get CPU time', file=sys.stderr)
            sys.exit(1)

        process_ticks = get_process_ticks(pid)

        if process_ticks is None:
            print('Failed to get process CPU time', file=sys.stderr)
            sys.exit(1)

        process_ticks += sum(get_process_ticks(p) or 0 for p in children)

        print(f'{process_ticks},{cpu_ticks}')

    print("process_ticks,cpu_ticks")
    print_ticks()
    while interval:
        time.sleep(interval)
        print_ticks()


if __name__ == "__main__":
    main()
