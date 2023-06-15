#!/usr/bin/env python3

import copy
import math
import sys

from itertools import cycle
from pathlib import Path
from typing import Any, Callable, Optional

import matplotlib as mpl
import matplotlib.pyplot as plt

import click
import numpy as np

from pubplot import Document

if sys.version_info < (3, 9, 0):
    raise RuntimeError("Python 3.9 or a more recent version is required.")

SYSTEM_NAME = "SyNAPSE"

NFs = {
    "proxy": "Proxy",
    "nat": "NAT",
    "cl": "CL",
    "psd": "PSD",
    "fw": "FW",
    "lb": "LB",
    "hhh": "HHH",
}

HEURISTICS = {
    "max_tpt": "Max. Tpt.",
    "max_cpt": "Max. Comp.",
    "min_cpu": "Min. CPU",
}

acm_acmsmall = {
    'documentclass': 'acmart',
    'document_options': 'acmsmall'
}

inches_per_pt = 1.0 / 72.27
golden_ratio = (1.0 + math.sqrt(5.0)) / 2.0
doc = Document(acm_acmsmall)
width = float(doc.columnwidth)
height = width / golden_ratio
width = width * inches_per_pt
height = height * inches_per_pt * 0.8
figsize = (width, height)

width_third = doc.textwidth / 3
height_third = width_third / golden_ratio
width_third = width_third * inches_per_pt
height_third = height_third * inches_per_pt
figsize_third = (width_third, height_third)

tight_layout_pad = 0.21
linewidth = 2
elinewidth = 0.5
capsize = 1
capthick = 0.5

# This is "colorBlindness::PairedColor12Steps" from R.
# Check others here: https://r-charts.com/color-palettes/#discrete
palette = [
    '#19B2FF',
    '#2ca02c',  # "#32FF00",  # I hate this green, so I changed it... It may
                # not be as color-blind friendly as it was originally but since
                # we also use patterns, it should be fine.
    '#FF7F00',
    '#654CFF',
    '#E51932',
    '#FFBF7F',
    '#FFFF99',
    '#B2FF8C',
    '#A5EDFF',
    '#CCBFFF'
]

hatch_list = ['////////', '-----', '+++++++', '|||||||']

linestyle = [
    (0, (1, 0)),
    (0, (4, 1)),
    (0, (2, 0.5)),
    (0, (1, 0.5)),
    (0, (0.5, 0.5)),
    (0, (4, 0.5, 0.5, 0.5)),
    (0, (3, 1, 1, 1)),
    (0, (8, 1)),
    (0, (3, 1, 1, 1, 1, 1)),
    (0, (3, 1, 1, 1, 1, 1, 1, 1)),
]

prop_cycle = mpl.cycler(color=palette) + mpl.cycler(linestyle=linestyle)

style = {
    # Line styles.
    'axes.prop_cycle': prop_cycle,

    # Grid.
    'grid.linewidth': 0.2,
    'grid.alpha': 0.4,
    'axes.grid': True,
    'axes.axisbelow': True,

    'axes.linewidth': 0.2,

    # Ticks.
    'xtick.major.width': 0.2,
    'ytick.major.width': 0.2,
    'xtick.minor.width': 0.2,
    'ytick.minor.width': 0.2,

    # Font.
    # You can use any of the predefined LaTeX font sizes here as well as
    # "caption", to match the caption size.
    'font.family': 'serif',
    'font.size': doc.footnotesize,
    'axes.titlesize': doc.footnotesize,
    'axes.labelsize': doc.small,
    "figure.labelsize": doc.footnotesize,
    'legend.fontsize': doc.scriptsize,
    'xtick.labelsize': doc.footnotesize,
    'ytick.labelsize': doc.footnotesize,

    'patch.linewidth': 0.2,

    'figure.dpi': 1000,

    'text.usetex': True,

    "text.latex.preamble": """
        \\usepackage[tt=false,type1=true]{libertine}
        \\usepackage[varqu]{zi4}
        \\usepackage[libertine]{newtxmath}
    """,
}


# Apply style globally.
for k, v in style.items():
    mpl.rcParams[k] = v


def bar_subplot(ax, xlabel: str, ylabel: str, data: list[dict],
                xtick_labels: Optional[list] = None,
                width_scale: float = 0.7,
                set_palette: Optional[list[str]] = None,
                set_hatch_list: Optional[list[str]] = None, **kwargs) -> None:
    x = None
    nb_catgs = len(data)
    bar_width = width_scale/nb_catgs  # The width of the bars.
    offset = bar_width * (1 - nb_catgs) / 2

    if set_palette is None:
        set_palette = palette

    if set_hatch_list is None:
        set_hatch_list = hatch_list

    for d, col, hatch in zip(data, cycle(set_palette), cycle(set_hatch_list)):
        if x is None:
            x = np.arange(len(d['values']))  # The xtick_labels locations.

        # Default options.
        options = {
            "fill": False,
            "hatch": hatch,
            "edgecolor": col,
            "error_kw": dict(elinewidth=elinewidth, capsize=capsize,
                             capthick=capthick),
        }
        options.update(kwargs)

        ax.bar(x + offset, d['values'], bar_width, yerr=d['errors'],
               label=d['label'], **options)
        offset += bar_width

    if xlabel is not None:
        ax.set_xlabel(xlabel)
    if ylabel is not None:
        ax.set_ylabel(ylabel)

    if xtick_labels is None:
        ax.set_xticks([])
    else:
        ax.set_xticks(x)
        ax.set_xticklabels(xtick_labels)

    ax.tick_params(axis='both', length=0)
    ax.grid(visible=False, axis='x')


def plot_throughput(data_dir: Path, dest_dir: Path,
                    opts: dict[str, Any]) -> None:
    fig_name = "throughput"
    fig, ax = plt.subplots(1, len(NFs), sharey=True)

    label_to_highlight = HEURISTICS["max_tpt"]

    # TODO(sadok): Replace with real data. #################################
    fig_name += "_mock"
    data = []
    for h in HEURISTICS.values():
        label = f"{SYSTEM_NAME} {h}"
        if label_to_highlight in label:
            label = f"\\textbf{{{label}}}"

        data.append({
            'label': label,
            'values': [100],
            'errors': [1]
        })
    data += [
        {
            'label': 'Lyra',
            'values': [12],
            'errors': [1]
        },
        {
            'label': 'Gallium',
            'values': [5],
            'errors': [1]
        },
    ]
    #######################################################################

    for i, nf in enumerate(NFs):
        bar_subplot(ax[i], "", "", data)

        data_copy = copy.deepcopy(data)
        edge_colors = []
        hatch_list = []
        for d in data_copy:
            if label_to_highlight in d["label"]:
                edge_colors.append("k")
            else:
                edge_colors.append("none")

            hatch_list.append("")

            d["label"] = None
            d["errors"] = None

        bar_subplot(ax[i], "", "", data_copy, set_palette=edge_colors,
                    set_hatch_list=hatch_list, linewidth=1)

        ax[i].set_title(NFs[nf])

    handles, labels = ax[0].get_legend_handles_labels()
    ax[0].set_ylabel("Throughput (Gbps)")

    fig.legend(handles, labels, loc='lower right', ncol=len(data),
               bbox_to_anchor=(0, 0.8, 1, 1))

    my_figsize = (width, height * 0.5)
    fig.set_size_inches(*my_figsize)
    fig.tight_layout(pad=0, rect=(0.0, 0.0, 0.0, 0.8))

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


def plot_latency_cdf(data_dir: Path, dest_dir: Path,
                     opts: dict[str, Any]) -> None:
    fig_name = "latency_cdf"
    fig, ax = plt.subplots(1, len(NFs), sharey=True)

    # label_to_highlight = HEURISTICS["min_cpu"]
    label_to_highlight = None

    max_p99 = 0
    min_p0 = np.inf

    labels = []
    labels += [f"{SYSTEM_NAME} {h}" for h in HEURISTICS.values()]
    labels += ["Lyra", "Gallium"]

    # TODO(sadok): Replace with real data. #############################
    fig_name += "_mock"
    all_data = np.array(
        [
            [4000, 1000],
            [5000, 1200],
            [5500, 1400],
            [6000, 5000],
            [7000, 8000],
            [8000, 2000],
            [9000, 400],
            [10000, 150],
        ]
    )
    all_data = np.array([all_data] * (len(labels) + 2))
    for j in range(len(labels)):
        all_data[j, :, 1] += 5000 * j
    ###################################################################

    for i, nf in enumerate(NFs):
        ax[i].set_title(NFs[nf])

        for j, label in enumerate(labels):
            data = all_data[j]

            x = data[:, 0]  # Bins
            y = data[:, 1]  # Number of elements in each bin.

            # Sort by bins.
            order = x.argsort()
            x = x[order]
            y = y[order]

            # Normalize counters.
            y = y / y.sum()

            cumsum_y = np.cumsum(y)

            # Convert from ns to us.
            x = x / 1e3

            p50 = x[np.searchsorted(cumsum_y, 0.5)]
            p99 = x[np.searchsorted(cumsum_y, 0.99)]
            p99_9 = x[np.searchsorted(cumsum_y, 0.999)]
            p99_99 = x[np.searchsorted(cumsum_y, 0.9999)]

            print(label, "RTT percentiles:")
            print(f"50%: {p50} us")
            print(f"99%: {p99} us")
            print(f"99.9%: {p99_9} us")
            print(f"99.99%: {p99_99} us")
            print()

            linewidth = 1
            if label_to_highlight is not None and label_to_highlight in label:
                label = f"\\textbf{{{label}}}"

            ax[i].plot(x, cumsum_y, linewidth=linewidth, label=label)
            max_p99 = max(max_p99, p99)
            min_p0 = min(min_p0, x[0])

        ax[i].set_xlabel(r"Latency ({\textmu}s)")
        ax[i].set_xlim(0, 12)
        ax[i].set_xticks([0, 5, 10])
        ax[i].tick_params('y', length=0)
        ax[i].tick_params('x', length=0)

    handles, labels = ax[0].get_legend_handles_labels()
    ax[0].set_ylabel("CDF")
    ax[0].set_ylim(0, 1)
    ax[0].set_yticks([0, 0.5, 1])

    fig.legend(handles, labels, loc='lower right', ncol=len(labels),
               bbox_to_anchor=(0, 0.8, 1, 1))

    my_figsize = (width, height * 0.5)
    fig.set_size_inches(*my_figsize)
    fig.tight_layout(pad=0, rect=(0.0, 0.0, 0.0, 0.8))

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


def plot_resources(data_dir: Path, dest_dir: Path, opts: dict) -> None:
    fig_name = "resources"
    fig, ax = plt.subplots(1, len(NFs), sharey=True)

    label_to_highlight = HEURISTICS["max_cpt"]

    # TODO(sadok): Replace with real data. #################################
    fig_name += "_mock"
    data = []
    for h in HEURISTICS.values():
        label = f"{SYSTEM_NAME} {h}"
        if label_to_highlight in label:
            label = f"\\textbf{{{label}}}"

        data.append({
            'label': label,
            'values': [100],
            'errors': [1]
        })
    data += [
        {
            'label': 'Lyra',
            'values': [12],
            'errors': [1]
        },
        {
            'label': 'Gallium',
            'values': [5],
            'errors': [1]
        },
    ]
    #######################################################################

    for i, nf in enumerate(NFs):
        bar_subplot(ax[i], "", "", data)

        data_copy = copy.deepcopy(data)
        edge_colors = []
        hatch_list = []
        for d in data_copy:
            if label_to_highlight in d["label"]:
                edge_colors.append("k")
            else:
                edge_colors.append("none")

            hatch_list.append("")

            d["label"] = None
            d["errors"] = None

        bar_subplot(ax[i], "", "", data_copy, set_palette=edge_colors,
                    set_hatch_list=hatch_list, linewidth=1)

        ax[i].set_title(NFs[nf])

    handles, labels = ax[0].get_legend_handles_labels()
    ax[0].set_ylabel(r"\% Switch Resources")

    fig.legend(handles, labels, loc='lower right', ncol=len(data),
               bbox_to_anchor=(0, 0.8, 1, 1))

    my_figsize = (width, height * 0.5)
    fig.set_size_inches(*my_figsize)
    fig.tight_layout(pad=0, rect=(0.0, 0.0, 0.0, 0.8))

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


def plot_cpu(data_dir: Path, dest_dir: Path, opts: dict[str, Any]) -> None:
    fig_name = "cpu"
    fig, ax = plt.subplots(1, len(NFs), sharey=True)

    label_to_highlight = HEURISTICS["min_cpu"]

    # TODO(sadok): Replace with real data. #################################
    fig_name += "_mock"
    data = []
    for h in HEURISTICS.values():
        label = f"{SYSTEM_NAME} {h}"
        if label_to_highlight in label:
            label = f"\\textbf{{{label}}}"

        data.append({
            'label': label,
            'values': [100],
            'errors': [1]
        })
    data += [
        {
            'label': 'Lyra',
            'values': [12],
            'errors': [1]
        },
        {
            'label': 'Gallium',
            'values': [5],
            'errors': [1]
        },
    ]
    #######################################################################

    for i, nf in enumerate(NFs):
        bar_subplot(ax[i], "", "", data)

        data_copy = copy.deepcopy(data)
        edge_colors = []
        hatch_list = []
        for d in data_copy:
            if label_to_highlight in d["label"]:
                edge_colors.append("k")
            else:
                edge_colors.append("none")

            hatch_list.append("")

            d["label"] = None
            d["errors"] = None

        bar_subplot(ax[i], "", "", data_copy, set_palette=edge_colors,
                    set_hatch_list=hatch_list, linewidth=1)

        ax[i].set_title(NFs[nf])

    handles, labels = ax[0].get_legend_handles_labels()
    ax[0].set_ylabel(r"\% CPU")

    fig.legend(handles, labels, loc='lower right', ncol=len(data),
               bbox_to_anchor=(0, 0.8, 1, 1))

    my_figsize = (width, height * 0.5)
    fig.set_size_inches(*my_figsize)
    fig.tight_layout(pad=0, rect=(0.0, 0.0, 0.0, 0.8))

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


def plot_churn(data_dir: Path, dest_dir: Path, opts: dict[str, Any]) -> None:
    fig_name = "churn"
    xlabel = "Churn (fpm)"
    ylabel = "Throughput (Gbps)"
    xtick_labels = [r"1\,M", r"10\,M", r"100\,M"]

    # TODO(sadok): Replace with real data. #################################
    fig_name += "_mock"
    data = []
    for i, h in enumerate(HEURISTICS.values()):
        label = f"{SYSTEM_NAME} {h}"
        values = [85, 45, 25]
        values = [v - (i * 10) for v in values]

        data.append({
            'label': label,
            'values': values,
            'errors': [1] * len(values)
        })
    #######################################################################

    set_figsize = (width / 2, height / 2)

    fig, ax = plt.subplots()

    bar_subplot(ax, xlabel, ylabel, data, xtick_labels=xtick_labels)

    ax.legend(loc='upper right')

    ax.set_ylim(0, 100)

    fig.set_size_inches(*set_figsize)
    fig.tight_layout(pad=0.1)

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


def plot_solution_time(data_dir: Path, dest_dir: Path,
                       opts: dict[str, Any]) -> None:
    fig_name = "solution_time"
    fig, ax = plt.subplots(1, len(NFs), sharey=True)

    label_to_highlight = HEURISTICS["min_cpu"]

    # TODO(sadok): Replace with real data. #################################
    fig_name += "_mock"
    data = []
    for h in HEURISTICS.values():
        label = f"{SYSTEM_NAME} {h}"
        data.append({
            'label': label,
            'values': [30],
            'errors': [1]
        })
    #######################################################################

    for i, nf in enumerate(NFs):
        bar_subplot(ax[i], "", "", data)

        data_copy = copy.deepcopy(data)
        edge_colors = []
        hatch_list = []
        for d in data_copy:
            if label_to_highlight in d["label"]:
                edge_colors.append("k")
            else:
                edge_colors.append("none")

            hatch_list.append("")

            d["label"] = None
            d["errors"] = None

        bar_subplot(ax[i], "", "", data_copy, set_palette=edge_colors,
                    set_hatch_list=hatch_list, linewidth=1)

        ax[i].set_title(NFs[nf])

    handles, labels = ax[0].get_legend_handles_labels()
    ax[0].set_ylabel("Search Time (s)")

    fig.legend(handles, labels, loc='lower right', ncol=len(data),
               bbox_to_anchor=(0, 0.8, 1, 1))

    my_figsize = (width, height * 0.5)
    fig.set_size_inches(*my_figsize)
    fig.tight_layout(pad=0, rect=(0.0, 0.0, 0.0, 0.8))

    plt.savefig(dest_dir / f"{fig_name}.pdf")

    if opts.get("save_png", False):
        plt.savefig(dest_dir / f"{fig_name}.png")


@click.command()
@click.argument("data_dir")
@click.argument("plot_dir")
@click.option("--pick", help="Plot only the specified plot")
@click.option("--png", is_flag=True, help="Also save plots as PNG")
def main(data_dir, plot_dir, pick, png):
    data_dir = Path(data_dir)
    plot_dir = Path(plot_dir)

    plot_dir.mkdir(parents=True, exist_ok=True)

    opts = {"save_png": png}

    plots: list[Callable[[Path, Path, dict], None]] = []
    if pick is None:
        plots = [
            plot_throughput,
            plot_latency_cdf,
            plot_resources,
            plot_cpu,
            plot_churn,
            plot_solution_time,
        ]
    else:
        function_name = f"plot_{pick}"
        if function_name not in globals():
            raise RuntimeError(f'Can\'t plot "{pick}"')
        plots = [globals()[function_name]]

    for plot in plots:
        plot(data_dir, plot_dir, opts)


if __name__ == "__main__":
    main()
