import argparse
import datetime
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd


def plot_week(year: int, week: int, group: pd.DataFrame, output_dir: Path) -> None:
    # Determine full week range (Monday to next Monday)
    start_week_date = datetime.date.fromisocalendar(year, week, 1)  # Monday
    end_week_date = start_week_date + datetime.timedelta(days=7)  # Next Monday

    start_ts = pd.Timestamp(start_week_date)
    end_ts = pd.Timestamp(end_week_date)

    # Setup plot (16:9 aspect ratio)
    _fig, ax1 = plt.subplots(figsize=(16, 9))

    # Plot all on primary axis with Log Scale
    ax1.set_yscale("log")
    ax1.set_xlabel("Time (Day Hour)")
    ax1.set_ylabel("Count (Log Scale)", fontweight="bold", fontsize=12)

    # Plot Lines
    l1 = ax1.plot(
        group["datetime"],
        group["request_count"],
        color="tab:blue",
        label="Requests",
        linewidth=2,
    )
    l2 = ax1.plot(
        group["datetime"],
        group["distinct_clients"],
        color="tab:orange",
        label="Distinct Clients",
        linewidth=2,
        linestyle="--",
    )
    l3 = ax1.plot(
        group["datetime"],
        group["distinct_fqdns"],
        color="tab:green",
        label="Distinct FQDNs",
        linewidth=2,
        linestyle="-.",
    )

    # Set X-Axis Limits to full week
    ax1.set_xlim(start_ts, end_ts)

    # Formatting X Axis
    # Show Day and Hour
    ax1.xaxis.set_major_locator(mdates.DayLocator())
    ax1.xaxis.set_major_formatter(mdates.DateFormatter("%a %Y-%m-%d"))
    # Add minor ticks for hours if needed, or just keep days clean for weekly view
    ax1.xaxis.set_minor_locator(mdates.HourLocator(interval=6))

    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha="right")

    # Legend
    lns = l1 + l2 + l3
    labs = [str(line.get_label()) for line in lns]
    ax1.legend(lns, labs, loc="upper left", fontsize=12)

    ax1.grid(True, which="both", alpha=0.3)

    title = f"Week {year}-W{week:02} ({start_week_date} to {end_week_date})"
    plt.title(title, fontsize=16, pad=20)

    plt.tight_layout()
    output_base = output_dir / f"timeseries_week_{year}_W{week:02}"
    plt.savefig(f"{output_base}.png", dpi=100)
    plt.savefig(f"{output_base}.pdf")
    print(f"Generated {output_base}.png and .pdf")
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate weekly timeseries plots from hourly metrics."
    )
    parser.add_argument(
        "--input",
        dest="input_file",
        type=Path,
        default=Path("../output/hourly_metrics.csv"),
        help="Path to input CSV file containing hourly metrics",
        metavar="FILE",
        required=False,
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=Path,
        default=Path("../output"),
        help="Directory where output plots will be saved",
        metavar="DIR",
        required=False,
    )
    args = parser.parse_args()

    input_file: Path = args.input_file
    output_dir: Path = args.output_dir

    if not input_file.exists():
        print(f"Error: {input_file} not found.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(input_file)
    df["datetime"] = pd.to_datetime(df["timestamp_hour"], unit="s")

    df["iso_year"] = df["datetime"].dt.isocalendar().year
    df["iso_week"] = df["datetime"].dt.isocalendar().week

    grouped = df.groupby(["iso_year", "iso_week"])
    for (year, week), group in grouped:
        group = group.sort_values("datetime")
        if group.empty:
            continue
        plot_week(year, week, group, output_dir)


if __name__ == "__main__":
    main()
