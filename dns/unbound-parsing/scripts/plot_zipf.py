import argparse
import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


def plot_week_zipf(week_str: str, week_data: pd.DataFrame, output_dir: Path) -> None:
    # Parse week string (e.g., "2025-W45")
    try:
        year_str, week_num_str = week_str.split("-W")
        year = int(year_str)
        week = int(week_num_str)

        # Calculate start (Monday) and end (Sunday) of the ISO week
        start_date = datetime.date.fromisocalendar(year, week, 1)  # 1 = Monday
        end_date = start_date + datetime.timedelta(days=6)  # Sunday
        date_range_str = f"{start_date} to {end_date}"
    except ValueError:
        date_range_str = "Unknown Date Range"

    week_data = week_data.sort_values("rank")

    plt.figure(figsize=(10, 8))

    # Log-log plot
    plt.loglog(
        week_data["rank"],
        week_data["count"],
        marker=".",
        linestyle="None",
        markersize=4,
        alpha=0.6,
        color="tab:blue",
    )

    # Annotate top 10
    top_10 = week_data.iloc[:10]
    for _, row in top_10.iterrows():
        plt.annotate(
            row["fqdn"],
            (row["rank"], row["count"]),
            xytext=(0, -15),  # Shift down
            textcoords="offset points",
            fontsize=8,
            ha="center",  # Horizontal align center
            va="top",  # Vertical align top
            rotation=90,  # Vertical text
            arrowprops=dict(arrowstyle="-", color="gray", alpha=0.5),
        )

    title = f"FQDN Popularity Zipf Plot - {week_str}\n({date_range_str})"
    plt.title(title, fontsize=14)
    plt.xlabel("Rank (log scale)", fontsize=12)
    plt.ylabel("Count (log scale)", fontsize=12)
    plt.grid(True, which="both", ls="-", alpha=0.2)

    output_base = output_dir / f"zipf_plot_{week_str}"
    plt.savefig(f"{output_base}.png")
    plt.savefig(f"{output_base}.pdf")
    print(f"Generated {output_base}.png and .pdf")
    plt.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate weekly Zipf distribution plots from FQDN ranks."
    )
    parser.add_argument(
        "--input",
        dest="input_file",
        type=Path,
        default=Path("../output/weekly_fqdn_ranks.csv"),
        help="Path to input CSV file containing weekly FQDN ranks",
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
    weeks = df["week"].unique()
    for week_str in weeks:
        week_data = df[df["week"] == week_str]
        plot_week_zipf(week_str, week_data, output_dir)


if __name__ == "__main__":
    main()
