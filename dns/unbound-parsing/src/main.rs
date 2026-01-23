use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, Timelike};
use clap::Parser;
use csv::Writer;
use flate2::read::GzDecoder;
use glob::glob;
use log::{info, warn};
use regex::Regex;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Directory containing the gzipped log files
    #[arg(long)]
    log_dir: String,
}

#[derive(Default)]
struct HourlyStats {
    request_count: u64,
    distinct_clients: HashSet<String>,
    distinct_fqdns: HashSet<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let log_pattern_path = Path::new(&args.log_dir).join("*.gz");
    let log_pattern = log_pattern_path
        .to_str()
        .ok_or(anyhow::anyhow!("Invalid path"))?;

    // Compile regex once
    // Pattern: [Timestamp] ... ... ClientIP FQDN ...
    // Example: [1762484726] 1 0 5d0ae7... linkedin.com. A IN
    let log_regex = Regex::new(r"^\[(?P<ts>\d+)\]\s+\S+\s+\S+\s+(?P<ip>\S+)\s+(?P<fqdn>\S+)")
        .context("Failed to compile regex")?;

    // Hour Timestamp -> Stats
    let mut hourly_data: HashMap<i64, HourlyStats> = HashMap::new();

    // Week String (e.g., "2025-W45") -> FQDN -> Count
    let mut weekly_fqdn_counts: HashMap<String, HashMap<String, u64>> = HashMap::new();

    info!("Scanning files matching: {}", log_pattern);

    let paths: Vec<_> = glob(log_pattern)?.filter_map(Result::ok).collect();
    let total_files = paths.len();

    if total_files == 0 {
        warn!("No files found matching '{}'", log_pattern);
        return Ok(());
    }

    for (i, path) in paths.iter().enumerate() {
        if i % 10 == 0 {
            info!("Processing file {}/{}", i + 1, total_files);
        }
        process_file(path, &log_regex, &mut hourly_data, &mut weekly_fqdn_counts)?;
    }

    info!("Finished processing. Writing outputs...");

    std::fs::create_dir_all("output").context("Failed to create output directory")?;

    write_hourly_metrics("output/hourly_metrics.csv", &hourly_data)?;
    write_weekly_ranks("output/weekly_fqdn_ranks.csv", &weekly_fqdn_counts)?;

    Ok(())
}

fn process_file(
    path: &Path,
    regex: &Regex,
    hourly_data: &mut HashMap<i64, HourlyStats>,
    weekly_fqdn_counts: &mut HashMap<String, HashMap<String, u64>>,
) -> Result<()> {
    let file = File::open(path).with_context(|| format!("Failed to open {:?}", path))?;
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let caps = match regex.captures(&line) {
            Some(c) => c,
            None => continue,
        };

        // Named Capture: ip (Client IP)
        let client_ip = &caps["ip"];
        // Named Capture: fqdn (FQDN)
        let fqdn = &caps["fqdn"];

        // Named Capture: ts (Timestamp digits)
        let timestamp_str = &caps["ts"];
        let timestamp_secs: i64 = match timestamp_str.parse() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let dt = DateTime::from_timestamp(timestamp_secs, 0)
            .ok_or(anyhow::anyhow!("Invalid timestamp"))?;

        // 1. Hourly Stats
        // Truncate to hour
        let hour_ts = dt
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap()
            .timestamp();

        let stats = hourly_data.entry(hour_ts).or_default();
        stats.request_count += 1;
        stats.distinct_clients.insert(client_ip.to_string());
        stats.distinct_fqdns.insert(fqdn.to_string());

        // 2. Weekly Stats
        // ISO Week
        let iso_week = dt.iso_week();
        let week_key = format!("{}-W{:02}", iso_week.year(), iso_week.week());

        let week_map = weekly_fqdn_counts.entry(week_key).or_default();
        *week_map.entry(fqdn.to_string()).or_insert(0) += 1;
    }

    Ok(())
}

fn write_hourly_metrics(filename: &str, data: &HashMap<i64, HourlyStats>) -> Result<()> {
    let mut wtr = Writer::from_path(filename)?;
    wtr.write_record([
        "timestamp_hour",
        "human_readable",
        "request_count",
        "distinct_clients",
        "distinct_fqdns",
    ])?;

    let mut sorted_keys: Vec<&i64> = data.keys().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        let stats = &data[key];
        let dt = DateTime::from_timestamp(*key, 0).unwrap(); // Should be safe
        wtr.write_record(&[
            key.to_string(),
            dt.to_rfc3339(),
            stats.request_count.to_string(),
            stats.distinct_clients.len().to_string(),
            stats.distinct_fqdns.len().to_string(),
        ])?;
    }
    wtr.flush()?;
    info!("Written {}", filename);
    Ok(())
}

fn write_weekly_ranks(filename: &str, data: &HashMap<String, HashMap<String, u64>>) -> Result<()> {
    let mut wtr = Writer::from_path(filename)?;
    wtr.write_record(["week", "rank", "fqdn", "count"])?;

    let mut sorted_weeks: Vec<&str> = data.keys().map(|s| s.as_str()).collect();
    sorted_weeks.sort();

    for week in sorted_weeks {
        let fqdn_map = &data[week];
        // Sort by count descending, then by name for stability
        let mut fqdns: Vec<(&String, &u64)> = fqdn_map.iter().collect();
        fqdns.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        for (rank, (fqdn, count)) in fqdns.iter().enumerate() {
            wtr.write_record([week, &(rank + 1).to_string(), fqdn, &count.to_string()])?;
        }
    }
    wtr.flush()?;
    info!("Written {}", filename);
    Ok(())
}
