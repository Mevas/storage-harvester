mod api;
mod cache;
mod collector;
mod config;
mod exporter;
mod registry;
mod scanner;
mod scheduler;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::registry::TargetRegistry;
use crate::scheduler::Scheduler;

#[derive(Debug, Parser)]
struct Args {
    #[arg(
        long,
        env = "STORAGE_HARVESTER_CONFIG",
        default_value = "/etc/storage-harvester/config.yaml"
    )]
    config: PathBuf,

    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    if args.check_config {
        TargetRegistry::from_config(&config)?;
        println!("configuration ok: {} target(s)", config.targets.len());
        return Ok(());
    }

    init_logging(&config.log_level)?;

    let registry = TargetRegistry::from_config(&config)?;
    let store = registry.snapshot_store();
    let _scan_tasks = Scheduler::new(registry.targets().to_vec(), store.clone()).start();
    api::serve(&config, store).await?;

    Ok(())
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}
