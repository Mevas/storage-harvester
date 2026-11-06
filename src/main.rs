mod api;
mod atlas;
#[cfg(target_os = "linux")]
mod btrfs;
mod cache;
mod collector;
mod config;
mod exporter;
mod fsinfo;
mod live;
mod lvm;
mod pictures;
mod registry;
mod scanner;
mod scheduler;
mod synotify;
mod tree;
mod who;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::live::LiveStore;
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
    let host = config.host_name();
    let mut targets = registry.targets().to_vec();
    if !config.live.enabled {
        for target in &mut targets {
            target.live = false;
        }
    }
    let live = LiveStore::new(
        host.clone(),
        &targets,
        &config.host_root,
        config.live.min_relist_interval,
    )?;
    // fanotify names directories by file handle, so those targets' walks record handles.
    for index in live::start_sources(&live, &config.live) {
        targets[index].collect_handles = true;
    }
    let _scan_tasks = Scheduler::new(targets, store.clone(), Arc::clone(&live)).start();
    let info = atlas::Static::new(&config, host);
    api::serve(&config, store, live, info).await?;

    Ok(())
}

fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(level))?;
    tracing_subscriber::fmt().with_env_filter(filter).init();
    Ok(())
}
