pub mod filesystem;

use anyhow::Result;

use crate::config::Target;

pub trait Collector {
    fn collect(&self) -> Result<Vec<Target>>;
}
