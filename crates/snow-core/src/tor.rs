//! Tor mode (Arti). The client bootstraps once per app run. Every chat gets an
//! isolated circuit, so two chats can't be linked at an exit relay.
//!
//! Arti keeps consensus data and guard state on disk under the directory the
//! app passes in (its private cache dir). That is Tor network metadata, never
//! chat data, and it's what keeps a stable set of guards — the main defense
//! against a hostile relay positioning itself as your entry point.
use crate::net::{io_err, BoxStream, NetError};
use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use std::sync::Arc;
use tor_rtcompat::PreferredRuntime;

#[derive(Clone)]
pub struct TorHandle(Arc<TorClient<PreferredRuntime>>);

impl TorHandle {
    pub async fn bootstrap(dir: &str) -> Result<Self, NetError> {
        let cfg = TorClientConfigBuilder::from_directories(
            format!("{dir}/state"),
            format!("{dir}/cache"),
        )
        .build()
        .map_err(io_err)?;
        let client = TorClient::create_bootstrapped(cfg).await.map_err(io_err)?;
        Ok(Self(client))
    }

    /// A handle that shares the bootstrap but never shares circuits with others.
    pub fn isolated(&self) -> Self {
        Self(self.0.isolated_client())
    }

    pub async fn connect(&self, host: &str, port: u16) -> Result<BoxStream, NetError> {
        let s = self.0.connect((host, port)).await.map_err(io_err)?;
        Ok(Box::new(s))
    }
}
