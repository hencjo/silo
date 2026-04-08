mod app;
mod cli;
mod codes;
mod config;
mod error;
mod jwt;
mod keys;
mod oidc;
mod remote;
mod server;

use std::sync::Arc;

use app::AppState;
use clap::Parser;
use cli::{Cli, Commands};
use config::ResolvedConfig;
use error::Result;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => run_server(args).await,
        Commands::ClientCredentials(args) => run_client_credentials(args).await,
        Commands::ExampleConfig => run_example_config(),
    }
}

async fn run_server(args: cli::ServeArgs) -> Result<()> {
    let config = ResolvedConfig::from_serve_args(args)?;
    let example_client = config.example_client_credentials_client().cloned();
    let signing_key = keys::load_or_create(&config.key_file).await?;
    let state = Arc::new(AppState::new(config.clone(), signing_key));
    let app = server::build_router(state);

    tracing::info!(listen = %config.listen, issuer = %config.issuer, "starting silo server");
    if !config.authorization_code_enabled() {
        eprintln!("authorization_code flow is disabled");
    }
    if let Some(client) = example_client {
        eprintln!("Run this in a terminal to test:");
        eprintln!(
            "  CLIENT_ID={} CLIENT_SECRET={} silo client_credentials --issuer-url {}",
            client.client_id, client.client_secret, config.issuer
        );
    }

    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn run_client_credentials(args: cli::ClientCredentialsArgs) -> Result<()> {
    let token = remote::fetch_client_credentials_token(args).await?;
    println!("{token}");
    Ok(())
}

fn run_example_config() -> Result<()> {
    print!("{}", config::example_config_yaml());
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tower_http=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};

        if let Ok(mut signal) = signal(SignalKind::terminate()) {
            let _ = signal.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
