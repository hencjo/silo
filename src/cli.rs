use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

const ROOT_ABOUT: &str =
    "NILOO: niloo is local only openid. Local OpenID mock backend with a browser login flow and a remote client_credentials mode.";
const ROOT_AFTER_HELP: &str = "\
Examples:
  niloo serve --port 9799 --config-file config.yaml
  CLIENT_ID=sub1 CLIENT_SECRET=client_secret niloo client_credentials --issuer-url http://localhost:9799/Niloo
  niloo example-config > config.yaml";

const SERVE_AFTER_HELP: &str = "\
Precedence:
  --port overrides PORT.
  --config-file is required and CLI-only.
  --sub is optional and CLI-only.
  --key-file is optional and CLI-only.

Behavior:
  --sub selects one configured user automatically for the browser authorization flow.
  Without --sub, the browser flow shows a user chooser page.
  Without --key-file, a temporary PEM file is created outside the project directory.
  For client_credentials, client_id must match a configured sub key.

Config file example:
  subs:
    sub1:
      givenName: Mock
      defaultName: Mock User
      claims:
        groups:
          - admin
    sub2:
      givenName: Admin
      defaultName: Admin User
      claims:
        groups:
          - auditor";

const CLIENT_CREDENTIALS_AFTER_HELP: &str = "\
Environment:
  ISSUER_URL and CLIENT_ID can come from env or be overridden by CLI options.
  CLIENT_SECRET is read from the environment only.

Niloo serve mode:
  client_id must match a configured sub key for client_credentials.

Example:
  CLIENT_ID=sub1 CLIENT_SECRET=client_secret niloo client_credentials --issuer-url http://localhost:9799/Niloo";

#[derive(Debug, Parser)]
#[command(
    name = "niloo",
    version,
    about = ROOT_ABOUT,
    long_about = ROOT_ABOUT,
    after_help = ROOT_AFTER_HELP,
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Run the mock OpenID server", after_help = SERVE_AFTER_HELP)]
    Serve(ServeArgs),
    #[command(
        name = "client_credentials",
        about = "Request a remote client_credentials access token and print it",
        after_help = CLIENT_CREDENTIALS_AFTER_HELP
    )]
    ClientCredentials(ClientCredentialsArgs),
    #[command(about = "Print an example config.yaml to stdout")]
    ExampleConfig,
}

#[derive(Debug, Clone, Args)]
pub struct KeyArgs {
    #[arg(long)]
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ServeArgs {
    #[command(flatten)]
    pub keys: KeyArgs,

    #[arg(long, env = "PORT")]
    pub port: u16,

    #[arg(long)]
    pub config_file: PathBuf,

    #[arg(long)]
    pub sub: Option<String>,
}

#[derive(Debug, Clone, Args)]
pub struct ClientCredentialsArgs {
    #[arg(long, env = "ISSUER_URL")]
    pub issuer_url: String,

    #[arg(long, env = "CLIENT_ID")]
    pub client_id: String,

    #[arg(long)]
    pub insecure: bool,
}
