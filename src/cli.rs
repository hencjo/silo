use clap::{Args, Parser, Subcommand};

const ROOT_ABOUT: &str =
    "SILO: Silo is local OpenID. Local OpenID mock backend with a browser login flow and a remote client_credentials mode.";
const ROOT_AFTER_HELP: &str = "\
Examples:
  silo serve --port 9799 --config-file config.yaml
  CLIENT_ID=system-api CLIENT_SECRET=client_secret silo client_credentials --issuer-url http://localhost:9799/Silo
  silo example-config > config.yaml";

const SERVE_AFTER_HELP: &str = "\
Precedence:
  --port overrides PORT.
  --config-file is required and CLI-only.
  --sub is optional and CLI-only.

Behavior:
  --sub selects one configured user automatically for the browser authorization flow.
  Without --sub, the browser flow shows a user chooser page.
  A temporary PEM file is created outside the project directory for each run.
  Any configured client_id may use any flow.

Config file example:
  clients:
    relying-party:
      client_secret: client_secret
    system-api:
      client_secret: client_secret
      givenName: System
      defaultName: System API
      claims:
        groups:
          - admin
  authorization_code:
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

Silo serve mode:
  client_id must match a configured client.

Example:
  CLIENT_ID=system-api CLIENT_SECRET=client_secret silo client_credentials --issuer-url http://localhost:9799/Silo";

#[derive(Debug, Parser)]
#[command(
    name = "silo",
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
pub struct ServeArgs {
    #[arg(long, env = "PORT")]
    pub port: u16,

    #[arg(long)]
    pub config_file: std::path::PathBuf,

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
