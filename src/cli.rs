use clap::{Args, Parser, Subcommand};

const ROOT_ABOUT: &str =
    "SILO: Silo is local OpenID. Local OpenID mock backend with remote authorization_code and client_credentials helpers.";
const ROOT_AFTER_HELP: &str = "\
Examples:
  silo serve --port 9799 --config-file config.yaml
  CLIENT_ID=relying-party CLIENT_SECRET=client_secret silo authorization_code --issuer-url https://idp.example
  CLIENT_ID=system-api CLIENT_SECRET=client_secret silo client_credentials --issuer-url http://localhost:9799/Silo --scope api.read
  silo example-config > config.yaml";

const SERVE_AFTER_HELP: &str = "\
Precedence:
  --port overrides PORT.
  --config-file is required and CLI-only.
  --sub is optional and CLI-only.

Behavior:
  --sub selects one configured user automatically for the browser authorization flow.
  Without --sub, the browser flow shows a user chooser page.
  A temporary signing key is created for each run unless config sets key_file.
  clients defines authorization_code relying parties.
  client_credentials.clients defines machine clients and scope-gated claims.

Config file example:
  clients:
    relying-party:
      client_secret: client_secret
  client_credentials:
    clients:
      system-api:
        client_secret: client_secret
        scopes:
          api.read:
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
  client_id must match a configured client_credentials client.
  Repeat --scope to request multiple scopes.

Example:
  CLIENT_ID=system-api CLIENT_SECRET=client_secret silo client_credentials --issuer-url http://localhost:9799/Silo --scope api.read";

const AUTHORIZATION_CODE_AFTER_HELP: &str = "\
Environment:
  ISSUER_URL and CLIENT_ID can come from env or be overridden by CLI options.
  CLIENT_SECRET is read from the environment only.

Behavior:
  Silo uses the first free callback port in 8787-8887 and prints the redirect URI on startup.
  Without --scope, Silo requests openid. Repeat --scope to request multiple scopes.
  Interactive mode prints the authorization URL. Use --no-browser to skip opening it automatically.
  Use --non-interactive against a local Silo issuer; --sub selects its mock user.
  --non-interactive conflicts with --no-browser, and --sub requires --non-interactive.

Example:
  CLIENT_ID=relying-party CLIENT_SECRET=client_secret silo authorization_code --issuer-url https://idp.example --scope openid --scope profile";

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
        name = "authorization_code",
        about = "Log in through a remote authorization code flow and print its access token",
        after_help = AUTHORIZATION_CODE_AFTER_HELP
    )]
    AuthorizationCode(AuthorizationCodeArgs),
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
    pub scope: Vec<String>,

    #[arg(long)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Args)]
pub struct AuthorizationCodeArgs {
    #[arg(long, env = "ISSUER_URL")]
    pub issuer_url: String,

    #[arg(long, env = "CLIENT_ID")]
    pub client_id: String,

    #[arg(long)]
    pub scope: Vec<String>,

    #[arg(long)]
    pub insecure: bool,

    #[arg(long)]
    pub no_browser: bool,

    #[arg(long, conflicts_with = "no_browser")]
    pub non_interactive: bool,

    #[arg(long, requires = "non_interactive")]
    pub sub: Option<String>,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Commands};

    #[test]
    fn parses_repeated_client_credentials_scopes() {
        let cli = Cli::try_parse_from([
            "silo",
            "client_credentials",
            "--issuer-url",
            "https://issuer.example",
            "--client-id",
            "system-api",
            "--scope",
            "api.read",
            "--scope",
            "api.write",
        ])
        .unwrap();

        let Commands::ClientCredentials(args) = cli.command else {
            panic!("expected client_credentials command");
        };
        assert_eq!(args.scope, ["api.read", "api.write"]);
    }

    #[test]
    fn parses_authorization_code_options() {
        let cli = Cli::try_parse_from([
            "silo",
            "authorization_code",
            "--issuer-url",
            "https://issuer.example",
            "--client-id",
            "relying-party",
            "--scope",
            "openid",
            "--scope",
            "profile",
            "--no-browser",
        ])
        .unwrap();

        let Commands::AuthorizationCode(args) = cli.command else {
            panic!("expected authorization_code command");
        };
        assert_eq!(args.scope, ["openid", "profile"]);
        assert!(args.no_browser);
        assert!(!args.non_interactive);
    }

    #[test]
    fn parses_non_interactive_authorization_code_sub() {
        let cli = Cli::try_parse_from([
            "silo",
            "authorization_code",
            "--issuer-url",
            "http://localhost:9799/Silo",
            "--client-id",
            "relying-party",
            "--non-interactive",
            "--sub",
            "sub2",
        ])
        .unwrap();

        let Commands::AuthorizationCode(args) = cli.command else {
            panic!("expected authorization_code command");
        };
        assert!(args.non_interactive);
        assert_eq!(args.sub.as_deref(), Some("sub2"));
    }

    #[test]
    fn rejects_sub_without_non_interactive_mode() {
        let error = Cli::try_parse_from([
            "silo",
            "authorization_code",
            "--issuer-url",
            "http://localhost:9799/Silo",
            "--client-id",
            "relying-party",
            "--sub",
            "sub2",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("--non-interactive"));
    }

    #[test]
    fn rejects_non_interactive_with_no_browser() {
        let error = Cli::try_parse_from([
            "silo",
            "authorization_code",
            "--issuer-url",
            "http://localhost:9799/Silo",
            "--client-id",
            "relying-party",
            "--non-interactive",
            "--no-browser",
        ])
        .unwrap_err();

        assert!(error.to_string().contains("cannot be used with"));
    }

    #[test]
    fn rejects_authorization_code_redirect_uri_option() {
        let error = Cli::try_parse_from([
            "silo",
            "authorization_code",
            "--issuer-url",
            "https://issuer.example",
            "--client-id",
            "relying-party",
            "--redirect-uri",
            "http://localhost:9999/callback",
        ])
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("unexpected argument '--redirect-uri'"));
    }
}
