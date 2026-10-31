export interface InstallerEnv {
  INSTALLER_DB: D1Database;
  ASSETS: Fetcher;
  PUBLIC_ORIGIN: string;
  CF_OAUTH_CLIENT_ID: string;
  CF_OAUTH_CLIENT_SECRET: string;
  CF_OAUTH_SCOPES: string;
  INSTALLER_ENCRYPTION_KEY: string;
}
