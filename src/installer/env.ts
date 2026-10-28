export interface InstallerEnv {
  INSTALLER_DB: D1Database;
  PUBLIC_ORIGIN: string;
  CF_OAUTH_CLIENT_ID: string;
  CF_OAUTH_CLIENT_SECRET: string;
  CF_OAUTH_SCOPES: string;
  INSTALLER_ENCRYPTION_KEY: string;
}
