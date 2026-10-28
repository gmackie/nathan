-- Optional domain-wide SSO realm for the installation job. Null for legacy
-- installations whose issuer is not login.<domain>.
ALTER TABLE nathan_install_jobs ADD COLUMN realm_apex TEXT;
