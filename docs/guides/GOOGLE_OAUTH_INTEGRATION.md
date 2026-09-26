# Google OAuth Integration

This guide configures Google as the OIDC provider for the browser UI.

## Create a Google OAuth client

1. In the Google Cloud Console, configure the OAuth consent screen and add the users who may sign in.
2. Create an OAuth client ID with application type **Web application**.
3. Add the public URL of Dead Man's Switch as an authorized JavaScript origin (for example, `https://switch.example.com`).
4. Add the UI callback URL as an authorized redirect URI (for example, `https://switch.example.com/`). The trailing slash is significant.
5. Copy the OAuth client ID and client secret.

Use HTTPS for any deployment exposed beyond local development.

## Configure the server

Set the Google OAuth client ID as the audience and configure the client secret on the server. Prefer an environment variable or a protected configuration file rather than putting the secret in shell history:

```sh
export DEAD_MANS_SWITCH_AUTH_ENABLED=true
export DEAD_MANS_SWITCH_AUTH_ISSUER_URL=https://accounts.google.com
export DEAD_MANS_SWITCH_AUTH_AUDIENCE='YOUR_CLIENT_ID'
export DEAD_MANS_SWITCH_AUTH_CLIENT_SECRET='YOUR_CLIENT_SECRET'
dead-mans-switch server
```

The equivalent flags are `--auth-enabled`, `--auth-issuer-url`, `--auth-audience`, and `--auth-client-secret`.

During browser sign-in, the UI uses the authorization-code flow with PKCE. It sends the code and PKCE verifier to the server, which redeems them with Google using the configured client secret. The secret is never returned by the auth configuration endpoint or sent to the browser.

Open the server URL and select **Sign in with Google**. The same public URL and trailing slash configured above must be used for the callback.
