# Discord OIDC Provider for Cloudflare Access

Simply put: Allows you to authorise with Cloudflare Access using your Discord account via a Cloudflare Worker. Wraps OIDC around the Discord OAuth2 API to achieve this. The JWT signing key is stored as a Cloudflare Workers Secret (no KV required).

Process flow was inspired by [kimcore/discord-oidc](https://github.com/kimcore/discord-oidc) but rewritten entirely for [Cloudflare Workers](https://workers.cloudflare.com/) and [Hono](https://honojs.dev/).

Some ideas were also taken from [eidam/cf-access-workers-oidc](https://github.com/eidam/cf-access-workers-oidc).

Show them some love!

## Setup

Requirements:
- A Cloudflare Access account - make sure you've gone through the onboarding flow and have a `NAME.cloudflareaccess.com` subdomain.
- A [Discord developer application](https://discord.com/developers/applications) to use for OAuth2.
    - Add a redirect URI `https://YOURNAME.cloudflareaccess.com/cdn-cgi/access/callback` to the Discord application.
- An installation of Node.js 20 or newer.

Steps:
1. Clone the repository and `cd` into it: `git clone https://github.com/Erisa/discord-oidc-worker.git && cd discord-oidc-worker` (or use the included source archive).
2. Install dependencies: `npm install`. This generates `package-lock.json` (the original Wrangler 3 lockfile was removed when upgrading to Wrangler 4).
3. Edit **`wrangler.jsonc`**: set `DISCORD_CLIENT_ID` and `DISCORD_REDIRECT_URI` under `vars`; set `name` if needed. Use exactly the same redirect URI that you registered with Discord.
4. Log in to Cloudflare: `npx wrangler login`.
5. Deploy the Worker once: `npm run deploy`. Until Secrets are configured, the Worker cannot issue ID tokens.
6. Create a signing key **once** and save it directly in a Workers Secret (don't put it in shell history or commit it):
   ```sh
   npm run -s keygen | npx wrangler secret put OIDC_PRIVATE_JWK
   ```
7. Store the Discord OAuth2 client secret:
   ```sh
   npx wrangler secret put DISCORD_CLIENT_SECRET
   ```
8. Run `npm test`. For subsequent deployments, use `npm run deploy`. Neither command generates or changes the signing key.

`wrangler secret put` updates the Worker with a new deployed version. Alternatively, add Secrets in **Workers & Pages → your Worker → Settings → Variables and Secrets**, with type **Secret**. Set `DISCORD_CLIENT_SECRET` and `OIDC_PRIVATE_JWK` before testing authentication.

If upgrading a previously deployed installation, you can preserve the original RSA signing key instead of generating a replacement: read the old KV `keys` entry securely and put its `privateKey` JWK into `OIDC_PRIVATE_JWK`. This keeps the public RSA key stable. Do not delete the old KV namespace until you have verified the new Worker in production. The role Bot Secret retains its original name, `DISCORD_TOKEN`.

There is **no KV namespace** to create, no `config.json` to maintain, and no CI/CD workflow to configure. The RSA private JWK lives only in the Cloudflare Workers Secret named `OIDC_PRIVATE_JWK`. **Preserve that Secret:** regenerating or deleting the key changes the JWKS public key and can invalidate tokens that are still in use. This implementation does not automatically rotate signing keys. Keep a secure backup if recovery of the same signing identity is important.

Cloudflare's recommended split is: **non-sensitive settings in `wrangler.jsonc` `vars`**, and **sensitive values in Worker Secrets** (`wrangler secret put` or the dashboard's **Settings → Variables and Secrets** with type *Secret*). Wrangler's config file is the source of truth for plaintext settings; edits to plaintext variables only in the dashboard can be overwritten by `wrangler deploy`. Secrets are preserved by ordinary deployments. [Cloudflare Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) · [Cloudflare Secrets](https://developers.cloudflare.com/workers/configuration/secrets/).

For local development, copy `.dev.vars.example` to `.dev.vars`, fill in its secret values (including a **separate local signing key** generated with `npm run -s keygen`), and run `npm run dev`. The `.dev.vars` file is gitignored. Do not put secrets in `vars` or `config.json`. Keep production Secrets in Cloudflare and do not copy them into local files.

Wrangler 4 and an up-to-date `compatibility_date` are used here, following [Cloudflare Workers best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/). There is no GitHub Actions workflow; deployments are made manually with Wrangler. The updated dependencies require running `npm install` once to generate a matching lockfile. Do not use the old Wrangler 3 lockfile.

## Usage

- Go to the [Cloudflare Zero Trust dashboard](https://one.dash.cloudflare.com)
- Navigate to Zero Trust > Integrations > Identity providers, select "Add new identity provider", then OpenID Connect.
- Fill the following fields:
    - Name: Whatever you want, e.g. `Discord`
    - App ID: Your Discord application ID.
    - Client secret: Your Discord application OAuth2 secret.
    - Auth URL: `https://discord-oidc.YOURNAME.workers.dev/authorize/email` or swap out `/email` for `/guilds` to include the Guilds scope.
    - Token URL:  `https://discord-oidc.YOURNAME.workers.dev/token`
    - Certificate URL: `https://discord-oidc.YOURNAME.workers.dev/jwks.json`
    - Proof Key for Code Exchange (PKCE): Enabled (the Worker forwards `code_challenge` and `code_verifier` when provided). Verify the complete login flow after setup.
    - OIDC Claims:
        - Email is included automatically without being set here.
        - It would be recommended to add `id` here, as the users unique Discord user ID.
        - `preferred_username` will map to the users username and discrim if they have one e.g. `Erisa#9999` or `erisachu`
        - `name` will map to the non-unique Display Name of the user, or username if there is none. E.g. `Erisa`. Basically a safer form of `global_name`, which might sometimes be null.
        - If the Auth URL is `/guilds` then the `guilds` claim can be used to provide a list of guild IDs.
        - Anything else from here will work: https://discord.com/developers/docs/resources/user#user-object-user-structure
- See the Examples section below for help with constructing policies.

## Usage with roles
- Follow the above setup, making sure to use the `/guilds` auth URL.
- Create a Discord Bot for the OAuth2 application, generate an OAuth2 URL with the `bot` scope and use it to invite the bot to your server.
    - The bot does not need any permissions, it just needs to exist in the server.
- Generate a bot token and register it as a **Worker Secret**:
  ```sh
  npx wrangler secret put DISCORD_TOKEN
  ```
- In `wrangler.jsonc`, add the IDs of the servers for which you want to check roles under `vars`. **Make sure the bot is a member of every listed server**. Separate multiple IDs with commas:
  ```jsonc
  "vars": {
    "DISCORD_CLIENT_ID": "1056005449054429204",
    "DISCORD_REDIRECT_URI": "https://erisa.cloudflareaccess.com/cdn-cgi/access/callback",
    "DISCORD_GUILD_IDS": "438781053675634713"
  }
  ```
- Redeploy the updated plain variables with `npm run deploy`.
- Edit the OIDC provider in Cloudflare Access and add the server IDs as claims prefixed with `roles:`, e.g. `roles:438781053675634713`.
- When creating a policy, reference the `roles:` claims as the name, and use the role ID as the claim value. This will match users in that server who have that role.

This replaces the previous `serversToCheckRolesFor` setting in `config.json`. The optional `DISCORD_GUILD_IDS` is a **non-secret** comma-separated variable; the optional `DISCORD_TOKEN` must be a **Secret**.

## Examples
My setup, as an example:

![](https://up.erisa.uk/firefox_5978jWH1ti.png)
![](https://up.erisa.uk/firefox_9Hzgvt2FiP.png)

To use this in a policy, simply enable it as an Identity provider in your Access application and then create a rule using `OIDC Claims` and the relevant claim above. Make sure the claim has been added to your provider in the steps above.

With roles:

![](https://up.erisa.uk/firefox_rfqxMIRj8t.png)

This example would allow me to access the application if I was myself on Discord or if I was a member of a specific server:
![](https://up.erisa.uk/firefox_1w0BXtk80X.png)

## Security

If you find a security vulnerability in this repository, do NOT create an Issue or Pull Request. Please contact me through email or message (There are links on my GitHub profile). If you create an issue for an active security vulnerability I will save the information and delete the issue.

Alternatively, you can try out a new GitHub feature for Security Advisories: https://github.com/Erisa/discord-oidc-worker/security
