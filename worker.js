import { Hono } from 'hono'
import { SignJWT, calculateJwkThumbprint, importJWK } from 'jose'

const DISCORD_API = 'https://discord.com/api/v10'
const OIDC_ISSUER = 'https://cloudflare.com' // Preserve the issuer used by the original Worker.
const app = new Hono()

function settings(env) {
  const clientId = env.DISCORD_CLIENT_ID?.trim()
  const redirectUri = env.DISCORD_REDIRECT_URI?.trim()
  if (!clientId || !redirectUri) {
    throw new Error('Missing DISCORD_CLIENT_ID or DISCORD_REDIRECT_URI')
  }
  return { clientId, redirectUri }
}

function guildIds(env) {
  // Comma-delimited Discord guild IDs; empty is fine when role claims are not used.
  return [...new Set((env.DISCORD_GUILD_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean))]
}

async function signingKey(env) {
  // A single, provisioned private JWK replaces KV and runtime key generation.
  // Keep it unchanged across deployments. Never return the private fields in JWKS.
  if (!env.OIDC_PRIVATE_JWK) {
    throw new Error('Missing OIDC_PRIVATE_JWK secret')
  }

  let jwk
  try {
    jwk = JSON.parse(env.OIDC_PRIVATE_JWK)
  } catch {
    throw new Error('OIDC_PRIVATE_JWK must be a JSON Web Key (JWK)')
  }
  if (jwk?.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.d) {
    throw new Error('OIDC_PRIVATE_JWK must contain an RSA private JWK')
  }

  const publicJwk = { kty: 'RSA', n: jwk.n, e: jwk.e }
  const kid = await calculateJwkThumbprint(publicJwk, 'sha256')
  const privateKey = await importJWK(jwk, 'RS256')
  return {
    privateKey,
    kid,
    publicJwk: { ...publicJwk, alg: 'RS256', use: 'sig', kid },
  }
}

app.get('/authorize/:scopemode', (c) => {
  let config
  try {
    config = settings(c.env)
  } catch {
    return c.text('Service not configured.', 503)
  }

  const scopeMode = c.req.param('scopemode')
  const state = c.req.query('state')
  if (c.req.query('client_id') !== config.clientId ||
      c.req.query('redirect_uri') !== config.redirectUri ||
      !['guilds', 'email'].includes(scopeMode) || !state ||
      (c.req.query('response_type') && c.req.query('response_type') !== 'code')) {
    return c.text('Bad request.', 400)
  }

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    response_type: 'code',
    scope: scopeMode === 'guilds' ? 'identify email guilds' : 'identify email',
    state,
    prompt: 'none',
  })
  // Forward PKCE parameters from Cloudflare Access to Discord when present.
  const challenge = c.req.query('code_challenge')
  if (challenge) {
    const method = c.req.query('code_challenge_method') ?? 'plain'
    if (method !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(challenge)) {
      return c.text('Unsupported PKCE challenge.', 400)
    }
    params.set('code_challenge', challenge)
    params.set('code_challenge_method', method)
  }
  return c.redirect(`https://discord.com/oauth2/authorize?${params}`)
})

app.post('/token', async (c) => {
  let config
  try {
    config = settings(c.env)
    if (!c.env.DISCORD_CLIENT_SECRET) throw new Error('Missing DISCORD_CLIENT_SECRET')
    if (!c.env.OIDC_PRIVATE_JWK) throw new Error('Missing OIDC_PRIVATE_JWK')
  } catch {
    return c.text('Service not configured.', 503)
  }

  let code
  let codeVerifier
  try {
    const body = await c.req.parseBody()
    code = body.code
    codeVerifier = body.code_verifier
  } catch {
    return c.text('Bad request.', 400)
  }
  if (typeof code !== 'string' || !code) return c.text('Bad request.', 400)
  if (codeVerifier !== undefined && (typeof codeVerifier !== 'string' || !/^[A-Za-z0-9._~-]{43,128}$/.test(codeVerifier))) {
    return c.text('Bad PKCE verifier.', 400)
  }

  const params = new URLSearchParams({
    client_id: config.clientId,
    client_secret: c.env.DISCORD_CLIENT_SECRET,
    redirect_uri: config.redirectUri,
    code,
    grant_type: 'authorization_code',
    scope: 'identify email',
  })
  if (codeVerifier) params.set('code_verifier', codeVerifier)

  const tokenResponse = await fetch(`${DISCORD_API}/oauth2/token`, {
    method: 'POST',
    body: params,
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  if (!tokenResponse.ok) return c.text('Discord authorization failed.', 400)
  const discordToken = await tokenResponse.json()
  if (!discordToken || typeof discordToken.access_token !== 'string') {
    return c.text('Discord authorization failed.', 400)
  }

  const userResponse = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${discordToken.access_token}` },
  })
  if (!userResponse.ok) return c.text('Unable to fetch Discord user.', 502)
  const user = await userResponse.json()
  if (!user?.verified || !user.id || !user.email) return c.text('Bad request.', 400)

  let guilds = []
  const guildResponse = await fetch(`${DISCORD_API}/users/@me/guilds`, {
    headers: { Authorization: `Bearer ${discordToken.access_token}` },
  })
  if (guildResponse.ok) {
    const guildData = await guildResponse.json()
    if (Array.isArray(guildData)) guilds = guildData.map((guild) => guild.id)
  }

  const roleClaims = {}
  if (c.env.DISCORD_TOKEN) {
    await Promise.all(guildIds(c.env).map(async (guildId) => {
      if (!guilds.includes(guildId)) return
      const response = await fetch(`${DISCORD_API}/guilds/${guildId}/members/${user.id}`, {
        headers: { Authorization: `Bot ${c.env.DISCORD_TOKEN}` },
      })
      if (!response.ok) return // Fail closed: don't grant any role on API errors.
      const member = await response.json()
      if (Array.isArray(member?.roles)) roleClaims[`roles:${guildId}`] = member.roles
    }))
  }

  const preferredUsername = user.discriminator && user.discriminator !== '0'
    ? `${user.username}#${user.discriminator}`
    : user.username
  const { privateKey, kid } = await signingKey(c.env)
  const idToken = await new SignJWT({
    ...user,
    ...roleClaims,
    preferred_username: preferredUsername,
    email: user.email,
    global_name: user.global_name,
    name: user.global_name ?? user.username,
    guilds,
  })
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(OIDC_ISSUER)
    .setAudience(config.clientId)
    .setSubject(String(user.id))
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey)

  c.header('Cache-Control', 'no-store')
  return c.json({ ...discordToken, scope: 'identify email', id_token: idToken })
})

app.get('/jwks.json', async (c) => {
  let key
  try {
    key = await signingKey(c.env)
  } catch {
    return c.text('Signing key not configured.', 503)
  }
  c.header('Cache-Control', 'public, max-age=300')
  return c.json({ keys: [key.publicJwk] })
})

export default app
