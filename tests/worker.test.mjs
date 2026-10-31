import test, { before } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { importJWK, jwtVerify } from 'jose'
import app from '../worker.js'

let env
let publicKey
before(async () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = privateKey.export({ format: 'jwk' })
  env = {
    DISCORD_CLIENT_ID: '12345',
    DISCORD_CLIENT_SECRET: 'test-discord-secret',
    DISCORD_REDIRECT_URI: 'https://example.cloudflareaccess.com/cdn-cgi/access/callback',
    OIDC_PRIVATE_JWK: JSON.stringify(jwk),
    DISCORD_GUILD_IDS: '111, 222, 111',
    DISCORD_TOKEN: 'bot-token-for-tests',
  }
  publicKey = await importJWK({ kty: jwk.kty, n: jwk.n, e: jwk.e }, 'RS256')
})

function get(path, bindings = env) {
  return app.request(`https://worker.example${path}`, { method: 'GET' }, bindings)
}

function token(bindings = env) {
  return app.request('https://worker.example/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'code=discord-code',
  }, bindings)
}

test('JWKS exposes public RSA parameters only and a stable key ID', async () => {
  const response = await get('/jwks.json')
  assert.equal(response.status, 200)
  const data = await response.json()
  assert.equal(data.keys.length, 1)
  assert.equal(data.keys[0].kty, 'RSA')
  assert.equal(data.keys[0].alg, 'RS256')
  assert.ok(data.keys[0].kid)
  for (const secretPart of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    assert.equal(data.keys[0][secretPart], undefined)
  }
  const again = (await (await get('/jwks.json')).json()).keys[0]
  assert.deepEqual(data.keys[0], again)
})

test('JWKS refuses a missing or malformed private key', async () => {
  assert.equal((await get('/jwks.json', { ...env, OIDC_PRIVATE_JWK: undefined })).status, 503)
  assert.equal((await get('/jwks.json', { ...env, OIDC_PRIVATE_JWK: '{}' })).status, 503)
})

test('authorize validates client and callback, then redirects with guild scope', async () => {
  const params = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    redirect_uri: env.DISCORD_REDIRECT_URI,
    state: 'opaque-state',
  })
  const response = await get(`/authorize/guilds?${params}`)
  assert.equal(response.status, 302)
  const target = new URL(response.headers.get('location'))
  assert.equal(target.hostname, 'discord.com')
  assert.equal(target.searchParams.get('scope'), 'identify email guilds')
  assert.equal(target.searchParams.get('state'), 'opaque-state')
  assert.equal((await get('/authorize/email?client_id=WRONG&redirect_uri=x&state=s')).status, 400)
  assert.equal((await get(`/authorize/email?client_id=${env.DISCORD_CLIENT_ID}&redirect_uri=${encodeURIComponent(env.DISCORD_REDIRECT_URI)}`)).status, 400)
})

test('token issues a verifiable JWT and emits only requested guild roles', async (t) => {
  const requests = []
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (input, options) => {
    const url = String(input)
    requests.push({ url, options })
    if (url.endsWith('/oauth2/token')) {
      return Response.json({ access_token: 'discord-access-token', token_type: 'Bearer' })
    }
    if (url.endsWith('/users/@me')) {
      return Response.json({ id: '999', username: 'tester', discriminator: '0', global_name: 'A tester', verified: true, email: 'tester@example.com' })
    }
    if (url.endsWith('/users/@me/guilds')) return Response.json([{ id: '111' }, { id: '333' }])
    if (url.endsWith('/guilds/111/members/999')) return Response.json({ roles: ['role-1'] })
    throw new Error(`Unexpected fetch: ${url}`)
  }
  t.after(() => { globalThis.fetch = originalFetch })

  const response = await token()
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('Cache-Control'), 'no-store')
  const body = await response.json()
  assert.equal(body.scope, 'identify email')
  assert.equal(body.access_token, 'discord-access-token')
  const { payload, protectedHeader } = await jwtVerify(body.id_token, publicKey, {
    issuer: 'https://cloudflare.com',
    audience: env.DISCORD_CLIENT_ID,
  })
  assert.equal(protectedHeader.alg, 'RS256')
  assert.ok(protectedHeader.kid)
  assert.deepEqual(payload.guilds, ['111', '333'])
  assert.deepEqual(payload['roles:111'], ['role-1'])
  assert.equal(payload['roles:222'], undefined)
  assert.equal(payload.sub, '999')
  assert.equal(payload.name, 'A tester')
  assert.equal(payload.preferred_username, 'tester')
  assert.ok(payload.exp - payload.iat <= 3600)
  assert.equal(requests.some(({ url }) => url.endsWith('/guilds/222/members/999')), false)
})

test('token denies malformed requests and missing runtime secrets', async () => {
  assert.equal((await token({ ...env, DISCORD_CLIENT_SECRET: undefined })).status, 503)
  const empty = await app.request('https://worker.example/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: '',
  }, env)
  assert.equal(empty.status, 400)
})

test('PKCE S256 parameters are forwarded to Discord and invalid challenges are rejected', async () => {
  const query = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    redirect_uri: env.DISCORD_REDIRECT_URI,
    state: 'opaque-state',
    code_challenge: 'A'.repeat(43),
    code_challenge_method: 'S256',
  })
  const response = await get(`/authorize/email?${query}`)
  assert.equal(response.status, 302)
  const target = new URL(response.headers.get('location'))
  assert.equal(target.searchParams.get('code_challenge'), 'A'.repeat(43))
  assert.equal(target.searchParams.get('code_challenge_method'), 'S256')
  query.set('code_challenge_method', 'plain')
  assert.equal((await get(`/authorize/email?${query}`)).status, 400)
})

test('token forwards a valid PKCE code_verifier to Discord', async (t) => {
  const originalFetch = globalThis.fetch
  let receivedVerifier
  globalThis.fetch = async (input, options) => {
    const url = String(input)
    if (url.endsWith('/oauth2/token')) {
      receivedVerifier = new URLSearchParams(options.body).get('code_verifier')
      return Response.json({ access_token: 'discord-access-token', token_type: 'Bearer' })
    }
    if (url.endsWith('/users/@me')) {
      return Response.json({ id: '999', username: 'tester', verified: true, email: 'tester@example.com' })
    }
    if (url.endsWith('/users/@me/guilds')) return Response.json([])
    throw new Error(`Unexpected fetch: ${url}`)
  }
  t.after(() => { globalThis.fetch = originalFetch })
  const verifier = 'a'.repeat(43)
  const response = await app.request('https://worker.example/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ code: 'discord-code', code_verifier: verifier }).toString(),
  }, env)
  assert.equal(response.status, 200)
  assert.equal(receivedVerifier, verifier)
  const bad = await app.request('https://worker.example/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'code=discord-code&code_verifier=too-short',
  }, env)
  assert.equal(bad.status, 400)
})
