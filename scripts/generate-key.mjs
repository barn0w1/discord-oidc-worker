import { generateKeyPairSync } from 'node:crypto'

// Run once and store the output only as a Cloudflare Workers Secret.
// Do not run this during builds or deploys; redeploys must keep the same key.
const { privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicExponent: 0x10001,
})
process.stdout.write(`${JSON.stringify(privateKey.export({ format: 'jwk' }))}\n`)
