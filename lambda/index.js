import { SecretsManager } from 'aws-sdk'
import { pki, ssh } from 'node-forge'

const secretsmanager = new SecretsManager()

const keyType = process.env.KEY_TYPE || 'RSA'
const bits = parseInt(process.env.KEY_BITS) || 2048

async function generateRSAKeyPair() {
  const {rsa} = pki
  return rsa.generateKeyPair({ bits, e: 0x10001 })
}

async function generateED25519KeyPair() {
  const {ed25519} = pki
  const keypair = ed25519.generateKeyPair()

  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.privateKey
  }
}

export async function handler(event, context) {
  try {
    let keypair
    if (keyType === 'ED25519') {
      keypair = await generateED25519KeyPair()
    } else {
      keypair = await generateRSAKeyPair()
    }

    await secretsmanager.putSecretValue({
      SecretId: event.pubkey_secret_name,
      SecretString: keyType === 'ED25519' ? keypair.publicKey.toString('base64') : ssh.publicKeyToOpenSSH(keypair.publicKey)
    }).promise()

    await secretsmanager.putSecretValue({
      SecretId: event.privkey_secret_name,
      SecretString: keyType === 'ED25519' ? keypair.privateKey.toString('base64') : ssh.privateKeyToOpenSSH(keypair.privateKey)
    }).promise()
  } catch (error) {
    console.error(error)
    throw error
  }
}
