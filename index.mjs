import path from 'path'
import url from 'url'
import fs from 'fs'
import * as snarkjs from 'snarkjs'
import { IncrementalMerkleTree, SparseMerkleTree, hash1, hash2, hash3, hash4 } from '@unirep/crypto'
import { TREE_DEPTH } from './config.mjs'
import crypto from 'crypto'

const __dirname = path.dirname(url.fileURLToPath(import.meta.url))

const buildPath = './zksnarkBuild'

const genProofAndPublicSignals = async (
    circuitName,
    inputs
) => {
  const circuitWasmPath = path.join(
    __dirname,
    buildPath,
    `${circuitName}.wasm`
  )
  const zkeyPath = path.join(__dirname, buildPath, `${circuitName}.zkey`)
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    circuitWasmPath,
    zkeyPath
  )

  return { proof, publicSignals }
}

const verifyProof = async (
  circuitName,
  publicSignals,
  proof
) => {
  const vkeyData = fs.readFileSync(path.join(buildPath, `${circuitName}.vkey.json`))
  const vkey = JSON.parse(vkeyData.toString())
  return snarkjs.groth16.verify(vkey, publicSignals, proof)
}

const randomHex = () => `0x${crypto.randomBytes(16).toString('hex')}`

// let's make a tree and a proof
// by default no entries are blacklisted
const tree = new SparseMerkleTree(TREE_DEPTH)

const blacklistedIMEIs = Array(100).fill().map(() => randomHex())

for (const IMEI of blacklistedIMEIs) {
  const leafIndex = hash1([IMEI])
  tree.update(leafIndex, BigInt(1))
}

console.log(`Tree root with 100 entries: ${tree.root}`)

// let's prove a valid IMEI
{
  const IMEI = randomHex()
  const start = +new Date()
  const { proof, publicSignals } = await genProofAndPublicSignals('proveNotBlacklisted', {
    IMEI,
    path_elements: tree.createProof(hash1([IMEI])),
  })
  const end = +new Date()
  const isValid = await verifyProof('proveNotBlacklisted', publicSignals, proof)
  if (!isValid) throw new Error('Generated invalid proof')
  console.log(`Generated proof in ${end-start} ms`)
  console.log(`Root for non-blacklisted IMEI: ${publicSignals[0]}`)
}

// now let's try to prove an invalid IMEI
{
  const IMEI = blacklistedIMEIs.pop()
  const start = +new Date()
  const { proof, publicSignals } = await genProofAndPublicSignals('proveNotBlacklisted', {
    IMEI,
    path_elements: tree.createProof(hash1([IMEI])),
  })
  const end = +new Date()
  const isValid = await verifyProof('proveNotBlacklisted', publicSignals, proof)
  if (!isValid) throw new Error('Generated invalid proof')
  console.log(`Generated proof in ${end-start} ms`)
  console.log(`Root for blacklisted IMEI: ${publicSignals[0]} (should mismatch above root)`)
}

{
  const paymentTree = new SparseMerkleTree(TREE_DEPTH)
  const nullifierMap = {}
  const payCycle = 30

  const myIdNullifier = randomHex()
  const myIdTrapdoor = randomHex()

  let myRid;
  let leafIndex;
  let myPayId;
  for (let x = 0; x < 50; x++) {
    const rid = randomHex()
    const payId = randomHex()
    paymentTree.update(BigInt(x), hash3([rid, payId, payCycle]))
    if (x === 12) {
      leafIndex = x
      myRid = rid
      myPayId = payId
    }
    const nullifier = hash4([rid,payId, payCycle, 12])
    nullifierMap[nullifier.toString()] = true
  }
  const start = +new Date()

  const {proof, publicSignals} = await genProofAndPublicSignals("proofOfPayment", {
    rid: myRid,
    payId: myPayId,
    payCycle: payCycle,
    merkleProof: paymentTree.createProof(BigInt(12)),
    idNullifier: myIdNullifier,
    idTrapdoor: myIdTrapdoor,
    leafIndex: 12,
  })

  const isValid = await verifyProof('proofOfPayment', publicSignals, proof)
  const end = +new Date()
  if (!isValid) throw new Error('Generated invalid proof')
  console.log(`Generated proof in ${end-start} ms`)
  console.log(`Root for payment: ${publicSignals[0]}`)

  const isPaymentRootValid = publicSignals[0].toString() === paymentTree.root.toString()
  console.log(isPaymentRootValid)
  const isIdentityValid = hash1([hash2([myIdNullifier, myIdTrapdoor])]).toString() === publicSignals[1].toString()
  console.log(isIdentityValid)
  console.log(`pub signal 2: ${publicSignals[2].toString()}`)
  console.log(nullifierMap)
  const isPaymentLeafNullifierValid = Object.keys(nullifierMap).indexOf(publicSignals[2].toString()) !== -1
  console.log(isPaymentLeafNullifierValid)
}

process.exit(0)
