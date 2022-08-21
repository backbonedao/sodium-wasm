// import * as sodium from "../../src/Sodium"
// import * as Const from "../../src/constants"
import sodium from '../../lib'

;(async () => {
  if(typeof sodium?.init === 'function') await sodium.init()
  const str = "test"
  const input = Buffer.isBuffer(str) ? str : Buffer.from(str)
  let hash = Buffer.alloc(sodium.crypto_generichash_BYTES)
  sodium.crypto_generichash(hash, input, null)
  console.log(hash.toString('hex') === "928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202")
})()
