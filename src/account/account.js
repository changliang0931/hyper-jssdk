const { doSignature,account } = require("../gm/sm2/index")

function signWithSM2(accountJSON, needHashString) {
    let { publicKey, privateKey, privateKeyEncrypted } = accountJSON;
    if (publicKey && privateKey && typeof(privateKeyEncrypted) === 'boolean') {
        const flag = "01" // 国密 -> 1  ECDSA -> 0        
        publicKey = publicKey.toLowerCase();
        privateKey = privateKey.toLowerCase();
        if (needHashString.slice(0, 2).toLowerCase() === '0x') {
            needHashString = needHashString.slice(2, needHashString.length)
        }
        const signatureHash = doSignature(needHashString, privateKey, {
          der: true,
          hash: true,
          publicKey
        })
        return flag + publicKey + signatureHash
    }
  }

  module.exports = { signWithSM2 };
