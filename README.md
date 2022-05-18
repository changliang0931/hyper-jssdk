# JS-SDK

目前只提供了国密接口(`sm2`, `sm3`, `sm4`)


## 安装私有npm

`npm install git+http://git.hyperchain.cn/hehao/jssdk`

## Example

### sm2

```javascript

import { smcrypto } from 'jssdk';

let keypair = smcrypto.sm2.generateKeyPairHex();
let publicKey = keypair.publicKey; // 公钥
let privateKey = keypair.privateKey; // 私钥

console.log("publicKey ->", publicKey)
console.log("privateKey ->", privateKey)

let msg = "test"

let sigValueHex = smcrypto.sm2.doSignature(msg, privateKey); // 签名
let verifyResult = smcrypto.sm2.doVerifySignature(msg, sigValueHex, publicKey) // 验签结果

// 纯签名
let sigValueHex2 = smcrypto.sm2.doSignature(msg, privateKey, {
    pointPool: [smcrypto.sm2.getPoint(), smcrypto.sm2.getPoint(), smcrypto.sm2.getPoint(), smcrypto.sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
});

console.log("sigValueHex2 -->", sigValueHex2)

// 签名
let sigValueHex3 = smcrypto.sm2.doSignature(msg, privateKey, {
  der: true,
});

console.log("sigValueHex3 -->", sigValueHex3)

// 验签结果
let verifyResult3 = smcrypto.sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
  der: true,
}); 

console.log("verifyResult3 -->", verifyResult3)

// 签名
let sigValueHex4 = smcrypto.sm2.doSignature(msg, privateKey, {
  hash: true,
}); 

console.log("sigValueHex4 -->", sigValueHex4)

// 验签结果
let verifyResult4 = smcrypto.sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
  hash: true,
}); 

console.log("verifyResult4 -->", verifyResult4)

let sigValueHex5 = smcrypto.sm2.doSignature(msg, privateKey, {
  hash: true,
  publicKey, // 传入公钥的话，可以去掉sm3杂凑中推导公钥的过程，速度会比纯签名 + 生成椭圆曲线点 + sm3杂凑快
});

console.log("sigValueHex5 -->", sigValueHex5)

let verifyResult5 = smcrypto.sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
  hash: true,
  publicKey,
});

console.log("verifyResult5 -->", verifyResult5)
```

### sm3

```javascript
import { smcrypto } from 'jssdk';

let hashData = smcrypto.sm3('abc'); // 杂凑

console.log("hashData ->", hashData)
```

### sm4

```javascript
import { smcrypto } from 'jssdk';

const key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

// 加密
let encryptData = smcrypto.sm4.encrypt([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10], key);

console.log("encryptData ->", encryptData)

// 解密
let decryptData = smcrypto.sm4.decrypt([0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46], key);

console.log("decryptData ->", decryptData)

```