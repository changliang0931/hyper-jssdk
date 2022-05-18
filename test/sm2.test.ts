
import { generateKeyPairHex,doSignature,doVerifySignature } from '../src/gm/sm2';

let keypair = generateKeyPairHex();
let publicKey = keypair.publicKey; // 公钥
let privateKey = keypair.privateKey; // 私钥

console.log("publicKey ->", publicKey)
console.log("privateKey ->", privateKey)

var msg = "a";
// var msg  =[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];

// =[0x01,..] ---> 0123456789abcdeffedcba9876543210
//   "aabbccdd" --->6161626263636464  
let sigValueHex = doSignature(msg, privateKey); // 签名
console.log("sigValueHex ->", sigValueHex)

// [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]


let verifyResult = doVerifySignature(msg, sigValueHex, publicKey) // 验签结果
console.log("verifyResult ->", verifyResult)
// // 纯签名
// let sigValueHex2 = sm2.doSignature(msg, privateKey, {pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
// });

// console.log("sigValueHex2 -->", sigValueHex2)

// // 签名
// let sigValueHex3 = sm2.doSignature(msg, privateKey, {
//   der: true,
// });

// console.log("sigValueHex3 -->", sigValueHex3)

// // 验签结果
// let verifyResult3 = sm2.doVerifySignature(msg, sigValueHex3, publicKey, {
//   der: true,
// }); 

// console.log("verifyResult3 -->", verifyResult3)

// // 签名
// let sigValueHex4 = sm2.doSignature(msg, privateKey, {
//   hash: true,
// }); 

// console.log("sigValueHex4 -->", sigValueHex4)

// // 验签结果
// let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
//   hash: true,
// }); 

// console.log("verifyResult4 -->", verifyResult4)

// let sigValueHex5 = sm2.doSignature(msg, privateKey, {
//   hash: true,
//   publicKey, // 传入公钥的话，可以去掉sm3杂凑中推导公钥的过程，速度会比纯签名 + 生成椭圆曲线点 + sm3杂凑快
// });

// console.log("sigValueHex5 -->", sigValueHex5)

// let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
//   hash: true,
//   publicKey,
// });

// console.log("verifyResult5 -->", verifyResult5)