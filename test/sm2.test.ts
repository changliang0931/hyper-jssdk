
import { generateKeyPairHex,doSignature,doVerifySignature } from '../src/gm/sm2';

let keypair = generateKeyPairHex();
let publicKey = keypair.publicKey; // 公钥
let privateKey = keypair.privateKey; // 私钥

console.log("publicKey ->", publicKey)
console.log("privateKey ->", privateKey)

// var msg  =[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
var msg ="from=0x6469643a6870633a526564436176653a63613764633364383330316431343764323731373263396334643764643163623431643735363063&to=0x6469643a6870633a526564436176653a63613764633364383330316431343764323731373263396334643764643163623431643735363063&value=0x0&payload=0x7b2264696441646472657373223a226469643a6870633a526564436176653a63613764633364383330316431343764323731373263396334643764643163623431643735363063222c227374617465223a302c227075626c69634b6579223a7b2274797065223a22736d32222c226b6579223a2242412b54647770364376516f77386d536a77636375465a5670747864326c63764c356c4f363832505348445353447573736e707a3841784e746a433273545949484c6c624a5979683651686955515357375559446b326f3d227d7d&timestamp=0x16f2496da73d66b5&nonce=0xd7af9ffc0cd8b&opcode=c8&extra=&vmtype=TRANSFER&version=3.2&extraid=&cname="; 
let sigValueHex = doSignature(msg, privateKey); // 签名
console.log("sigValueHex  r + s --->", sigValueHex)

// [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]

let verifyResult = doVerifySignature(msg, sigValueHex, publicKey) // 验签结果
console.log("verifyResult r + s->", verifyResult)
// // 纯签名
// let sigValueHex2 = sm2.doSignature(msg, privateKey, {pointPool: [sm2.getPoint(), sm2.getPoint(), sm2.getPoint(), sm2.getPoint()], // 传入事先已生成好的椭圆曲线点，可加快签名速度
// });

// console.log("sigValueHex2 -->", sigValueHex2)

// 签名:
let sigValueHex3 = doSignature(msg, privateKey, {pointPool:null, der: true, hash:null, publicKey:null});

console.log("sigValueHex3 asn1 der编码 ---->", sigValueHex3)

// 验签结果
let verifyResult3 = doVerifySignature(msg, sigValueHex3, publicKey, { der: true,hash:null}); 

console.log("verifyResult3 asn1 der编码 -->", verifyResult3)

// 签名
let sigValueHex4 = doSignature(msg, privateKey,{pointPool:null, der: null, hash:true, publicKey:null}); 

console.log("sigValueHex4 -->", sigValueHex4)

// // 验签结果
// let verifyResult4 = sm2.doVerifySignature(msg, sigValueHex4, publicKey, {
//   hash: true,
// }); 

// console.log("verifyResult4 -->", verifyResult4)

let sigValueHex5 = doSignature(msg, privateKey, {pointPool:null, der: true, hash:true, publicKey:publicKey
   // 传入公钥的话，可以去掉sm3杂凑中推导公钥的过程，速度会比纯签名 + 生成椭圆曲线点 + sm3杂凑快
});

console.log("sigValueHex5 -->", sigValueHex5)

// let verifyResult5 = sm2.doVerifySignature(msg, sigValueHex5, publicKey, {
//   hash: true,
//   publicKey,
// });

// console.log("verifyResult5 -->", verifyResult5)