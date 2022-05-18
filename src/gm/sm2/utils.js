const { BigInteger, SecureRandom } = require('jsbn');
const { ECCurveFp } = require ('./ec');

let rng = new SecureRandom();
let { curve, G, n } = generateEcparam();

/**
 * 获取公共椭圆曲线
 */
function getGlobalCurve() {
    return curve;
}

/**
 * 生成ecparam
 */
function generateEcparam() {
    // 椭圆曲线
    let p = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16);
    let a = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', 16);
    let b = new BigInteger('28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', 16);
    let curve = new ECCurveFp(p, a, b);

    // 基点
    let gxHex = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7';
    let gyHex = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0';
    let G = curve.decodePointHex('04' + gxHex + gyHex);

    let n = new BigInteger('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16);

    return { curve, G, n };
}

/**
 * 生成密钥对
 */
function generateKeyPairHex() {
    //let d = new BigInteger(n.bitLength(), rng).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE); // 随机数
    // 4ab828467260931beecd23c22bba3591a8208b9c8311eb996a5b526be1eeae6c
    // 5d1c8c8d5cb3d046d72feebd4877ec85d3514206a9efa14223d9b007c7c1820a
    /**                            
      wallet2---PublicKey--------->040f93770a7a0af428c3c9928f071cb85655a6dc5dda572f2f994eebcd8f4870d2483bacb27a73f00c4db630b6b136081cb95b258ca1e90862510496ed4603936a
      wallet2---getPrivate--------->5d1c8c8d5cb3d046d72feebd4877ec85d3514206a9efa14223d9b007c7c1820a
      sig2------------>6b865c4e69900c04201e9c8e642f27ff0955e4d6dc14dcda1654d955b3d4d2e44ac0f148c941450ecf18d8c8df891dedb52102ee8195d7d099cb05f6859763e6
     */
    let d = new BigInteger('5d1c8c8d5cb3d046d72feebd4877ec85d3514206a9efa14223d9b007c7c1820a',16)
    //let d = new BigInteger("d84cabe73ec53f71ef16e8dea041c9f2b7d43fde8460a4f20799216e1fbf3603",16)
    let privateKey = leftPad(d.toString(16), 64);

    let P = G.multiply(d); // P = dG，p 为公钥，d 为私钥
    let Px = leftPad(P.getX().toBigInteger().toString(16), 64);
    let Py = leftPad(P.getY().toBigInteger().toString(16), 64);
    let publicKey = '04' + Px + Py;

    return { privateKey, publicKey };
}

/**
 * 解析utf8字符串到16进制
 */
function parseUtf8StringToHex(input) {
    input = unescape(encodeURIComponent(input));

    let length = input.length;

    // 转换到字数组
    let words = [];
    for (let i = 0; i < length; i++) {
        words[i >>> 2] |= (input.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
    }

    // 转换到16进制
    let hexChars = [];
    for (let i = 0; i < length; i++) {
        let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 解析arrayBuffer到16进制字符串
 */
function parseArrayBufferToHex(input) {
    return Array.prototype.map.call(new Uint8Array(input), x => ('00' + x.toString(16)).slice(-2)).join('');
}

/**
 * 补全16进制字符串
 */
function leftPad(input, num) {
    if (input.length >= num) return input;

    return (new Array(num - input.length + 1)).join('0') + input
}

/**
 * 转成16进制串
 */
function arrayToHex(arr) {
    let words = [];
    let j = 0;
    for (let i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j]) << (24 - (i % 8) * 4);
        j++;
    }
    
    // 转换到16进制
    let hexChars = [];
    for (let i = 0; i < arr.length; i++) {
        let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        hexChars.push((bite >>> 4).toString(16));
        hexChars.push((bite & 0x0f).toString(16));
    }

    return hexChars.join('');
}

/**
 * 转成utf8串
 */
function arrayToUtf8(arr) {
    let words = [];
    let j = 0;
    for (let i = 0; i < arr.length * 2; i += 2) {
        words[i >>> 3] |= parseInt(arr[j]) << (24 - (i % 8) * 4);
        j++
    }

    try {
        let latin1Chars = [];

        for (let i = 0; i < arr.length; i++) {
            let bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            latin1Chars.push(String.fromCharCode(bite));
        }

        return decodeURIComponent(escape(latin1Chars.join('')));
    } catch (e) {
        throw new Error('Malformed UTF-8 data');
    }
}

/**
 * 转成ascii码数组
 */
function hexToArray(hexStr) {
    let words = [];
    let hexStrLength = hexStr.length;

    if (hexStrLength % 2 !== 0) {
        hexStr = leftPad(hexStr, hexStrLength + 1);
    }

    hexStrLength = hexStr.length;

    for (let i = 0; i < hexStrLength; i += 2) {
        words.push(parseInt(hexStr.substr(i, 2), 16));
    }
    return words
}

module.exports = {
    getGlobalCurve,
    generateEcparam,
    generateKeyPairHex,
    parseUtf8StringToHex,
    parseArrayBufferToHex,
    leftPad,
    arrayToHex,
    arrayToUtf8,
    hexToArray,
};
