const { BigInteger } = require('jsbn');
const { ECPointFp } = require ('./ec');
const SM3Digest = require('./sm3');
const _ = require('./utils');

class SM2Cipher {
    constructor() {
        this.ct = 1;            //kdf的计数器
        this.p2 = null;         //暂时保存temp
        this.sm3keybase = null; //KDF(p2.x||p2.y,klen),输出是一个和M同长的比特串t
        this.sm3c3 = null;      //计算c3 H(p2.x || M || p2.y)
        this.key = new Array(32);
        this.keyOff = 0;        //
        this.debug_t = [];
    }

    reset() {                   //初始化SM3,初始化计数器
        this.sm3keybase = new SM3Digest();      //计算kdf
        this.sm3c3 = new SM3Digest();       //计算c3
        let xWords = _.hexToArray(this.p2.getX().toBigInteger().toRadix(16));
        let yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16));
        this.sm3keybase.blockUpdate(xWords, 0, xWords.length);
        this.sm3c3.blockUpdate(xWords, 0, xWords.length);
        this.sm3keybase.blockUpdate(yWords, 0, yWords.length);
        this.ct = 1;
        this.nextKey();     //计算t
    }

    nextKey() {
        //KDF
        //把p2的x和y拼在一起，再拼上ct,hash,得到一个v长度的分组（SM3的length是32byte）
        let sm3keycur = new SM3Digest(this.sm3keybase);
        //这里ct是一个32bit的值，把他转为字节是4个，然后依次updata
        //ct的初始值是1
        sm3keycur.update((this.ct >> 24 & 0x00ff));         //依次处理各个字节
        sm3keycur.update((this.ct >> 16 & 0x00ff));
        sm3keycur.update((this.ct >> 8 & 0x00ff));
        sm3keycur.update((this.ct & 0x00ff));
        sm3keycur.doFinal(this.key, 0);                     //暂时存到key中
        this.keyOff = 0;
        this.ct++;
    }
    initEncipher(userKey) {                             //传入公钥Pb
        let keypair = _.generateKeyPairHex();
        let k = new BigInteger(keypair.privateKey, 16);
        let publicKey = keypair.publicKey;              //pubkey作为c1 = g^k

        this.p2 = userKey.multiply(k); // [k](Pb)       //计算p2 = pb^k
        this.reset();                                   //

        if (publicKey.length > 128) {
          publicKey = publicKey.substr(publicKey.length - 128);
        }
        return publicKey;
    }
    
    encryptBlock(data) {        //计算c3和t,一次循环计算出t和c3,并完成异或。输入是msg。
        this.sm3c3.blockUpdate(data, 0, data.length);       //c3
        for (let i = 0; i < data.length; i++) {             //一个字节一个字节处理msg
            if (this.keyOff === this.key.length) {          //每32个字节，从新计算kdf的一个分组，结果保存在this.key
                this.nextKey();
            }
            this.debug_t.push(this.key[this.keyOff])
            data[i] ^= this.key[this.keyOff++] & 0xff;             //keyoff用来计数0到31
        }
    }

    initDecipher(userD, c1) {
        this.p2 = c1.multiply(userD);
        this.reset();
    }

    decryptBlock(data) {
        for (let i = 0; i < data.length; i++) {
            if (this.keyOff === this.key.length) {
                this.nextKey();
            }
            this.debug_t.push(this.key[this.keyOff])
            data[i] ^= this.key[this.keyOff++] & 0xff;
        }
        this.sm3c3.blockUpdate(data, 0, data.length);
    }

    doFinal(c3) {
        let yWords = _.hexToArray(this.p2.getY().toBigInteger().toRadix(16));
        this.sm3c3.blockUpdate(yWords, 0, yWords.length);
        this.sm3c3.doFinal(c3, 0);
        this.reset();
    }
    
    createPoint(x, y) {     //编码x,y成为一个点
        let publicKey = '04' + x + y;
        let point = _.getGlobalCurve().decodePointHex(publicKey);
        return point;
    }
}

module.exports = SM2Cipher;
