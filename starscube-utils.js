//rsa加密
function rsaCrypt(data) {
    var rsa = new JSEncrypt();
    var pubKey = document.getElementById('publicKey').value;
    if (pubKey) {
        rsa.setPublicKey(pubKey);
        return rsa.encrypt(data);
    }

}


//rsa验证数字签名
function rsaVerify(source, sign) {
    var pubKey = document.getElementById('publicKey').value;
    var sig2 = new KJUR.crypto.Signature({ "alg": "MD5withRSA" });
    sig2.init('-----BEGIN PUBLIC KEY-----\n' + pubKey + '\n-----END PUBLIC KEY-----');
    sig2.updateString(source);
    var isValid = sig2.verify(sign);
    return isValid;
}

function rsaVerify2(source, sign) {
    var pubKey = document.getElementById('publicKey').value;
    var sig2 = new KJUR.crypto.Signature({ "alg": "MD5withRSA" });
    sig2.init(pubKey);
    sig2.updateString(source);
    var isValid = sig2.verify(sign);
    return isValid;
}


//随机生成16位key
function randomKeys(rdmSize) {
    var seed = "0123456789abcdefghijklmnopqrstuvwxyz&";
    var len = seed.length;
    var rst = "";
    for (var i = 0; i < rdmSize; i++) {
        rst += seed.charAt(Math.round(Math.random() * 36));
    }
    return rst;
}

//AES加密
function aesEncrypt(seed, data) {
    var key = CryptoJS.enc.Utf8.parse(seed);
    var iv = CryptoJS.enc.Utf8.parse(seed);
    encrypted = CryptoJS.AES.encrypt(data, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}

//AES解密
function aesDecrypt(seed, data) {
    var key = CryptoJS.enc.Utf8.parse(seed);
    var iv = CryptoJS.enc.Utf8.parse(seed);
    var decrypt = CryptoJS.AES.decrypt(data, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return decrypt.toString(CryptoJS.enc.Utf8);
}