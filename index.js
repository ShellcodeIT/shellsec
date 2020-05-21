import CryptoJS from "crypto-js"
import NodeRSA from "node-rsa"

export default class ShellSec {

  constructor($pub, $priv) {
    this.rsa = new NodeRSA($priv);
    this.pubRsa = new NodeRSA($pub);
    console.log("ShellSec initialized")
  }

  // generate an AES random key and encrypt the key with RSA private key
  cryptAesRsaJWT($req, $data) {
    const encMethod = ($req && typeof $req == 'string') ? $req : ($req ? $req.params.encmethod : null);
    if (encMethod && encMethod == 'aesrsa') {
      let str = JSON.stringify($data);
      var aesKey = CryptoJS.SHA256(str + Math.random().toString()).toString()
      var aesCryptData = CryptoJS.AES.encrypt(str, aesKey);
      const rsaCryptedKey = this.rsa.encrypt(aesKey, 'base64');
      let jwtData = {
        key: rsaCryptedKey,
        keyType: encMethod,
        data: aesCryptData.toString()
      }
      return jwtData;
    }
    return $data;
  }

  // decrypt AS key with RSA private key and decrypt data
  decryptAesRsaJWT($data) {
    if ($data.keyType && $data.keyType == 'aesrsa') {
      const aesDecryptedKey = this.rsa.decrypt($data.key, 'utf8');
      var aesDecryptData = CryptoJS.AES.decrypt($data.data, aesDecryptedKey);
      return JSON.parse(aesDecryptData.toString(CryptoJS.enc.Utf8));
    }
    return $data;
  }
}
