<?php


namespace EasySwoole\Crypto;


class RSA
{
    protected $publicKey;
    protected $privateKey;

    const RSA_DECRYPT_128 = 128;
    const RSA_ENCRYPT_117 = 117;

    public function __construct($publicKey,$privateKey)
    {
        $publicKey = $this->transform('public',$publicKey);
        $privateKey = $this->transform('private',$privateKey);
        $this->publicKey = openssl_get_publickey($publicKey);
        $this->privateKey = openssl_get_privatekey($privateKey);
    }

    /**
     * 公钥加密
     * @param $data string 加密数据
     * @param $max_encrypt_block int 分段加密
     * @return bool|string
     */
    public function encrypt($data,$max_encrypt_block = RSA::RSA_ENCRYPT_117)
    {
        //加密数据
        $encrypt_data = '';
        $plain_data = str_split($data, $max_encrypt_block);
        foreach ($plain_data as $chunk){
            $str = '';
            if (openssl_public_encrypt($chunk, $str, $this->publicKey)){
                $encrypt_data .= $str;
                continue;
            }
            return false;
        }
        return base64_encode($encrypt_data);
    }

    /**
     * 私钥分段解密
     * @param $data string 加密数据
     * @param $max_decrypt_block int 分段加密
     * @return bool|string
     */
    public function decrypt(string $data,int $max_decrypt_block = RSA::RSA_DECRYPT_128)
    {
        $decrypted = '';
        $plain_data = str_split(base64_decode($data), $max_decrypt_block);
        foreach($plain_data as $chunk) {
            $str = '';
            //私钥解密
            if (openssl_private_decrypt($chunk, $str, $this->privateKey)) {
                $decrypted .= $str;
                continue;
            }
            return false;
        }
        return $decrypted;
    }

    /**
     * 私钥签名
     * @param string $data 数据
     * @param string $signature_alg 加密算法
     * @return string
     */
    public function sign(string $data,$signature_alg)
    {
        $signature = '';
        openssl_sign($data, $signature, $this->privateKey,$signature_alg);
        openssl_free_key($this->privateKey);
        $signature = base64_encode($signature);
        return $signature;
    }

    /**
     * 公钥验证签名
     * @param string $data  签名数据
     * @param string $signature 签名
     * @param string $signature_alg  加密算法
     * @return bool
     */
    public function isValid(string $data, string $signature,$signature_alg)
    {
        $result = openssl_verify($data, base64_decode($signature), $this->publicKey, $signature_alg);
        if ($result === 1){
            return true;
        }
        return false;
    }

    /**
     * 格式化传入的公私钥
     *
     * @param $type
     * @param $key
     * @return string
     */
    private function transform($type, $key)
    {
        switch ($type)
        {
            case 'private':
                if (!strpos($key,'BEGIN RSA PRIVATE KEY')){
                    $str = chunk_split($key, 64, "\n");
                    $key = "-----BEGIN RSA PRIVATE KEY-----\n$str-----END RSA PRIVATE KEY-----\n";
                }
                break;
            case 'public' :
                if (!strpos($key,'BEGIN PUBLIC KEY')){
                    $str = chunk_split($key, 64, "\n");
                    $key = "-----BEGIN PUBLIC KEY-----\n$str-----END PUBLIC KEY-----\n";
                }
                break;
        }
        return $key;
    }
}
