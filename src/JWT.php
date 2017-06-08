<?php

/**
 * Created by PhpStorm.
 * User: wanyujun
 * Date: 2017/6/8
 * Time: 下午11:13
 */
namespace  Jwt;

class Jwt
{

    public function __construct()
    {

    }


    /**
     * 生成jwt
     * @param array $data 载何实体数据
     * @param $secret 秘钥
     */
    public function buildJwt(array $data, $secret)
    {
        
    }


    /**
     * 验证jwt是否正确
     * @param $jwt jwt字符串
     * @param $secret 秘钥
     */
    public function verifyJwt($jwt, $secret)
    {
        $result = $this->_parseJwt($jwt);
        if ($result === false) {
            return false;
        }

        if (in_array($result['header']['typ'], hash_algos())) {
            return false;
        }

        $jwtstr = base64_encode(json_encode($result['header'])) . '.' . base64_encode(json_encode($result['payload'])) . '.' . base64_encode($secret);
        $signature = hash_hmac($result['header']['typ'], $jwtstr, $secret);
        if ($signature != $result['signature']) {
            return false;
        }

        //验证载何信息(具体验证请自己实现)

        return true;

    }


    /**
     * 解析jwt数据
     * @param $jwt jwt字符串
     * @return array
     */
    private function _parseJwt($jwt)
    {
        if (empty($jwt)) {
            return false;
        }

        list($info['header'], $info['payload'], $info['signature']) = explode('.', $jwt);

        array_map('base64_decode', $info);

        if (empty($info['header']) || empty($info['payload']) || empty($info['signature'])) {
            return false;
        }

        $info['header'] = json_decode($info['header'], true);
        $info['payload'] = json_decode($info['payload'], true);

        return $info;

    }




}