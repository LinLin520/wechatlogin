<?php
namespace App\WeChat;

use Illuminate\Contracts\Encryption\Encrypter;
use App\Http\Models\Member;
use Illuminate\Support\Facades\Cookie;

class Wechat
{
    CONST HOST = 'api.parllay.cn/v1.1';
    CONST USER_COOKIE_KEY = 'WECHAT_USER_INFO';
    private $redirect_url='';
    private $parllay_token;
    private $parllay_app_id;
    private $parllay_app_secret;
    private $wx_app_id;
    private $wx_app_secret;
    private $parllay_protocol;
    private $access_token='';
    private $wx_access_token='';
    private $user = null;
    private $scope_type = 'snsapi_base';
    protected $encrypter;
    private $needDecrypt = false;

    public function __construct(Encrypter $encrypter)
    {
        $this->parllay_token = config('app.parllay_token');
        $this->parllay_app_id = config('app.parllay_app_id');
        $this->parllay_app_secret = config('app.parllay_app_secret');
        $this->wx_app_id = config('app.wx_app_id');
        $this->wx_app_secret = config('app.wx_app_secret');
        $this->parllay_protocol = $this->use_https() ? 'https' : 'http';
        $this->encrypter = $encrypter;
    }

    /**
     * Set wechat scope's value
     * @param $type
     */
    public function setScope($type){
        $this->scope_type = $type;
    }
    /**
     * Get Parrly's access-token
     * @return string
     */
    public function getAccessToken()
    {
        if(!$this->access_token)$this->setAccessToken();
        return $this->access_token;
    }

    /**
     * SCRM 1.0.0
     * set Parllay a third-party Access Token that not WeChat
     */
    private function setAccessToken()
    {
        $api_url = $this->getPreUri()."/token/get?app_id=" . $this->parllay_app_id . "&app_secret=" . $this->parllay_app_secret;

        try{
            $data = file_get_contents($api_url);
            $result = json_decode($data);
            $this->access_token = $result->access_token;
        }catch (\Exception $e){
            \Log::error($e->getMessage());
        }
    }

    /** SCRM 1.1.0
     * Set　parllay Tag follower
     * @param $tag Tag_NAME
     * @param $group Tag_GROUP
     * @param $open_id open_id
     * @return array|mixed|object
     */
    public function getTagFollower($tag ,$group ,$open_id){
        $api_url = $this->getPreUri() . "/tag/". $this->parllay_token ."/". $tag.
            "?access_token=".$this->getAccessToken(false).
            "&group=". $group .
            "&openid=".$open_id;
        try{
            $data = file_get_contents($api_url);
            return json_decode($data ,true);
        }catch (\Exception $e)
        {
            \Log::error($e->getMessage());
            return [];
        }
    }

    /**
     * SCRM 1.2.0
     * Auth WX
     * @return mixed
     */
    public function authorize () {
        $scope = $this->scope_type;
        $state = 'justopenid';
        $access_token = $this->getAccessToken();

        $header_url = $this->getPreUri() . "/social/sns/oauth2/". $this->parllay_token."/authorize?access_token=".$access_token
            ."&scope=".$scope
            ."&state=".$state
            ."&url=".$this->redirect_url;
        //keep current url
        $previous_url = _myMemcache('request_wechat_url'.get_client_ip_from_ns());
        if(!$previous_url) _myMemcache('request_wechat_url'.get_client_ip_from_ns(),'set',$this->get_url(),8);
        header("location:".$header_url);
        exit;
    }

    /**
     * Handle the callback of Parlly
     * @param $request
     * @return string
     */
    public function handleCallback($request)
    {
        $wx_user = [
            'open_id'=>  $request->input('openid',''),
            'nick_name' => $request->input('nickname',''),
            'head_img_url' => $request->input('headimgurl',''),
        ];
        //add wechat's user information into cookies
        $this->addCookie(self::USER_COOKIE_KEY, json_encode($wx_user));
        $previous_url = _myMemcache('request_wechat_url'.get_client_ip_from_ns());
        if(!$previous_url) $previous_url = 'homepage';
//        _myMemcache('request_wechat_url'.get_client_ip_from_ns(),'del');
        //Add tag for each visitor gets into the Html5
        $this->getTagFollower('os-2018jul-peh5-visitor', 'os-2018jul-pe', $wx_user['open_id']);
        $this->updateMember($wx_user); //调用修改用户信息
        return $previous_url;
    }

    /**
     * describe: update member info
     * author: lzy
     * date: 10/16/2018
     * @param array $wx_user
     * @return bool
     */
    private function updateMember($wx_user){
        $memberModel = new Member();
        if(is_wechat()){
            $openId = $wx_user['open_id'];
            if(!$openId) return false;
            $nickName = $wx_user['nick_name'];
            \Log::info($openId);
            $userInfo = $memberModel->getOneMessage('openid',$openId);
            if(!$userInfo){
                $userInfo = $wx_user;
                $memberModel->insertMember($userInfo); //add member
            }else if((!$userInfo->nick_name && $nickName) || ($userInfo->nick_name != $nickName)){ //update member
                $memberModel->updateMember('openid',$openId,['nick_name'=>$nickName]);
            }
            return true;
        }
    }

    /**
     * set callback url of authorize.
     * @param $url
     */
    public function setRedirectUrl($url='')
    {
        $this->redirect_url = urlencode($url);
    }

    /**
     * describe: get WeChat now  url
     * author: lzy
     * date: 10/16/2018
     * @param string $val
     * @param string $valb
     * @param array $var
     * @return string
     */
    public function get_url($val = '', $valb = '', $var = array())
    {
        $sys_protocal = isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == '443' ? 'https://' : 'http://';
        if ($valb == 'img') {
            if (strstr($val, 'http:')) return $val;
            return $sys_protocal . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . $val;
        } elseif ($valb == 'url') {
            $var['token'] = $GLOBALS['userinfo']['token'];
            if (strstr($val, 'http:')) return $val;
            return $sys_protocal . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . U($val, $var);
        } elseif ($valb == '_url') {
            $var['token'] = $GLOBALS['userinfo']['token'];
            if (strstr($val, 'http:')) return $val;
            return $sys_protocal . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . U($val, $var);
        }
        $php_self = $_SERVER['PHP_SELF'] ? $_SERVER['PHP_SELF'] : $_SERVER['SCRIPT_NAME'];
        $path_info = isset($_SERVER['PATH_INFO']) ? $_SERVER['PATH_INFO'] : '';
        $relate_url = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : $php_self . (isset($_SERVER['QUERY_STRING']) ? '?' . $_SERVER['QUERY_STRING'] : $path_info);
        return $sys_protocal . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '') . $relate_url;
    }

    /**
     * get WeChat ID
     * @return mixed
     */
    public function getOpenId()
    {
        $this->getUser();
        return $this->user['open_id'];
    }
    public function getHeadImage()
    {
        $this->getUser();
        return $this->user['head_img_url'];
    }
    public function getNick()
    {
        $this->getUser();
        return $this->user['nick_name'];
    }
    /**
     * Get WeChat user info from Cookie
     */
    public function getUser(){
        if(!is_null($this->user)){
            return $this->user;
        }
        if(is_wechat() && !\Cookie::has(self::USER_COOKIE_KEY)){
            $this->authorize();
        }
        $this->user = json_decode($this->decryptCookie(\Cookie::get(self::USER_COOKIE_KEY)), true);
    }

    /**
     * get WeChat's access-token
     * @return string
     */
    public function getWXAccessToken(){
        if(!$this->wx_access_token)$this->setWXAccessToken();
        return $this->wx_access_token;
    }
    /**
     * SCRM 1.3
     * Set WeChat AccessToken via getting data from Parllay
     * And it is not necessary considering cache at local, Parrly has done
     */
    private function setWXAccessToken(){
        $api_url = $this->getPreUri(). "/social/token/".$this->parllay_token."/get/client?access_token=".$this->getAccessToken();
        try{
            $res = file_get_contents($api_url);
            $token = json_decode($res);
            $this->wx_access_token = $token->access_token;
        }catch (\Exception $e){
            \Log::error('setWXAccessToken:');
            \Log::error($e->getMessage());
        }
    }

    /**
     * Get JS Ticket from WX instead of Parllay,and cache 100 minutes.
     * @return bool|string false if not successful, js_ticket string if successful.
     */
    public function getWXJSTicket(){
        $js_ticket_key = 'WeChat_js_ticket';

        return \Cache::remember($js_ticket_key, 100, function(){
            $wx_access_token = $this->getWXAccessToken();
            $json = file_get_contents($this->parllay_protocol.'://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=' . $wx_access_token . '&type=jsapi');
            $json_r = json_decode($json);
            $ero = $json_r->{'errcode'};
            if ($ero == '0') {
                \Log::info("Ticket:".$json_r->{'ticket'});
                return $json_r->{'ticket'};
            } else {
                return false;
            }
        });
    }
    private function getPreUri()
    {
        return $this->parllay_protocol."://".self::HOST;
    }

    private function use_https() {
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            return true;
        }
        return false;
    }

    /**
     * api 调用时cookie加密了，所以是需要解密的
     * @param $cookie
     * @return string
     */
    protected function decryptCookie($cookie)
    {
        if($this->needDecrypt)
        {
            return $this->encrypter->decrypt($cookie);
        }
        return $cookie;
    }

    /**
     * add Cookie
     * @param $key
     * @param $value
     * @param int $expir
     */
    public function addCookie($key, $value, $expir=3600)
    {
        Cookie::queue($key, $value, $expir, $path = null, $domain = null, $secure = false);

    }


    private function is_json($string)
    {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    public function setNeedDecrypt($value = false){
        $this->needDecrypt = $value;
        return $this;
    }

}


