<?php
/**
 * 域名Whois查询
 */

namespace plugin\web\whois;

use app\Plugin;
use think\facade\Db;
use Iodev\Whois\Factory;
use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Exception;

class App extends Plugin
{
    const CACHE_TIME = 172800;

    // https://help.aliyun.com/document_detail/35793.html
    const status_name = ['ok'=>'正常状态', 'active'=>'正常状态', 'addPeriod'=>'域名新注册期', 'clientDeleteProhibited'=>'注册商设置禁止删除', 'serverDeleteProhibited'=>'注册局设置禁止删除', 'clientUpdateProhibited'=>'注册商设置禁止更新', 'serverUpdateProhibited'=>'注册局设置禁止更新', 'clientTransferProhibited'=>'注册商设置禁止转移', 'serverTransferProhibited'=>'注册局设置禁止转移', 'pendingVerification'=>'注册信息审核期', 'clientHold'=>'注册商设置暂停解析', 'serverHold'=>'注册局设置暂停解析', 'inactive'=>'非激活状态', 'clientRenewProhibited'=>'注册商设置禁止续费', 'serverRenewProhibited'=>'注册局设置禁止续费', 'pendingTransfer'=>'转移过程中', 'redemptionPeriod'=>'赎回期', 'pendingDelete'=>'待删除'];
    
    public function index()
    {
        return $this->view();
    }

    public function query(){
        $domain = input('post.domain', null, 'trim');
        if(!$domain) return msg('error','no domain');
        if(filter_var($domain, FILTER_VALIDATE_IP)){
            $type = 'ip';
        }elseif(checkdomain($domain)){
            $type = 'domain';
        }else{
            return msg('error', '域名或IP格式不正确！');
        }

        $captcha_result = verify_captcha4();
        if($captcha_result !== true){
            return msg('error', '验证失败，请重新验证');
        }

        if(self::CACHE_TIME > 0){
            $cache = Db::name('querycache')->where('type', 'whois')->where('key', $domain)->find();
            if($cache && time() - strtotime($cache['uptime']) <= self::CACHE_TIME){
                $array = json_decode($cache['content'], true);
                return msg('ok','success',$array);
            }
        }

        try {
            $whois = Factory::get()->createWhois();
            $info = $whois->loadDomainInfo($domain);
        } catch (ConnectionException $e) {
            return msg('error', '查询失败，Whois服务器连接失败');
        } catch (ServerMismatchException $e) {
            return msg('error', '查询失败，Whois服务器不存在');
        } catch (WhoisException $e) {
            return msg('error', '查询失败，'.$e->getMessage());
        }
        if(!$info){
            return msg('ok','success',null);
        }

        $data = ['domainName'=>$info->domainName, 'whoisServer'=>$info->whoisServer, 'creationDate'=>$info->creationDate ? date('Y-m-d H:i:s', $info->creationDate) : null, 'expirationDate'=>$info->expirationDate ? date('Y-m-d H:i:s', $info->expirationDate) : null, 'updatedDate'=>$info->updatedDate ? date('Y-m-d H:i:s', $info->updatedDate) : $info->updatedDate, 'nameServers'=>$info->nameServers, 'states'=>$info->states, 'owner'=>$info->owner, 'registrar'=>$info->registrar, 'dnssec'=>$info->dnssec, 'rawData'=>$info->getResponse()->text];

        if(strpos($data['rawData'],'For more information on')){
            $data['rawData'] = substr($data['rawData'], 0, strpos($data['rawData'],'For more information on'));
        }

        $status_name = array_change_key_case(self::status_name, CASE_LOWER);
        if(!empty($data['states'])){
            $status = [];
            foreach($data['states'] as $state){
                $name = null;
                $key = str_replace(' ', '', strtolower($state));
                if(isset($status_name[$key]))
                    $name = $status_name[$key];
                if(!$name) {$name = $state;$state = null;}
                $status[] = ['value'=>$state, 'name'=>$name];
            }
            $data['states'] = $status;
        }

        if(self::CACHE_TIME > 0){
            Db::name('querycache')->duplicate([
                'content' => json_encode($data),
                'uptime' => date('Y-m-d H:i:s')
            ])->insertGetId([
                'type' => 'whois',
                'key' => $domain,
                'content' => json_encode($data),
                'uptime' => date('Y-m-d H:i:s')
            ]);
        }

        return msg('ok','success',$data);
    }

}