<?php
require 'whois.php';

/**
  * wechat php test
  */

//define your token
define("TOKEN", "9zSzQ9S8NIIlysCsEWJ0");
$wechatObj = new wechatCallbackapiTest();
$wechatObj->responseMsg();

class wechatCallbackapiTest
{
	public function valid()
    {
        $echoStr = $_GET["echostr"];

        //valid signature , option
        if($this->checkSignature()){
        	echo $echoStr;
        	exit;
        }
	else {
		echo "test";
	}
    }

    public function responseMsg()
    {
		//get post data, May be due to the different environments
		$postStr = $GLOBALS["HTTP_RAW_POST_DATA"];

      	//extract post data
		if (!empty($postStr)){
                
              	$postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
                $fromUsername = $postObj->FromUserName;
                $toUsername = $postObj->ToUserName;
                $keyword = trim($postObj->Content);
                $time = time();
                $textTpl = "<xml>
							<ToUserName><![CDATA[%s]]></ToUserName>
							<FromUserName><![CDATA[%s]]></FromUserName>
							<CreateTime>%s</CreateTime>
							<MsgType><![CDATA[%s]]></MsgType>
							<Content><![CDATA[%s]]></Content>
							<FuncFlag>0</FuncFlag>
							</xml>";             
				if(!empty( $keyword ))
                {
              		$msgType = "text";
                	//$contentStr = "Welcome to the world!";
					$contentStr = $keyword;
					// 判断是否首次关注
					if ( $keyword == "Hello2BizUser" ) {
						$contentStr = "Welcome to the world!";
					}
					
					// 判断是否需要帮助
					if ( strtolower($keyword) == "help" || $keyword == "?" || 1==1) {
						$contentStr = "请输入域名查询whois，或输入IP获取连通性结果。";
					}

					// 判断是否域名，如果分隔符. 倒数第四位内，默认为域名
					if ( substr_count($keyword, '.') > 0 && substr_count($keyword, '.') <= 2 ) {
						$sd = new SearchDomain(); 
						$sd->SetDomain($keyword); 
						$rs = $sd->GetInfo(); 
						if($rs=="ok") {
							$contentStr = $sd->domain." 未注册";
						} else {
							if($rs=="") {
								$contentStr = "无法查询 ".$sd->domain." 状态";
							} else {
								$contentStr = $sd->domain." 已注册，到期时间：$rs";
							}
						}
					}
					// 判断是否为纯IP，如果是则PING
					if ( substr_count($keyword, '.') == 3 ) {
						$to_ping = $keyword;
						$count = 4; 
						$psize = 65;

						exec("ping -c $count -s $psize $to_ping", $list); 
						for ($i=0;$i < count($list);$i++) { 
							$contentStr = $list[$i]; 
						}
					}
					// $contentStr = "to:".$toUsername."-from:".$fromUsername;
					// $fromUsername = "o_Zzhjp54yOOh-6uRJXYNxVAGNvA";
                	$resultStr = sprintf($textTpl, $fromUsername, $toUsername, $time, $msgType, $contentStr);
                	echo $resultStr;
                }else{
                	echo "Input something...";
                }

        }else {
        	echo "";
        	exit;
        }
    }
		
	private function checkSignature()
	{
        $signature = $_GET["signature"];
        $timestamp = $_GET["timestamp"];
        $nonce = $_GET["nonce"];	
        		
		$token = TOKEN;
		$tmpArr = array($token, $timestamp, $nonce);
		sort($tmpArr);
		$tmpStr = implode( $tmpArr );
		$tmpStr = sha1( $tmpStr );
		
		if( $tmpStr == $signature ){
			return true;
		}else{
			return false;
		}
	}
}

?>
