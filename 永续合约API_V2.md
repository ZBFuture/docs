* [1\. 请求规则](#1-请求规则)
    * [1\.1\. 请求参数方式约定](#1-1-请求参数方式约定)
    * [1\.2\. 请求头header参数](#1-2-请求头header参数)
    * [1\.3\. 签名规则](#1-3-签名规则)
        * [1\.3\.1\. apiKey](#1-3-1-apikey)
        * [1\.3\.2\. 请求验签](#1-3-2-请求验签)
        * [1\.3\.3\. requestPath](#1-3-3-requestPath)
        * [1\.3\.4\. request query/request body参数排序](#1-3-4-request-queryrequest-body参数排序)
        * [1\.3\.5\. 组成最终的要进行签名计算的字符串](#1-3-5-组成最终的要进行签名计算的字符串)
        * [1\.3\.6\. 时间同步安全](#1-3-6-时间同步安全)
        * [1\.3\.7\. Java代码示例](#1-3-7-java代码示例)
        * [1\.3\.8\. Python代码示例](#1-3-8-python代码示例)
* [2\.响应规则](#2响应规则)
* [3\.  服务端地址](#3--服务端地址)
* [4\. 帐户和交易](#4-帐户和交易)
    * [4\.1 合约账户信息](#4-1-合约账户信息)
    * [4\.2 所有合约仓位/单个合约仓位(marketId\+side过滤)](#4-2-所有合约仓位单个合约仓位marketidside过滤)
    * [4\.3 保证金信息查询（最大保证金增加数量，最大保证金提取数量，预计强平价格）](#4-3-保证金信息查询最大保证金增加数量最大保证金提取数量预计强平价格)
    * [4\.4 保证金提取或者增加](#4-4-保证金提取或者增加)
    * [4\.5 仓位杠杆设置](#4-5-仓位杠杆设置)
    * [4\.6 仓位持仓模式设置](#4-6-仓位持仓模式设置)
    * [4\.7 仓位保证金模式设置](#4-7-仓位保证金模式设置)
    * [4\.8 查看用户当前头寸](#4-8-查看用户当前头寸)
    * [4\.9 查询用户bill账单](#4-9-查询用户bill账单)
    * [4\.10 查询账单类型信息list](#4-10-查询账单类型信息list)
    * [4\.11 逐仓保证金变动历史](#4-11-逐仓保证金变动历史)
    * [4\.12 仓位配置信息查询](#4-12-仓位配置信息查询)
    * [4\.13 通过userid，currencyName 查询资金](#4-13-通过useridcurrencyname-查询资金)
    * [4\.14 设置自动追加保证金](#4-14-设置自动追加保证金)
    * [4\.15 设置保证金使用顺序](#4-15-设置保证金使用顺序)
    * [4\.16 和zb之间资金划转](#4-16-和zb之间资金划转)
    * [4\.17 查询冻结类型信息list](#4-17-查询冻结类型信息list)
    * [4\.18 查询冻结list](#4-18-查询冻结list)
* [5\. 合约交易](#5-合约交易)
    * [5\.1 下单](#5-1-下单)
        * [止盈止损参数说明](#止盈止损参数说明)
    * [5\.2 批量下单](#5-2-批量下单)
    * [5\.3 撤单](#5-3-撤单)
    * [5\.4 批量撤单](#5-4-批量撤单)
    * [5\.5 全部撤单](#5-5-全部撤单)
    * [5\.6 查询当前全部挂单](#5-6-查询当前全部挂单)
    * [5\.7 查询所有订单(包括历史订单)](#5-7-查询所有订单包括历史订单)
    * [5\.8 订单信息](#5-8-订单信息)
    * [5\.9 订单成交明细](#5-9-订单成交明细)
    * [5\.10 查询历史成交记录](#5-10-查询历史成交记录)
    * [5\.11 委托策略下单](#5-11-委托策略下单)
    * [5\.12委托策略撤单](#5-12委托策略撤单)
    * [5\.13 委托策略查询](#5-13-委托策略查询)
    * [5\.14 修改下单止盈止损参数](#5-14-修改下单止盈止损参数)
    * [止盈止损参数说明](#止盈止损参数说明-1)
* [6\. 交易活动](#6-交易活动)
    * [6\.1  购买入场券/返场](#6-1--购买入场券返场)
* [7\. 公共行情：Http](#7-公共行情http)
    * [7\.1 交易对](#7-1-交易对)
    * [7\.2 全量深度](#7-2-全量深度)
    * [7\.3  k 线](#7-3--k-线)
    * [7\.4 成交](#7-4-成交)
    * [7\.5 Ticker](#7-5-ticker)
    * [7\.6  最新标记价格](#7-6--最新标记价格)
    * [7\.7  最新指数价格](#7-7--最新指数价格)
    * [7\.8  标记价格k 线](#7-8--标记价格k-线)
    * [7\.9  指数价格k 线](#7-9--指数价格k-线)
    * [7\.10 资金费率和下次结算时间](#7-10-资金费率和下次结算时间)
    * [7\.11 最新标记价格和资金费率](#7-11-最新标记价格和资金费率)
    * [7\.12 查询资金费率历史](#7-12-查询资金费率历史)
    * [7\.13 查询市场强平订单](#7-13-查询市场强平订单)
    * [7\.14 大户账户数多空比](#7-14-大户账户数多空比)
    * [7\.15 大户持仓量多空比](#7-15-大户持仓量多空比)
* [8\. 公共行情：ws](#8-公共行情ws)
    * [8\.1 订阅](#81-订阅)
    * [8\.2 取消订阅](#8-2-取消订阅)
    * [8\.3 全量深度](#8-3-全量深度)
    * [8\.4 增量深度](#8-4-增量深度)
    * [8\.5 k线](#8-5-k线)
    * [8\.6 成交](#8-6-成交)
    * [8\.7 Ticker](#8-7-ticker)
    * [8\.8 全部Ticker](#8-8-全部ticker)
    * [8\.9 指数价格和标记价格](#8-9-指数价格和标记价格)
    * [8\.10 指数价格K线和标记价格K线](#8-10-指数价格k线和标记价格k线)
    * [8\.11 资金费率和下次结算时间](#8-11-资金费率和下次结算时间)
    * [8\.12 ping](#8-12-ping)
* [9\. 用户数据：ws](#9-用户数据ws)
    * [9\.1概述](#9-1概述)
        * [9\.1\.1 ping](#9-1-1-ping)
    * [9\.2 登录](#9-2-登录)
        * [9\.2\.1签名规则](#9-2-1签名规则)
    * [9\.3资金](#93资金)
        * [9\.3\.1、资金变动](#9-3-1资金变动)
        * [9\.3\.2、资金查询](#9-3-2资金查询)
        * [9\.3\.3、查询用户bill账单](#9-3-3查询用户bill账单)
        * [9\.3\.4、合约的账户详情变动](#9-3-4合约的账户详情变动)
        * [9\.3\.5  查询合约的账户详情](#9-3-5--查询合约的账户详情)
    * [9\.4仓位](#9-4仓位)
        * [9\.4\.1、仓位变动](#9-4-1仓位变动)
        * [9\.4\.2、仓位查询](#9-4-2仓位查询)
        * [9\.4\.3、保证金信息查询](#9-4-3保证金信息查询)
        * [9\.4\.4、提取或增加保证金](#9-4-4提取或增加保证金)
        * [9\.4\.5、仓位配置信息查询](#9-4-5仓位配置信息查询)
        * [9\.4\.6、仓位杠杆设置](#9-4-6仓位杠杆设置)
        * [9\.4\.7、仓位持仓模式设置](#9-4-7仓位持仓模式设置)
        * [9\.4\.8、仓位保证金模式设置](#9-4-8仓位保证金模式设置)
        * [9\.4\.9、查看用户当前头寸](#9-4-9查看用户当前头寸)
    * [9\.5订单和交易](#9-5订单和交易)
        * [9\.5\.1、订单变动](#9-5-1订单变动)
        * [9\.5\.2、下单](#9-5-2下单)
        * [9\.5\.3、查询订单明细](#9-5-3查询订单明细)
        * [9\.5\.4、取消订单](#9-5-4取消订单)
        * [9\.5\.5、批量取消委托](#9-5-5批量取消委托)
        * [9\.5\.6、取消所有订单](#9-5-6取消所有订单)
        * [9\.5\.7、查询当前全部挂单(未完成的订单列表)](#9-5-7查询当前全部挂单未完成的订单列表)
        * [9\.5\.8、查询所有订单](#9-5-8查询所有订单)
        * [9\.5\.9、查询成交明细](#9-5-9查询成交明细)
        * [9\.5\.10、查询历史成交记录](#9-5-10查询历史成交记录)
        * [9\.5\.11、批量下单](#9-5-11批量下单)
* [10\.错误码](#10错误码)

## 1. 请求规则

### 1.1. 请求参数方式约定

- GET请求：所有查询使用GET且采用request query方式传参即key1=value1&key2=value2

- POST请求：除查询外其他操作均使用POST请求且采用 request body方式传参，POST请求头header需要声明为`Content-Type:application/json`



### 1.2. 请求头header参数

需要设置如下请求头信息

```json
ZB-APIKEY: 72d41c5f-****-****-****-08b18902fab9

ZB-TIMESTAMP: 发起请求的时间（UTC），如：2021-01-05T14:05:28.616Z

ZB-SIGN: u4ALcTlk946vNin8pmhQsqt2Ky2DdnXKwrXrZYmnDIQ=

ZB-LAN: cn
```

参数说明：

- ZB-APIKEY: api key
- ZB-TIMESTAMP: 请求时间，为ISO格式，如`2021-01-05T14:05:28.616Z
- ZB-SIGN：签名
- ZB-LAN: 语言，支持cn(中文)、en(英文)和kr(韩文)，默认是cn



### 1.3. 签名规则
**本平台提供了python，java，go版本的api签名请求demo，见：**<br>
python版本:  https://github.com/ZBFuture/zb_sdk_python <br>
java版本：https://github.com/ZBFuture/zb_sdk_java <br>
go版本：https://github.com/ZBFuture/zb_sdk_Go <br>

**另外1.3.6和1.3.7章节有签名部分的代码示例可以参考**


#### 1.3.1. apiKey

由zb平台生成用户的api key



#### 1.3.2. 请求验签

- 服务器对发起的请求进行签名检验，确认请求来源和数据完整性；

- 请勿将secretKey在请求或响应中传输；

- ZB-SIGN的请求头是对``timestamp`` + ``method``  + ``requestPath`` + ``request query/request body字符串`` (+表示字符串连接)，以及SecretKey，使用HMAC SHA256方法加密，通过Base64编码输出而得到的；

  如：`sign=CryptoJS.enc.Base64.Stringify(CryptoJS.HmacSHA256(timestamp + 'GET' + '/users/self/verify', SecretKey))`

  其中，`timestamp`的值与`ZB-TIMESTAMP`请求头相同，为ISO格式，如`2021-01-05T14:05:28.616Z`。

  method是请求方法，字母全部大写：`GET/POST`。

  requestPath见1.3.3说明

  request query/request body字符串：是按照ASCII码顺序进行排序，将各参数使用字符 “&” 连接

  SecretKey为用户申请APIKey时所生成，***<u>需用sha加密</u>***。如：`ceb892e0-0367-4cc1-88d1-ef9289feb053`，加密SecretKey得到：c9a206b430d6c6a43322a05806acb5f9514ac488

  在线加密工具: http://tool.oschina.net/encrypt?type=2



#### 1.3.3. requestPath

请求接口路径，USDT合约以/usdt开头，QC合约以/qc开头。如：`/usdt/Server/api/v1/trade/getOrder`



#### 1.3.4. request query/request body参数排序

参数按照ASCII码排序，比如下面是原始的参数：

```
symbol=BTC_USDT
orderId=1234567890
```

排序之后应该为：

```
orderId=1234567890
symbol=BTC_USDT
```

按照以上顺序，将各参数使用字符 “&” 连接

```
orderId=1234567890&symbol=BTC_USDT
```



#### 1.3.5. 组成最终的要进行签名计算的字符串

例如：请求头ZB-TIMESTAMP: 2021-01-05T14:05:28.616Z，method: GET，请求接口路径：/Server/api/v1/trade/getOrder，那么最终的要进行签名计算的字符串是

```
2021-01-05T14:05:28.616ZGET/Server/api/v1/trade/getOrderorderId=1234567890&symbol=BTC_USDT
```



#### 1.3.6. 时间同步安全

- 签名接口均需要传递`timestamp`参数, 其值应当是请求发送时刻的unix时间戳（毫秒）

- 服务器收到请求时会判断请求中的时间戳，如果是1分钟之前发出的，则请求会被认为无效。这个时间窗口值可以通过发送可选参数`recvWindow`来自定义。

- 另外，如果服务器计算得出客户端时间戳在服务器时间的‘未来’3秒以上，也会拒绝请求。

- 逻辑伪代码：

  ```java
  if (timestamp < (serverTime + 3000) && (serverTime - timestamp) <= recvWindow) {
    // process request
  } else {
    // reject request
  }
  ```



#### 1.3.7. Java代码示例

```java
import org.voovan.tools.log.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.RuntimeErrorException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;
import com.alibaba.fastjson.JSONObject;

/**
 * Description: 采用 Hmac SHA256 + base64 生成签名和验签
 *
 * @author micheal
 * Date 2020/12/3 4:46 下午
 * Version V1.0
 */
public class HmacSHA256Base64Utils {

    private static final int MAX_FAST_TIME = 3000;                  // 最大允许比服务器快的毫秒数
    private static final int MAX_SLOW_TIME = 1 * 60 * 1000;        // 最大允许比服务器慢的毫秒数

    private static final String ALGORITHM = "HmacSHA256";
    private static final String CHARSET = "UTF-8";

    public static Mac SHA256_HMAC;

    static {
        try {
            SHA256_HMAC = Mac.getInstance(ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeErrorException(new Error("Can't get Mac's instance."));
        }
    }

    /**
     * 验证签名
     *
     * @param timestamp     时间
     * @param method        请求方法：GET/POST
     * @param requestPath   请求接口路径
     * @param params        请求参数
     * @param apiKey        api key
     * @param secretKey     api密钥
     * @return
     */
    public static boolean verify(String timestamp, String method, String requestPath, Map<String, Object> params, String sign, String apiKey, String secretKey)
            throws UnsupportedEncodingException, CloneNotSupportedException, InvalidKeyException {

        if (timestamp == null || method == null) {
            return false;
        }

        long serverTime = System.currentTimeMillis();
        if (timestamp >= (serverTime + MAX_FAST_TIME) || (serverTime - timestamp) > MAX_SLOW_TIME) {
            Logger.errorf("timestamp - serverTime：{1}", timestamp - serverTime);
            return false;
        }

        return sign(timestamp, method, requestPath, params, apiKey, secretKey).equalsIgnoreCase(sign);
    }

    /**
     * 生成签名
     * 对timestamp + method + requestPath + request query/request body字符串 (+表示字符串连接)，以及SecretKey，使用HMAC SHA256方法加密，通过Base64编码输出而得到的
     *
     * @param timestamp     时间
     * @param method        请求方法：GET/POST
     * @param requestPath   请求接口路径
     * @param params        请求参数
     * @param apiKey        api key
     * @param secretKey     api密钥
     * @return
     */
    public static String sign(String timestamp, String method, String requestPath, Map<String, Object> params, String apiKey, String secretKey)
            throws UnsupportedEncodingException, CloneNotSupportedException, InvalidKeyException {
        if (apiKey == null || secretKey == null) {
            throw new RuntimeException("apiKey/secretKey must not be null !");
        }

        String signStr = buildSortParam(params);
        String content = timestamp + method + requestPath + signStr;
        String sign = generateSign(secretKey, content);
        return sign;
    }

    /**
     * 按照ASCII码排序
     *
     * @param params
     * @return
     */
    private static String buildSortParam(Map<String, Object> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }

        StringBuilder toSign = params.entrySet().stream()
                .filter(en -> en.getValue() != null && !"".equals(en.getValue()))
                .sorted(Map.Entry.comparingByKey())
                // url
                .reduce(new StringBuilder(),
                        (acc, it) -> {
                            acc.append("&").append(it.getKey()).append("=");
                            if (it.getValue() != null &&
                                    (it.getValue() instanceof Collection ||
                                            it.getValue().getClass().isArray() ||
                                            it.getValue() instanceof Map ) ) {
                                acc.append(JSONObject.toJSONString(it.getValue()));
                            } else {
                                acc.append(it.getValue());
                            }
                            return acc;
                        },
                        (l, r) -> null)
                .deleteCharAt(0);
        return toSign.toString();
    }Sy

    private static String generateSign(String secretKey, String content)
            throws UnsupportedEncodingException, CloneNotSupportedException, InvalidKeyException {
        byte[] secretKeyBytes = secretKey.getBytes(CHARSET);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKeyBytes, ALGORITHM);
        Mac mac = (Mac) SHA256_HMAC.clone();
        mac.init(secretKeySpec);
        return Base64.getEncoder().encodeToString(mac.doFinal(content.getBytes(CHARSET)));
    }

}
```

#### 1.3.8. Python代码示例

```
import hmac
import json
import time
import base64
import hashlib
import requests
from datetime import datetime


def headers_private(timestampISO, api_key, sign):

    headers = {}
    headers['ZB-APIKEY'] = api_key
    headers['ZB-LAN'] = 'cn'
    headers['ZB-TIMESTAMP'] = timestampISO
    headers['ZB-SIGN'] = sign

    """
    headers['Content-Type'] = 'application/json'
    """
    return headers

def __build_sort_param(params):
    '''
    :param params: request query/request body参数排序
    :return: 排序结果
    '''
    if params is None:
        return ''
    keys = sorted(params)
    return '&'.join([k + '=' + str(params[k]) for k in keys if params[k] is not None and params[k] != ''])

def generate_sign(timestamp, method, urlpath, params, secret_key):
    '''
    :param timestamp: 传递timestamp参数, 其值应当是请求发送时刻的unix时间戳（毫秒）
    :param method: 请求方法，字母全部大写：GET/POST
    :param urlpath: requestPath是请求接口路径。如：/Server/api/v1/trade/getOrder
    :param params: 是按照ASCII码顺序进行排序，将各参数使用字符 “&” 连接
    :param secret_key: SecretKey为用户申请APIKey时所生成，需用sha1加密,在线加密工具: http://tool.oschina.net/encrypt?type=2
    :return: sign(ZB-SIGN加密参数)
    '''
    param_str = __build_sort_param(params)    #排序结果
    content = timestamp + method + urlpath + param_str  #字符串连接用于加密
    print("sign string :", content)
    key = secret_key.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, content.encode('utf-8'), digestmod=hashlib.sha256).digest())
    return str(sign, 'utf-8')

def myInfo(api_key, secret_key):
    '''
    :param api_key: ZB-api_key
    :param secret_key: ZB-secret_key
    :return: 合约账户信息
    '''
    api_url = 'https://fapi.zb.com'
    params = {'convertUnit': 'usdt',
              'futuresAccountType': '1',
              }
    method = 'GET'
    reqPath = '/Server/api/v2/Fund/getAccount'
    timestampISO = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    sign = generate_sign(timestampISO, method, reqPath, params, secret_key)

    headers = headers_private(timestampISO, api_key, sign)
    print('headers:', headers)
    url = api_url + reqPath
    request = requests.get(url=url, params=params, headers=headers)
    print('request url:', request.url)
    return request

if __name__ == '__main__':
    '''
    在zb.com获取api的api_key、secret_key
    '''
    
    api_key = ''
    secret_key = ''
    if secret_key:
        secret_key = hashlib.sha1(secret_key.encode('utf-8')).hexdigest()
        myInfo = myInfo(api_key, secret_key)
        print(myInfo.text)


```



### 1.4. 访问限频规则

- Rest API 单个接口请求次数限制默认为100次/2s
- Websocket API 单个接口请求次数限制默认为200次/2s



## 2.响应规则

**响应参数**

| 参数名称 | 类型   | 是否可空 | 描述                                    |
| -------- | ------ | -------- | --------------------------------------- |
| code     | Int    | 否       | 结果代码，10000表示成功，其他均是错误码 |
| desc     | string | 否       | 结果描述                                |
| data     | json   | 是       | 具体数据                                |

**响应实例**

```json
 {
     "code": 10000,
     "desc": "success",
     "cnDesc": null,
     "data": {
         "userId": 3,
         "currencyId": 11,
         "fundId": 6740243890479048704,
         "freezeId": 0,
         "type": 6,
         "changeAmount": 1.1,
         "feeRate": null,
         "fee": null,
         "operatorId": 12,
         "beforeAmount": 11.1,
         "beforeFreezeAmount": 1,
         "symbolId": 0,
         "outsideId": "wdfsdfsdf12121",
         "id": 6740263121669072906,
         "createTime": 1607003956239,
         "modifyTime": 0,
         "extend": null
     }
 }
```



## 3.  服务端地址

https://fapi.zb.com



## 4. 帐户和交易

### 4.1 合约账户信息

- URL: /Server/api/v2/Fund/getAccount
- 接口类型: Http
- 请求类型: GET
- 请求参数:

| 参数名称 | 类型   | 是否可空 | 描述                                    |
| -------- | ------ | -------- | --------------------------------------- |
| futuresAccountType     | Int    | 否       | 合约类型，1:USDT合约  2: QC合约|
|convertUnit |否  |String | 折合单位，页面显示上"≈"号后面的数字单位，可选：cny，usd,usdt,btc,默认cny    |

- 响应结果:

  ```json
    {
      "code": 1,
      "desc": "success",
      "data": {
        "account": {//账户信息，包括可用余额、保证金余额、未实现盈亏
          "accountBalance": 996.12,
          "accountNetBalance":"873.12",
          "allMargin": 1000.13,
          "available": 1002.1,
          "freeze": 2304.1212,
          "allUnrealizedPnl": -123.789,
          
          "accountBalanceConvert": 996.12,
          "accountNetBalanceConvert":"873.12",
          "allMarginConvert": 1000.13,
          "availableConvert": 1002.1,
          "freezeConvert": 2304.1212,
          "allUnrealizedPnlConvert": -123.789,
         
          "convertUnit": "cny",
          "unit": "usdt",
          "percent": "12.12%"
        },   
        "assets": [{//资产信息，包括可用、冻结
           "userId": 3,
           "currencyId": 11,
           "amount": 12.2,
           "freezeAmount": 1,
           "id": 6740243890479048704,
           "createTime": 1606999371166,
           "modifyTime": 1607003956239,
           "extend": null
       },
      {}]     
      }
    }
  ```
-  assets 数据说明
-
|参数名|必选|类型|说明|
|:----    |:---|:----- |:-----   |
|userId |是  |Long |用户id   |
|currencyId |是  |Long | 币种id    |
|currencyName |是  |String | 币种名    |
|amount     |是  |BigDecimal | 可用资产量    |
|freezeAmount     |是  |BigDecimal | 冻结量    |
|id     |否  |Long | 资金id    |
|allMargin     |否  |Long | 账户保证金    |
|createTime     |否  |Long | 创建时间    |
|modifyTime     |是  |Long | 更新时间    |
|extend     |是  |String | 备用字段    |

-  account 数据说明
-
|参数名|必选|类型|说明|
|:----    |:---|:----- |:-----   |
|accountBalance |是  |BigDecimal |账户余额：可用+冻结   |
|accountNetBalance     |否  |Long | 账户净资产=可用+冻结+账户未实现盈亏    |
|allMargin |是  |BigDecimal | 所有仓位保证金    |
|available     |是  |BigDecimal | 可用资产量    |
|freeze     |是  |BigDecimal | 冻结量    |
|allUnrealizedPnl     |是  |BigDecimal | 所有对应仓位的累积未实现盈亏    |
|unit     |是  |String | 固定返回，如果是u本位，返回usdt，如果是币本位返回btc，如果是qc合约返回qc，统计数据的单位    |
|allMarginConvert |是  |BigDecimal | 所以仓位保证金折合    ||
|accountBalanceConvert |是  |BigDecimal |账户余额折合：可用+冻结   |
|accountNetBalanceConvert     |否  |Long | 账户净资产折合=可用+冻结+账户未实现盈亏    |
|availableConvert     |是  |BigDecimal | 可用资产量折合    |
|freezeConvert     |是  |BigDecimal | 冻结量折合    |
|allUnrealizedPnlConvert     |是  |BigDecimal | 所有对应仓位的累积未实现盈亏折合    |
|convertUnit     |是  |String | 折合单位，页面显示上"≈"号后面的数字单位，如：cny，usd,btc    |
|percent     |是  |BigDecimal | 未实现盈亏/所有仓位保证金*100%    |

### 4.2 所有合约仓位/单个合约仓位(marketId+side过滤)
- URL: /Server/api/v2/Positions/getPositions
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  |参数名|必选|类型|说明|
  |:----    |:---|:----- |:-----   |
  |marketId |否  |Long | 市场id和市场名称必选其一    |
  |symbol |否  |String | 市场id和市场名称必选其一    |
  |side |否  |Integer | 1 多仓  0 空仓 2 单向持仓 |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": [
           {
               "userId": 3,
               "marketId": 100,
               "marketName": null,
               "side": 0,
               "leverage": 20,
               "amount": 1,
               "freezeAmount": 0,
               "avgPrice": null,
               "liquidatePrice": null,
               "margin": 0,
               "marginMode": 1,
               "status": 1,
               "unrealizedPnl": 0,
               "marginBalance": 0,
               "maintainMargin": 0,
               "marginRate": 0,
               "nominalValue": 0,
               "id": 6740550682467641344,
               "createTime": 1607072516076,
               "modifyTime": null,
               "extend": null
           },
           {
               "userId": 3,
               "marketId": 100,
               "marketName": null,
               "side": 1,
               "leverage": 20,
               "amount": 2,
               "freezeAmount": 0,
               "avgPrice": null,
               "liquidatePrice": null,
               "margin": 0,
               "marginMode": 1,
               "status": 1,
               "unrealizedPnl": 0,
               "marginBalance": 0,
               "maintainMargin": 0,
               "marginRate": 0,
               "nominalValue": 0,
               "id": 6740550683470080000,
               "createTime": 1607072516315,
               "modifyTime": null,
               "extend": null
           }
       ]
   }
  ```

  |参数名|必选|类型|说明|
  |:----    |:---|:----- |:-----   |
  |userId |是  |Long |用户id   |
  |marketId |是  |Long | 市场id    |
  |marketName     |是  |String | 市场名称    |
  |side     |是  |Integer | 仓位类型,双向开多：1 双向开空：0   单向持仓：2 |
  |leverage     |否  |Integer | 杠杆倍数    |
  |amount     |否  |BigDecimal | 持有仓位数量    |
  |freezeAmount     |是  |BigDecimal | 下单冻结仓位数量    |
  |avgPrice     |是  |BigDecimal | 开仓均价    |
  |liquidatePrice |是  |BigDecimal |强平价格   |
  |margin |是  |BigDecimal | 保证金    |
  |marginMode     |是  |Integer | 保证金模式：1逐仓（默认），2全仓    |
  |status     |是  |Integer | 状态: 1 可用、2:锁定、3:冻结、4：不显示    |
  |unrealizedPnl     |否  |BigDecimal | 未实现盈亏    |
  |marginBalance     |是  |BigDecimal | 保证金余额    |
  |maintainMargin     |是  |BigDecimal | 维持保证金    |
  |marginRate     |是  |BigDecimal | 保证金率    |
  |nominalValue     |是  |BigDecimal | 头寸的名义价值    |
  |liquidateLevel |是  |Integer |强平档位，即头寸对应的维持保证金档位   |
  |autoLightenRatio     |是  |BigDecimal | 自动减仓比例，范围0～1，数字越大自动减仓风险越高    |
  |returnRate     |是  |BigDecimal | 回报率    |
  |id |是  |Long |仓位id   |
  |createTime |是  |Long | 创建时间    |
  |modifyTime     |是  |Long | 修改时间    |
  |extend     |否  |Long | 备用字段    |





### 4.3 保证金信息查询（最大保证金增加数量，最大保证金提取数量，预计强平价格）
- 如果没有记录不会创建一条空记录
- URL: /Server/api/v2/Positions/marginInfo
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |positionsId |是  |Long | 仓位Id    |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": {
           "maxAdd": 1212.12,
           "maxSub": 1212.12,
           "liquidatePrice": 121212.12
       }
   }
  ```

  |参数名|必选|类型|说明|
    |:----    |:---|:----- |:-----   |
  |maxAdd |是  |BigDecimal |最大可增加保证金   |
  |maxSub |是  |BigDecimal | 最大可减少保证金    |
  |liquidatePrice     |是  |BigDecimal | 预估强平价格    |

### 4.4 保证金提取或者增加
- URL: /Server/api/v2/Positions/updateMargin
- 接口类型: Http
- 请求类型: POST
- 请求参数:
    ```
  {
      "positionsId":6742095107924699136,
      "amount":0.1,
      "futuresAccountType":1,
      "type":0
  }
  
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |positionsId |是  |Long | 仓位id    |
  |amount |是  |BigDecimal | 变更数量    |
  |type |是  |Integer | 1: 增加  0：减少    |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": {
           "userId": 13049813743,
           "marketId": 100,
           "marketName": "BTC_USDT",
           "side": 0,
           "leverage": 20,
           "amount": 0.2,
           "freezeAmount": 0,
           "avgPrice": 18094,
           "liquidatePrice": 19516,
           "margin": 299.90000391,
           "marginMode": 1,
           "positionsMode": 2,
           "status": 1,
           "unrealizedPnl": 44.245187542,
           "marginBalance": 0,
           "maintainMargin": 0,
           "marginRate": 0,
           "nominalValue": 3618.57160886009711505219580608,
           "id": 6742095107924699136,
           "createTime": 1607503759950,
           "modifyTime": 1607747709697,
           "extend": null
       }
   }
  ```

  响应参数说明 data：
  见 仓位查询接口

### 4.5 仓位杠杆设置
- URL: /Server/api/v2/setting/setLeverage
    - 接口类型: Http
    - 请求类型: POST
- 请求参数:
    ```
  {
      "symbol":"BTC_USDT",
      "leverage":12,
      "futuresAccountType":1
  }
      
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |marketId |否  |Long | 市场id和市场名称必选其一    |
  |symbol |否  |String | 市场id和市场名称必选其一    |
  |leverage |是  |Integer | 杠杆倍数    |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

    - 响应结果:
      ```json
       {
           "code": 10000,
           "desc": "success",
           "data": {
               "userId": 111,
               "marketId": 100,
               "leverage": 20,
               "marginMode": 1,
               "positionsMode": 2,
               "enableAutoAppend": 1,
               "maxAppendAmount": "11212",
               "marginCoins": "eth,qc",
               "id": 6737268451833817088,
               "createTime": 1606289971312,
               "modifyTime": 0,
               "extend": null
      }
       }
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |userId |是  |Long |用户id   |
      |marketId |是  |Long | 市场id    |
      |leverage     |是  |BigDecimal | 杠杠倍数    |
      |marginMode     |是  |Integer | 保证金模式：1逐仓（默认），2全仓    |
      |positionsMode     |否  |Integer | 1:单向持仓，2: 双向持仓    |
      |id     |否  |Long | 仓位id    |
      |maxAppendAmount |是  |BigDecimal |最多追加保证金，可能被修改，如果为0会关闭自动增加保证金   |
      |enableAutoAppend |是  |Integer | 是否开启自动追加保证金 1:开启  0 ：不开启    |
      |marginCoins |是  |String | 配置的按顺序冻结的保证金，如 eth,usdt,qc    |
      |createTime     |否  |Long | 创建时间    |
      |modifyTime     |是  |Long | 更新时间    |
      |extend     |是  |String | 备用字段    |

### 4.6 仓位持仓模式设置
- URL: /Server/api/v2/setting/setPositionsMode
    - 接口类型: Http
    - 请求类型: POST
    - 请求参数:
        ```
      {
          "symbol":"btc_usdt",
          "positionsMode":1,
          "futuresAccountType":1
      }
      
      ```

      |参数名|必选|类型|说明|
                |:----    |:---|:----- |:-----   |
      |marketId |否  |Long | 市场id和市场名称必选其一    |
      |symbol |否  |String | 市场id和市场名称必选其一    |
      |positionsMode |是  |Integer | 1:单向持仓，2: 双向持仓    |
      |futuresAccountType |是  |Integer | 1:USDT永续合约  2：QC永续合约, 3 币本位合约    |

    - 响应结果:
      ```json
       {
           "code": 10000,
           "desc": "success",
           "data": {
               "userId": 111,
               "marketId": 100,
               "leverage": 20,
               "marginMode": 1,
               "positionsMode": 2,
               "enableAutoAppend": 1,
               "maxAppendAmount": "11212",
                "marginCoins": "qc,usdt,eth",
               "id": 6737268451833817088,
               "createTime": 1606289971312,
               "modifyTime": 0,
               "extend": null
           }
       }
      ```

      |参数名|必选|类型|说明|
                |:----    |:---|:----- |:-----   |
      |userId |是  |Long |用户id   |
      |marketId |是  |Long | 市场id    |
      |leverage     |是  |BigDecimal | 杠杠倍数    |
      |marginMode     |是  |Integer | 保证金模式：1逐仓（默认），2全仓    |
      |positionsMode     |否  |Integer | 1:单向持仓，2: 双向持仓    |
      |id     |否  |Long | 仓位id    |
      |maxAppendAmount |是  |BigDecimal |最多追加保证金，可能被修改，如果为0会关闭自动增加保证金   |
      |enableAutoAppend |是  |Integer | 是否开启自动追加保证金 1:开启  0 ：不开启    |
      |marginCoins |是  |String | 配置的按顺序冻结的保证金，如 eth,usdt,qc    |
      |createTime     |否  |Long | 创建时间    |
      |modifyTime     |是  |Long | 更新时间    |
      |extend     |是  |String | 备用字段    |


### 4.7 仓位保证金模式设置
- 暂未开通，目前默认只支持逐仓

### 4.8 查看用户当前头寸
- URL: /Server/api/v2/Positions/getNominalValue
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |marketId |否  |Long | 市场id和市场名称必选其一    |
  |symbol |否  |String | 市场id和市场名称必选其一    |
  |side |否  |Integer | 方向：1：开多   0 开空    |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": {
          "nominalValue":7692.229,
          "openOrderNominalValue":342.1,
          "marketId":100
      } 
   }
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |marketId |是  |Long | 市场id    |
  |side |是  |Long | 1:多仓 0：空仓    |
  |nominalValue |否  |BigDecimal |用户仓位头寸名义价值 （传side时返回）  |
  |openOrderNominalValue     |否  |BigDecimal | 委托单头寸名义价值（传side时返回）    |
  |longNominalValue |否  |BigDecimal |用户多仓位头寸名义价值 （不传side时返回）  |
  |shortNominalValue |否  |BigDecimal |用户空仓位头寸名义价值 （不传side时返回）  |
  |openOrderLongNominalValue     |否  |BigDecimal | 委托单多仓头寸名义价值 （不传side时返回）   |
  |openOrderShortNominalValue     |否  |BigDecimal | 委托单空仓头寸名义价值 （不传side时返回）   |

### 4.9 查询用户bill账单
- URL: /Server/api/v2/Fund/getBill
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |currencyId |否  |Long | 币种id    |
  |currencyName |否  |String | 币种名字    |
  |type |否  |Integer |账单类型   |
  |startTime |否  |Long | 开始时间戳    |
  |endTime |否  |Long |结束时间戳   |
  |pageNum |否  |Integer | 页码    |
  |pageSize |否  |Integer | 每页行数，默认10    |
  |isHistory |否  |Integer | 1:查询历史更多   0：查询最近   默认0   |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": {
           "pageSize": 2,
           "pageNum": 1,
           "from": 0,
           "list": [
               {
                   "userId": 3,
                   "currencyId": 11,
                   "fundId": 6740243890479048704,
                   "freezeId": 0,
                   "type": 6,
                   "changeAmount": 1.1,
                   "feeRate": null,
                   "fee": null,
                   "operatorId": 12,
                   "beforeAmount": 13.3,
                   "beforeFreezeAmount": 1,
                   "marketId": 0,
                   "outsideId": "wdfsdfsdf1121211",
                   "id": 6740449817681471488,
                   "isIn": 1,
                   "available": 14.44,
                   "unit": "eth",
                   "createTime": 1607048468037,
                   "modifyTime": 0,
                   "extend": null
               },
               {
                   "userId": 3,
                   "currencyId": 11,
                   "fundId": 6740243890479048704,
                   "freezeId": 0,
                   "type": 6,
                   "changeAmount": 1.1,
                   "feeRate": null,
                   "fee": null,
                   "operatorId": 12,
                   "beforeAmount": 12.2,
                   "beforeFreezeAmount": 1,
                   "marketId": 0,
                   "outsideId": "wdfsdfsdf121211",
                   "id": 6740275309691545600,
                   "isIn": 1,
                   "available": 14.44,
                   "unit": "btc",
                   "createTime": 1607006862090,
                   "modifyTime": 0,
                   "extend": null
               }
           ]
       }
   }
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |userId |是  |Long |用户id   |
  |freezeId |是  |String | 冻结id    |
  |type     |是  |BigDecimal | 账单类型    |
  |changeAmount     |是  |BigDecimal | 变更资金量    |
  |feeRate     |否  |BigDecimal | 费率    |
  |fee     |否  |BigDecimal | 手续费    |
  |operatorId     |否  |Long | 操作者id    |
  |beforeAmount     |是  |BigDecimal | 变更前账户资金    |
  |beforeFreezeAmount     |是  |BigDecimal | 变更前冻结资金    |
  |marketId     |否  |Long | 市场id    |
  |outsideId     |否  |Long | 外部幂等id    |
  |id     |否  |Long | 账单id    |
  |isIn     |否  |Integer | 1：增加  0： 减少    |
  |available     |否  |BigDecimal | 当前可用资产    |
  |unit     |否  |String | 币种名称，数量单位    |
  |createTime     |否  |Long | 创建时间戳    |
  |modifyTime     |否  |Long | 更新时间戳    |
  |extend     |否  |String | 备用字段    |

### 4.10 查询账单类型信息list
- URL: /Server/api/v2/Fund/getBillTypeList
- 接口类型: Http
- 请求类型: GET
- 请求参数:
  无

- 响应结果:
  ```json
   {
       "code": 10000,
       "data": [
           {
               "code": 1,
               "cnDesc": "已实现盈亏",
               "enDesc": "realized pnl"
           },
           {
               "code": 2,
               "cnDesc": "手续费",
               "enDesc": "commission"
           },
           {
               "code": 3,
               "cnDesc": "资金费扣除",
               "enDesc": "funding fee sub"
           },
           ...
       ],
       "desc": "操作成功"
   }
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |code |是  |Integer |账单类型   |
  |cnDesc |是  |String | 账单类型中文描述    |
  |enDesc     |是  |String | 账单类型英文描述    |

### 4.11 逐仓保证金变动历史
- 使用位置：自动追加保证业务，用户手动调整保证金

- URL: /Server/api/v2/Fund/marginHistory
    - 接口类型: Http
    - 请求类型: GET
- 请求参数:
    ```
        
    ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |symbol |否  |String | 市场,如 ETH_USDT    |
  |startTime |否  |Long | 毫秒时间戳    |
  |endTime |否  |Long | 毫秒时间戳    |
  |type |否  |Integer | 调整方向 1: 增加逐仓保证金，0: 减少逐仓保证金    |
  |pageNum |否  |Integer | 页码，默认1    |
  |pageSize |否  |Integer | 页大小 默认10    |

    - 响应结果: 返回仓位对象信息
      ```json
        
       {
         "code": 10000,
         "data": {
           "list": [
              {
                "symbol": "ETH_USDT",
                "asset": "usdt",
                "amount": "USDT:9982.66756951, BTC:0.999540947",
                "type": 1,
                "isAuto": 0,
                "contractType": 1,
                "positionSide": "BOTH",
                "createTime": "1619062409274"
              },
              {
                "symbol": "ETH_USDT",
                "asset": "usdt",
                "amount": "1.000000000000000",
                "type": 1,
                "isAuto": 0,
                "contractType": 1,
                "positionSide": "BOTH",
                "createTime": "1619058949337"
              }
            ],
              "pageNum": 1,
              "pageSize": 10
         },
         "desc": "操作成功"
       }
        
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |symbol |是  |String |市场，如ETH_USDT   |
      |asset |是  |String | 保证金币种，可能1个或者多个，如 USDT,ETH    |
      |amount     |是  |String | 保证金数量，可能多个，如 USDT:121210.00001, ETH:0.0002    |
      |type     |是  | | 调整方向 1: 增加逐仓保证金，0: 减少逐仓保证金   |
      |isAuto     |否  |Integer | 是否自动，默认否 0，1为是    |
      |contractType     |否  |Long | 合约类型    |
      |positionSide |是  |String |持仓方向:LONG SHORT BOTH   如果单向持仓就是LONG/SHORT   双向持仓：BOTH   |
      |createTime |是  |Integer | 创建时间    |






### 4.12 仓位配置信息查询
- URL: /Server/api/v2/setting/get
    - 接口类型: Http
    - 请求类型: GET
    - 请求参数:
        - marketId: 市场id

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |marketId |是  |Long | 市场id    |
      |symbol |是  |String | 市场名称    |
      |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
   {
       "code": 10000,
       "desc": "success",
       "data": {
           "userId": 111,
           "marketId": 100,
           "leverage": 20,
           "marginMode": 1,
           "positionsMode": 2,
           "enableAutoAppend": 1,
           "maxAppendAmount": "11212",
            "marginCoins": "eth,qc",
           "id": 6737268451833817088,
           "createTime": 1606289971312,
           "modifyTime": 0,
           "extend": null
       }
   }
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |userId |是  |Long |用户id   |
  |marketId |是  |Long | 市场id    |
  |leverage     |是  |BigDecimal | 杠杠倍数    |
  |marginMode     |是  |Integer | 保证金模式：1逐仓（默认），2全仓    |
  |positionsMode     |否  |Integer | 1:单向持仓，2: 双向持仓    |
  |id     |否  |Long | 仓位id    |
  |maxAppendAmount |是  |BigDecimal |最多追加保证金，可能被修改，如果为0会关闭自动增加保证金   |
  |enableAutoAppend |是  |Integer | 是否开启自动追加保证金 1:开启  0 ：不开启    |
  |marginCoins |是  |String | 配置的按顺序冻结的保证金，如 eth,usdt,qc    |
  |createTime     |否  |Long | 创建时间    |
  |modifyTime     |是  |Long | 更新时间    |
  |extend     |是  |String | 备用字段    |





### 4.13 通过userid，currencyName 查询资金
- 如果没有记录不会创建一条空记录
- URL: /Server/api/v2/Fund/balance
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |currencyId |否  |String | 币种id    |
  |currencyName |否  |String | 币种名称    |
  |futuresAccountType |是  |Integer | 1:USDT永续合约    |

- 响应结果:
  ```json
  {
      "code":10000,
      "data":[
          {
              "userId":"6796980210517471232",
              "currencyId":"6",
              "currencyName":"usdt",
              "amount":"9894.07266456",
              "allowTransferOutAmount":"873.12"，
              "freezeAmount":"0",
              "id":"6796980210551171072",
              "createTime":"1620526363981",
              "accountBalance":"9894.07266456",
              "allUnrealizedPnl":"0",
              "allMargin":"0"
          },
          {
              "userId":"6796980210517471232",
              "currencyId":"7",
              "currencyName":"zb",
              "amount":"0",
              "allowTransferOutAmount":"873.12"，
              "freezeAmount":"0",
              "id":"6807584179576958991",
              "createTime":"1623054547209",
              "accountBalance":"0",
              "allUnrealizedPnl":0,
              "allMargin":0
          }
      ],
      "desc":"操作成功"
  }
  ```

  |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |userId |是  |Long |用户id   |
  |currencyId |是  |Long | 币种id    |
  |currencyName |是  |String | 币种名字    |
  |amount     |是  |BigDecimal | 可用资产量    |
  |allowTransferOutAmount     |是  |BigDecimal | 允许划出的最大量    |
  |freezeAmount     |是  |BigDecimal | 冻结量    |
  |id     |否  |Long | 资金id    |
  |accountBalance     |否  |BigDecimal | 账户余额    |
  |allUnrealizedPnl     |否  |BigDecimal | 账户未实现盈亏    |
  |allMargin     |否  |BigDecimal | 账户保证金    |
  |createTime     |否  |Long | 创建时间    |





### 4.14 设置自动追加保证金
- URL: /Server/api/v2/Positions/updateAppendUSDValue
    - 接口类型: Http
    - 请求类型: POST
    - 请求参数:
        ```
      {
          "maxAdditionalUSDValue":1212.12,
          "positionsId":123123123123,
          "futuresAccountType":1
      }
      
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |positionsId |是  |Long | 仓位ID    |
      |maxAdditionalUSDValue |是  |BigDecimal | 设置增加的保证金数量，如果为0会关闭自动增加保证金    |
      |futuresAccountType |是  |Integer | 1:USDT永续合约    |

    - 响应结果: 返回仓位对象信息
      ```json
       {
         "code": 10000,
         "data": "6740243890479048704-674024389",
         "desc": "操作成功"
       }
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |data |是  |String |本次操作的clientId，由秒时间戳+仓位ID 组成   |

### 4.15 设置保证金使用顺序
- 使用位置：下单冻结顺序、开仓冻结顺序、手续费扣除顺序、已实现亏损扣除顺序、平仓解冻顺序、增加减少保证金顺序

- URL: /Server/api/v2/Positions/setMarginCoins
    - 接口类型: Http
    - 请求类型: POST
    - 请求参数:
        ```
      {
          "marginCoins":"eth,usdt,qc",
          "symbol":"BTC_USDT",
          "futuresAccountType":1
      }
      
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |symbol |是  |String | 市场名称    |
      |marginCoins |是  |String | 设置保证金顺序    |
      |futuresAccountType |是  |Integer | 1:USDT永续合约    |

    - 响应结果: 返回仓位对象信息
      ```json
       {
         "code": 10000,
         "data": {
           "id": "6793092825585035264",
           "positionsMode": 2,
           "userId": "6781470961192413204",
           "keyMark": "6781470961192413204-101-",
           "leverage": 1,
           "marginMode": 1,
           "marketId": "101",
           "enableAutoAppend": 1,
           "maxAppendAmount": "11212",
            "marginCoins": "eth,qc",
           "createTime": "1619599539181",
           "modifyTime": "1622112737137"
         },
         "desc": "操作成功"
       }
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |userId |是  |Long |用户id   |
      |marketId |是  |Long | 市场id    |
      |leverage     |是  |BigDecimal | 杠杠倍数    |
      |marginMode     |是  |Integer | 保证金模式：1逐仓（默认），2全仓    |
      |positionsMode     |否  |Integer | 1:单向持仓，2: 双向持仓    |
      |id     |否  |Long | 仓位id    |
      |maxAppendAmount |是  |BigDecimal |最多追加保证金，可能被修改，如果为0会关闭自动增加保证金   |
      |enableAutoAppend |是  |Integer | 是否开启自动追加保证金 1:开启  0 ：不开启    |
      |marginCoins |是  |String | 配置的按顺序冻结的保证金，如 eth,usdt,qc    |
      |createTime     |否  |Long | 创建时间    |
      |modifyTime     |是  |Long | 更新时间    |
      |extend     |是  |String | 备用字段    |

### 4.16 和zb之间资金划转

- URL: /Server/api/v2/Fund/transferFund
    - 接口类型: Http
    - 请求类型: POST
    - 请求参数:
        ```
      {
          "currencyName":"USDT",
          "amount":"12.12",
          "clientId"："2sdfsdfsdf232342",
          "side"："1"
      }
      
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |currencyName |是  |String | 币种名称    |
      |amount |是  |BigDecimal | 划转数量,进度参考币种信息    |
      |clientId |是  |String | 唯一id，保持幂等性，不能为空或长度不能超过18    |
      |side |是  |Integer | 1：充值（zb账户->合约账户），0：提币（合约账户->zb账户）    |

    - 响应结果: 返回仓位对象信息
      ```json
       {
         "code": 10000,
         "data": "2sdfsdfsdf232342",
         "desc": "操作成功"
       }
      ```

      |参数名|必选|类型|说明|
            |:----    |:---|:----- |:-----   |
      |data |是  |String |操作成功返回幂等id，否则返回null   |




### 4.17 查询冻结类型信息list
- URL: /Server/web/v1/Fund/getFreezeTypeList
- 接口类型: Http
- 请求类型: GET
- 请求参数:
  无

- 响应结果:
```json
  
   {
    "code": 10000,
    "data": [
        {
        "code": 0,
        "cnDesc": "下单冻结资金",
        "enDesc": "order freeze fund"
        },
        {
        "code": 1,
        "cnDesc": "仓位保证金",
        "enDesc": "positions freeze fund"
        },
        {
        "code": 2,
        "cnDesc": "系统冻结资金",
        "enDesc": "system freeze"
        },
        {
        "code": 3,
        "cnDesc": "平多冻结仓位",
        "enDesc": "long positions"
        },
        ...
    ],
    "desc": "操作成功"
}

```

|参数名|必选|类型|说明|
|:----    |:---|:----- |:-----   |
|code |是  |Integer |类型   |
|cnDesc |是  |String | 类型中文描述    |
|enDesc     |是  |String | 类型英文描述    |



### 4.18 查询冻结list
- URL: /Server/web/v1/Fund/getFreeze
- 接口类型: Http
- 请求类型: GET
- 请求参数:
- |参数名|必选|类型|说明|
      |:----    |:---|:----- |:-----   |
  |currencyId |否  |Long |币种id   |
  |currencyName |否  |Long | 币种名称    |
  |marketId     |否  |Long | 市场id    |
  |marketName |否  |BigDecimal |市场名称   |
  |freezeType     |否  |Integer | 冻结类型，具体类型参数getFreezeTypeList接口    |
  |startCreateTime |否  |Integer |开始时间   |
  |endCreateTime |否  |Long | 结束时间    |
  |pageNum     |否  |Long | 第n页    |
  |pageSize |否  |String |每页记录数   |
  |isHistory     |否  |Long | 是否历史 1：历史， 默认0：当前最近记录    |


- 响应结果:
```json
 
   {
    "code": 10000,
    "desc": "操作成功",
    "data": {
        "pageSize": 10,
        "pageNum": 1,
        "list": [
            {
                "userId": "6838756832803039232",
                "fundId": "6881461855223556096",
                "currencyId": "15",
                "freezeAmount": "0",
                "originAmount": "0",
                "type": 1,
                "status": 1,
                "unfreezeTime": "1644255997612",
                "marketId": "500",
                "orderId": "6881493271575537669",
                "pageNum": null,
                "pageSize": null,
                "id": "6881493271579731993",
                "createTime": "1640675847907",
                "modifyTime": "1644255997612",
                "extend": null
                },
                {
                "userId": "6838756832803039232",
                "fundId": "6881461855223556096",
                "currencyId": "15",
                "freezeAmount": "12",
                "originAmount": "0",
                "type": 5,
                "status": 1,
                "unfreezeTime": "1644256004072",
                "marketId": "501",
                "orderId": "502",
                "pageNum": null,
                "pageSize": null,
                "id": "6881484039937599508",
                "createTime": "1640673646912",
                "modifyTime": "1644256004072",
                "extend": {"orderRemainingAmount":"0","ofa":{},"bofa":{},"sofa":{},"pfa":{},"theoryBofa":"1.123456","theorySofa":"200.1"}
                }
            ]
    }
}

```

#### freeze字段说明
|参数名|必选|类型|说明|
|:----    |:---|:----- |:-----   |
|userId |是  |Long |用户id   |
|fundId |是  |Long | 冻结资金对应的资金记录id    |
|currencyId     |是  |Long | 币种id    |
|freezeAmount |是  |BigDecimal |冻结量   |
|originAmount |是  |BigDecimal | 原始冻结量    |
|type     |是  |Integer | 冻结类型，具体类型参数getFreezeTypeList接口    |
|status |是  |Integer |状态  0: 已解冻, 1:冻结   |
|unfreezeTime |是  |Long | 解冻时间    |
|marketId     |是  |Long | 市场id    |
|orderId |是  |String |业务id   |
|createTime     |是  |Long | 创建时间    |
|modifyTime |是  |Long |更新时间   |

#### freeze.extend字段说明,有值的情况
- 当前使用到freezeType=5的情况下有值，单向持仓所有下单累积冻结在一条记录里面

|参数名|必选|类型|说明|
|:----    |:---|:----- |:-----   |
|orderRemainingAmount |是  |BigDecimal | 双向持仓使用，此订单剩余交易数量    |
|theoryBofa     |是  |BigDecimal | 单向持仓使用，累积订单的理论买冻结    |
|theorySofa |是  |BigDecimal |单向持仓使用，累积订单的理论卖冻结   |







## 5. 合约交易

### 5.1 下单

- URL: /Server/api/v2/trade/order
- 接口类型: Http
- 请求类型: POST
- 请求参数:

| 名称          | 类型       | 是否必须 | 描述                                                         |
| :------------ | :--------- | :------- | :----------------------------------------------------------- |
| symbol        | String     | 是       | 交易对，如：BTC_USDT                                         |
| action        | Integer    | 否       | 订单价格类型:  <br/>1   限价<br/>11 对手价<br/>12 最优5档<br/>13 最优10档<br/>14 最优20档<br/>19 最优极限档，即在限价上限或下限的最优价格<br/>3   IOC<br/>31 对手价IOC<br/>32 最优5档IOC<br/>33 最优10档IOC<br/>34 最优20档IOC<br/>39 最优极限档IOC，即在限价上限或下限的最优价格IOC<br/>4   只做 maker<br/>5   FOK<br/>51 对手价FOK<br/>52 最优5档FOK<br/>53 最优10档FOK<br/>54 最优20档FOK<br/>59 最优极限档FOK，即在限价上限或下限的最优价格FOK<br/>默认是1 |
| side          | Integer    | 是       | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| amount        | BigDecimal | 是       | 委托数量 (某个仓位平仓所有持仓请使用仓位的 amount-freezeAmount 作为委托数量)        |
| price         | BigDecimal | 否       | 委托价格，当为对手价或最优5档价格（即为action11，12，31，32，51或52）可以为空，其他均必填 |
| clientOrderId | String     | 否       | 用户自定义的订单号，不可以重复出现在挂单中。必须满足正则规则 `^[a-zA-Z0-9-_]{1,36}$` |


- 响应结果:

```
{
	"code": 10000,
	"desc": "success",
	"cnDesc": "操作成功",
	"data": {
    	"orderId":"6848243828432838656"
  		"orderCode":"01aa0ff5b1974d9ab09167b77e6dd116"
  }
}
```

响应参数说明 data：

| 参数名    | 必选 | 类型   | 说明         |
| :-------- | :--- | :----- | :----------- |
| orderId   | 是   | String | 订单id       |
| orderCode | 是   | String | 自定义订单号 |

### 5.2 批量下单

- URL: /Server/api/v2/trade/batchOrder

- 接口类型: Http

- 请求类型: POST

- 请求参数:

  示例

```

{
  "orderDatas": [
    {
      "symbol": "ETH_USDT",
      "amount": 1,
      "side": 1,
      "price": "1100",
      "action": 1,
      "orderCode": "test01"
    },
    {
      "symbol": "ETH_USDT",
      "amount": 1,
      "side": 1,
      "price": "1000",
      "action": 1,
      "orderCode": "test02"
    }
  ]
}
```

| 名称       | 类型 | 是否必须 | 描述           |
| :--------- | :--- | :------- | :------------- |
| orderDatas | List | 是       | 订单列表，数组 |

- 响应结果:

```
{
    "code": 10000, 
    "data": [
        {
            "sCode": 1, 
            "orderId": "6754725173120933888", 
            "orderCode": "6754725172671948800", 
            "sMsg": "success"
        }, 
        {
            "sCode": 1, 
            "orderId": "6754725173074796544", 
            "orderCode": "6754725172676143104", 
            "sMsg": "success"
        }
    ], 
    "desc": "操作成功"
}
```

响应参数说明 data：

| 名称      | 类型   | 是否必须 | 描述                                 |
| :-------- | :----- | :------- | :----------------------------------- |
| sCode     | Int    | 是       | 结果的code，1代表成功                |
| sMsg      | String | 是       | 结果描述                             |
| orderId   | String | 否       | 订单ID                               |
| orderCode | String | 否       | 自定义订单ID，如空缺系统会自动赋值。 |

### 5.3 撤单

- URL: /Server/api/v2/trade/cancelOrder
- 接口类型: Http
- 请求类型: POST
- 请求参数:

| 名称          | 类型   | 是否必须 | 描述                 |
| :------------ | :----- | :------- | :------------------- |
| symbol        | String | 是       | 交易对，如：BTC_USDT |
| orderId       | long   | 否       | 订单ID               |
| clientOrderId | String | 否       | 自定义订单ID         |

orderId 与 clientOrderId 选填1个

- 响应结果:

```json
{
"code": 10000,
"desc": "success",
"cnDesc": "操作成功",
"data": "6747737516411133952"
}
```

响应参数说明 data：

| 参数名  | 必选 | 类型   | 说明   |
| :------ | :--- | :----- | :----- |
| orderId | 是   | String | 订单id |



### 5.4 批量撤单

- URL: /Server/api/v2/trade/batchCancelOrder

- 接口类型: Http

- 请求类型: POST

- 请求参数:

  示例：

  ```json
  {
    "symbol": "ETH_USDT",
    "orderIds": [6747737380100448256, 6747737516411133952]
  }
  ```

请求参数说明：

| 名称           | 类型   | 是否必须 | 描述                 |
| :------------- | :----- | :------- | :------------------- |
| symbol         | String | 是       | 交易对，如：BTC_USDT |
| orderIds       | List   | 否       | 订单ID列表           |
| clientOrderIds | List   | 否       | 自定义订单ID列表     |

orderIds 与 clientOrderIds 选填1个

- 响应结果:

若取消失败则会列出失败的明细

  ```json
{
    "cnDesc": "操作成功",
    "code": 10000,
    "data": [
        {
            "cnDesc": "订单不存在",
            "code": 12011,
            "data": 6747737380100448000,
            "desc": "order not exists"
        },
        ...
    ],
    "desc": "success"
}
  ```

响应参数说明 data数组元素：

| 参数名  | 必选 | 类型   | 说明             |
| :------ | :--- | :----- | :--------------- |
| orderId | 是   | String | 取消失败的订单id |

### 5.5 全部撤单

- URL: /Server/api/v2/trade/cancelAllOrders
- 接口类型: Http
- 请求类型: POST
- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 是       | 交易对，如：BTC_USDT |

- 响应结果:

```
{
"code": 10000,
"data": [ ],
"desc": "success"
}
```

若data中有数据则表示有删除失败的订单，具体数据格式参考``批量撤单接口``

### 5.6 查询当前全部挂单

- URL: /Server/api/v2/trade/getUndoneOrders
- 接口类型: Http
- 请求类型: GET
- 请求参数:

| 名称     | 类型   | 是否必须 | 描述                                                         |
| :------- | :----- | :------- | :----------------------------------------------------------- |
| symbol   | String | 是       | 交易对，如：BTC_USDT                                         |
| type     | 否     | Integer  | 类型: -1 卖, 1 买， 0或空则查询全部                          |
| side     | 否     | Integer  | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| action   | 否     | Integer  | 订单价格类型， 0或空则查询全部  <br/>1   限价<br/>11 对手价<br/>12 最优5档<br/>3   IOC<br/>31 对手价IOC<br/>32 最优5档IOC<br/>4   Only Maker<br/>5   FOK<br/>51 对手价FOK<br/>52 最优5档FOK |
| pageNum  | INT    | 否       | 页码，从1开始，默认是1                                       |
| pageSize | INT    | 否       | 分页返回的结果集数量，最大为100，不填默认返回30条            |

- 响应结果:

```
{
    "code": 10000,
    "data": {
        "list": [
            {
                "action": 1,
                "amount": "1",
                "availableAmount": "1",
                "availableValue": "600",
                "avgPrice": "0",
                "canCancel": true,
                "cancelStatus": 20,
                "createTime": 1608814053726,
                "entrustType": 1,
                "id": "6747855220799382000",
                "leverage": 20,
                "marketId": 101,
                "modifyTime": 1608814053760,
                "orderCode": "1608814052115",
                "price": "600",
                "showStatus": 1,
                "side": 1,
                "sourceType": 1,
                "status": 12,
                "tradeAmount": "0",
                "tradeValue": "0",
                "type": 1,
                "userId": 1,
                "value": "600",
              	"orderAlgos": [
                  {
                      "bizType": 1, 
                      "createTime": "1638779420239", 
                      "id": "6873539077426126853", 
                      "priceType": 1, 
                      "priority": 0, 
                      "status": 0, 
                      "triggerPrice": "55200"
                  }, 
                  {
                      "bizType": 2, 
                      "createTime": "1638779420239", 
                      "id": "6873539077426126858", 
                      "priceType": 1, 
                      "priority": 0, 
                      "status": 0, 
                      "triggerPrice": "42200"
                  }
              ]
            }
        ],
        "pageNum": 1,
        "pageSize": 10
    },
    "desc": "success"
}
```

响应参数说明 data

| 参数名           | 必选 | 类型       | 说明                                                         |
| :--------------- | :--- | :--------- | :----------------------------------------------------------- |
| id               | 是   | String     | 订单id                                                       |
| orderCode        | 是   | String     | 自定义订单ID                                                 |
| marketId         | 是   | Long       | 市场id                                                       |
| price            | 是   | Decimal    | 委托价格                                                     |
| amount           | 是   | Decimal    | 委托数量                                                     |
| value            | 否   | Decimal    | 委托价值，即委托价格 * 委托数量                              |
| availableAmount  | 否   | Decimal    | 可用委托数量                                                 |
| availableValue   | 是   | Decimal    | 可用委托价值                                                 |
| tradeAmount      | 是   | Decimal    | 成交完成量, 每次成交都会增加                                 |
| tradeValue       | 是   | Decimal    | 成交完成价值, 每次成交都会增加                               |
| type             | 是   | Integer    | 委托类型: -1 卖, 1 买                                        |
| action           | 是   | Integer    | 订单价格类型:  <br/>1   限价<br/>11 对手价<br/>12 最优5档<br/>13 最优10档<br/>14 最优20档<br/>19 最优极限档，即在限价上限或下限的最优价格<br/>3   IOC<br/>31 对手价IOC<br/>32 最优5档IOC<br/>33 最优10档IOC<br/>34 最优20档IOC<br/>39 最优极限档IOC，即在限价上限或下限的最优价格IOC<br/>4   只做 maker<br/>5   FOK<br/>51 对手价FOK<br/>52 最优5档FOK<br/>53 最优10档FOK<br/>54 最优20档FOK<br/>59 最优极限档FOK，即在限价上限或下限的最优价格FOK |
| showStatus       | 是   | Integer    | 状态: 1:未成交、2:部分成交（订单还在挂单中）、3:已完成、4：取消中、5:完全取消、6：取消失败、7：部分取消（订单已完成，部分成交） |
| entrustType      | 是   | Integer    | 委托类型： <br/>1限价委托 <br/>2强制减仓 <br/>3强制平仓 <br/>4计划委托 <br/>5止盈 <br/>6止损 <br/>7强平（未穿仓） <br/>8强平（风险基金）<br/>9强平（自动减仓） |
| side             | 是   | Integer    | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>7 只减仓平多<br/>8 只减仓平空 |
| sourceType       | 是   | Integer    | 来源：<br/>1:WEB<br/>2:Android<br/>3:iOS<br/>4:Rest API<br/>5:WebSocket API<br/>6:System<br/>7:Plan Entrust(计划委托)<br/>8:Take Profit(止盈)<br/>9:Stop Loss(止损) |
| leverage         | 是   | Integer    | 杠杠倍数                                                     |
| avgPrice         | 是   | BigDecimal | 成交均价                                                     |
| canCancel        | 是   | Boolean    | 能否取消                                                     |
| createTime       | 是   | Long       | 下单时间，时间戳                                             |
| margin           | 是   | Decimal    | 保证金                                                       |
| **orderAlgos[]** |      |            |                                                              |
| bizType          | 是   | Integer    | 类型，1：止盈，2：止损                                       |
| priceType        | 是   | Integer    | 价格类型，1：标记价格，2：最新价格                           |
| triggerPrice     | 是   | Decimal    | 触发价格                                                     |
| status           | 是   | Integer    | 状态，0：未生效，1：已生效                                   |



### 5.7 查询所有订单(包括历史订单)

- URL:  /Server/api/v2/trade/getAllOrders
- 请注意，如果订单满足如下条件，不会被查询到：
    - 订单的最终状态为 `已取消` , **并且**
    - 订单没有任何的成交记录
- 接口类型: Http
- 请求类型: GET
-
- 请求参数:

| 名称      | 类型   | 是否必须 | 描述                                                         |
| :-------- | :----- | :------- | :----------------------------------------------------------- |
| symbol    | String | 是       | 交易对，如：BTC_USDT                                         |
| type      | 否     | Integer  | 类型: -1 卖, 1 买， 0或空则查询全部                          |
| side      | 否     | Integer  | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| dateRange | 否     | Integer  | 查询类型<br/>0 最近委托，默认值<br/>1 更多委托               |
| action    | 否     | Integer  | 订单价格类型， 0或空则查询全部  <br/>1   限价<br/>11 对手价<br/>12 最优5档<br/>3   IOC<br/>31 对手价IOC<br/>32 最优5档IOC<br/>4   Only Maker<br/>5   FOK<br/>51 对手价FOK<br/>52 最优5档FOK |
| startTime | LONG   | 否       | 起始时间                                                     |
| endTime   | LONG   | 否       | 结束时间                                                     |
| pageNum   | INT    | 否       | 页码，从1开始，默认是1                                       |
| pageSize  | INT    | 否       | 分页返回的结果集数量，最大为100，不填默认返回30条            |

- 响应结果:

```
{
    "code": 10000,
    "data": {
        "list": [
            {
                "action": 1,
                "amount": "1",
                "availableAmount": "1",
                "availableValue": "613",
                "avgPrice": "0",
                "canCancel": false,
                "cancelStatus": 23,
                "createTime": 1608879733642,
                "entrustType": 1,
                "id": "6748130702333780000",
                "leverage": 20,
                "marketId": 101,
                "modifyTime": 1608881828525,
                "orderCode": "1608879732629",
                "price": "613",
                "showStatus": 5,
                "side": 1,
                "sourceType": 6,
                "status": 12,
                "tradeAmount": "0",
                "tradeValue": "0",
                "type": 1,
                "userId": 1,
                "value": "613"
            },
            ...
        ],
        "pageNum": 1,
        "pageSize": 2
    }
}
```


响应参数说明，参考``5.6查询当前全部挂单``

### 5.8 订单信息

- URL: /Server/api/v2/trade/getOrder
- 接口类型: Http
- 请求类型: GET
- 请求参数:

| 名称          | 类型   | 是否必须 | 描述                 |
| :------------ | :----- | :------- | :------------------- |
| symbol        | String | 是       | 交易对，如：BTC_USDT |
| orderId       | long   | 否       | 订单ID               |
| clientOrderId | String | 否       | 自定义订单ID         |

orderId 与 clientOrderId 选填1个

- 响应结果:

```
{
    "code": 10000,
    "data": {
        "action": 1,
        "amount": "1",
        "availableAmount": "1",
        "availableValue": "613",
        "avgPrice": "0",
        "canCancel": false,
        "cancelStatus": 23,
        "createTime": 1608879733642,
        "entrustType": 1,
        "id": "6748130702333780000",
        "leverage": 20,
        "marketId": 101,
        "modifyTime": 1608881828525,
        "orderCode": "1608879732629",
        "price": "613",
        "showStatus": 5,
        "side": 1,
        "sourceType": 6,
        "status": 12,
        "tradeAmount": "0",
        "tradeValue": "0",
        "type": 1,
        "userId": 1,
        "value": "613"
    },
    "desc": "success"
}
```

响应参数说明，参考``查询当前全部挂单``



### 5.9 订单成交明细

- URL: /Server/api/v2/trade/getTradeList
- 接口类型: Http
- 请求类型: GET
- 请求参数:

| 名称     | 类型   | 是否必须 | 描述                                    |
| :------- | :----- | :------- | :-------------------------------------- |
| symbol   | String | 是       | 交易对，如：BTC_USDT                    |
| orderId  | long   | 是       | 订单ID                                  |
| pageNum  | int    | 否       | 分页页码，不填默认1                     |
| pageSize | int    | 否       | 分页返回结果集数量，不填默认10，最大100 |

- 响应结果:

```
{
    "code": 10000, 
    "data": {
        "list": [
            {
                "amount": "0.001", 
                "createTime": "1614708954563", 
                "feeAmount": "0.00060286", 
                "feeCurrency": "USDT", 
                "maker": false, 
                "orderId": "6772580218407231488", 
                "price": "1507.14", 
                "relizedPnl": "0", 
                "side": 1, 
                "userId": "6755742981778581504"
            }, 
            ...
        ], 
        "pageNum": 1, 
        "pageSize": 10
    }, 
    "desc": "操作成功"
}

```

响应参数说明 data：

| 参数名      | 必选 | 类型    | 说明                                                         |
| :---------- | :--- | :------ | :----------------------------------------------------------- |
| id          | 是   | Long    | 成交明细id                                                   |
| orderId     | 是   | Long    | 订单id                                                       |
| price       | 是   | Decimal | 成交价格                                                     |
| amount      | 是   | Decimal | 成交数量                                                     |
| feeAmount   | 是   | Decimal | 手续费                                                       |
| feeCurrency | 是   | String  | 手续费币种                                                   |
| relizedPnl  | 是   | Decimal | 已实现盈亏                                                   |
| side        | 是   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>7 只减仓平多<br/>8 只减仓平空 |
| maker       | 是   | Boolean | 是否maker,否则为taker                                        |
| createTime  | 是   | Long    | 成交时间戳                                                   |



### 5.10 查询历史成交记录

- URL: /Server/api/v2/trade/tradeHistory

- 接口类型: Http

- 请求类型: GET

- 请求参数:

  请求参数说明 body：

  | 参数名    | 必选 | 类型    | 说明                                                         |
    | :-------- | :--- | :------ | :----------------------------------------------------------- |
  | symbol    | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
  | side      | 否   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
  | dateRange | 否   | Integer | 查询类型<br/>0 最近委托，默认值<br/>1 更多委托               |
  | startTime | 否   | Long    | 开始时间，Unix时间戳的毫秒数格式，如 `1608862284859`         |
  | endTime   | 否   | Long    | 结束时间，Unix时间戳的毫秒数格式，如 `1608862284859`         |
  | pageNum   | 是   | Integer | 页码，从1开始                                                |
  | pageSize  | 是   | Integer | 分页返回结果集数量，不填默认10，最大100                      |

    - 响应结果:

      ```json
      {
          "cnDesc": "操作成功",
          "code": 10000,
          "data": {
              "list": [
                  {
                      "amount": "1",
                      "createTime": 1608862284859,
                      "feeAmount": "0.01224",
                      "feeCurrency": "USDT",
                      "maker": false,
                      "orderId": "6748057516749562000",
                      "price": "612",
                      "relizedPnl": "0",
                      "side": 2,
                      "userId": 1
                  },
                  ...
              ],
              "pageNum": 1,
              "pageSize": 2
          },
          "desc": "success"
      }
      ```

      响应参数说明 data 同 上一个接口 ``订单成交明细``



### 5.11 委托策略下单

- 说明：使用不同的委托策略下单

- URL: /Server/api/v2/trade/orderAlgo

    - 接口类型: Http

    - 请求类型: POST

    - 请求参数:

- 请求参数（通用）

  | 参数名    | 必选 | 类型    | 说明                                                         |
    | :-------- | :--- | :------ | :----------------------------------------------------------- |
  | symbol    | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
  | side      | 是   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
  | orderType | 是   | Integer | `1`：计划委托<br/>`2`：止盈止损                              |
  | amount    | 是   | Decimal | 数量                                                         |


​			 **计划委托参数**

| 参数名       | 必选 | 类型    | 说明                           |
| :----------- | :--- | :------ | :----------------------------- |
| triggerPrice | 是   | Decimal | 触发价格，填写值0\<X\<=1000000 |
| algoPrice    | 是   | Decimal | 委托价格，填写值0\<X\<=1000000 |

​		**止盈止损参数**

| 参数名       | 必选 | 类型    | 说明                           |
| :----------- | :--- | :------ | :----------------------------- |
| triggerPrice | 是   | Decimal | 触发价格，填写值0\<X\<=1000000 |
| priceType    | 是   | Integer | `1`:标记价格<br/>`2`:最新价格  |
| algoPrice    | 是   | Decimal | 委托价格，填写值0\<X\<=1000000 |
| bizType      | 是   | Integer | `1`:止盈<br/>`2`:止损          |



- 响应结果:

  ```json
  {
      "code": 10000, 
      "data": "6819520763146739712", 
      "desc": "操作成功"
  }
  ```

响应参数说明 data：

| 参数名 | 必选 | 类型   | 说明       |
| :----- | :--- | :----- | :--------- |
| algoId | 是   | String | 委托策略id |



### 5.12委托策略撤单

- 说明：撤销计划委托单和止盈止损委托单

- URL: /Server/api/v2/trade/cancelAlgos

    - 接口类型: Http

    - 请求类型: POST

    - 请求示例

      单个撤单：`POST /Server/app/v1/trade/cancelAlgos{"symbol":"BTC_USDT", "ids":[6819506476072247296]}`

      批量撤单：`POST /Server/app/v1/trade/cancelAlgos{"symbol":"BTC_USDT","ids":[6819506476072247296,6819506476072247297]}`


- 请求参数:

  | 参数名 | 必选 | 类型         | 说明                                                         |
    | :----- | :--- | :----------- | :----------------------------------------------------------- |
  | symbol | 是   | String       | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
  | ids    | 否   | List<String> | 撤销指定的委托单ID                                           |
  | side   | 否   | Integer      | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |

  优先根据ids进行撤销，若ids和side都为空则取消该市场的所有委托策略


- 响应结果:

若取消失败则会列出失败的明细

```json
# 取消成功
{
    "code": 10000, 
    "data": [ ], 
    "desc": "操作成功"
}

# 取消失败
{
    "code": 10000, 
    "data": [
        {
            "code": 12201, 
            "data": "6819506476072247296", 
            "desc": "委托策略不存在"
        }
    ], 
    "desc": "操作成功"
}
```

###响应参数说明 data数组元素：

| 参数名      | 必选 | 类型   | 说明                 |
| :---------- | :--- | :----- | :------------------- |
| orderAlgoId | 是   | String | 取消失败的委托策略id |



### 5.13 委托策略查询

- URL: /Server/api/v2/trade/getOrderAlgos

    - 接口类型: Http

    - 请求类型: GET

    - 请求参数:

- 请求参数说明 body：

| 参数名    | 必选 | 类型    | 说明                                                         |
| :-------- | :--- | :------ | :----------------------------------------------------------- |
| symbol    | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
| side      | 否   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| orderType | 是   | Integer | `1`：计划委托<br/>`2`：止盈止损                              |
| bizType   | 否   | Integer | 针对止盈止损<br/>`1`:止盈<br/>`2`:止损                       |
| status    | 否   | Integer | **针对计划委托**<br/>`1`:等待委托<br/>`2`:已取消<br/>`3`:挂单中<br/>`4`:委托失败<br/>`5`已完成<br/>`6`:部分成交<br/>`7`:订单已取消<br/>`8`失败<br/>**针对止盈止损**<br/>`1`:未触发<br/>`2`:已取消<br/>`3`:挂单中<br/>`4`:触发失败<br/>`5`已完成<br/>`6`:部分成交<br/>`7`:订单已取消<br/>`8`失败 |
| startTime | 否   | Long    | 开始时间                                                     |
| endTime   | 否   | Long    | 结束时间                                                     |
| pageNum   | 是   | Integer | 页码，从1开始                                                |
| pageSize  | 是   | Integer | 分页大小，默认10                                             |

- 响应结果:

```
  {
      "code": 10000, 
      "data": {
          "list": [
              {
                  "algoPrice": "2050", 
                  "amount": "0.5", 
                  "bizType": 1, 
                  "canCancel": true, 
                  "createTime": "1625898596847", 
                  "id": "6819512988349964288", 
                  "leverage": 20, 
                  "marketId": "101", 
                  "modifyTime": "1625898596847", 
                  "orderType": 1, 
                  "priceType": 1, 
                  "side": 1, 
                  "sourceType": 4, 
                  "status": 1, 
                  "triggerPrice": "2100", 
                  "triggerTime": "0", 
                  "userId": "6755742981778581504"
              }, 
              ...
          ], 
          "pageNum": 1, 
          "pageSize": 10
      }, 
      "desc": "操作成功"
  }
```



- 响应参数说明 data

| 参数名 | 必选 | 类型                                     | 说明     |
| :----- | :--- | :--------------------------------------- | :------- |
| data   | 是   | Page{pageNum, pageSize, list<OrderAlgo>} | 委托策略 |

- 委托策略

| 参数名       | 必选 | 类型    | 说明                                                         |
| :----------- | :--- | :------ | :----------------------------------------------------------- |
| id           | 是   | Long    | 订单id                                                       |
| marketId     | 是   | Long    | 市场id                                                       |
| triggerPrice | 是   | Decimal | 触发价格                                                     |
| algoPrice    | 是   | Decimal | 委托价格                                                     |
| amount       | 是   | Decimal | 委托数量                                                     |
| side         | 是   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| orderType    | 是   | Integer | `1`：计划委托<br/>`2`：止盈止损                              |
| priceType    | 是   | Integer | `1`:标记价格<br/>`2`:最新价格                                |
| algoPrice    | 是   | Decimal | 委托价格，填写值0\<X\<=1000000                               |
| bizType      | 是   | Integer | `1`:止盈<br/>`2`:止损                                        |
| leverage     | 是   | Integer | 杠杠倍数                                                     |
| sourceType   | 是   | Integer | 来源：<br/>1:WEB<br/>2:Android<br/>3:iOS<br/>4:Rest API<br/>5:WebSocket API<br/>6:System<br/>7:Plan Entrust(计划委托)<br/>8:Take Profit(止盈)<br/>9:Stop Loss(止损) |
| canCancel    | 是   | Boolean | 能否取消                                                     |
| triggerTime  | 否   | Long    | 触发时间，时间戳                                             |
| tradedAmount | 否   | Decimal | 已成交数量                                                   |
| errorCode    | 否   | Integer | 错误代码                                                     |
| errorDesc    | 否   | String  | 错误代码描述                                                 |
| createTime   | 是   | Long    | 创建时间，时间戳                                             |
| status       | 是   | Integer | **针对计划委托**<br/>`1`:等待委托<br/>`2`:已取消<br/>`3`:挂单中<br/>`4`:委托失败<br/>`5`已完成<br/>`6`:部分成交<br/>`7`:订单已取消<br/>`8`失败<br/>**针对止盈止损**<br/>`1`:未触发<br/>`2`:已取消<br/>`3`:挂单中<br/>`4`:触发失败<br/>`5`已完成<br/>`6`:部分成交<br/>`7`:订单已取消<br/>`8`失败 |



### 5.14 修改下单止盈止损参数

- URL: /Server/api/v2/trade/updateOrderAlgo

- 接口类型: Http

- 请求类型: POST

- 请求参数:

  | 参数名     | 必选 | 类型   | 说明                                                         |
      | :--------- | :--- | :----- | :----------------------------------------------------------- |
  | symbol     | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
  | orderId    | 是   | Long   | 订单号                                                       |
  | orderAlgos | 是   | List   | 止盈止损参数，如："orderAlgos":[{"bizType":1,"priceType":1,"triggerPrice":"70000"},{"bizType":2,"priceType":1,"triggerPrice":"40000"}] |

- 止盈止损参数说明

  | 参数名       | 必选 | 类型    | 说明                               |
      | :----------- | :--- | :------ | :--------------------------------- |
  | bizType      | 是   | Integer | 类型，1：止盈，2：止损             |
  | priceType    | 是   | Integer | 价格类型，1：标记价格，2：最新价格 |
  | triggerPrice | 是   | Decimal | 触发价格                           |

- 响应结果:

  ```
  {
      "code": 10000, 
      "data": {
          "action": 1, 
          "amount": "0.01", 
          "availableAmount": "0.01", 
          "availableValue": "450", 
          "avgPrice": "0", 
          "canCancel": true, 
          "cancelStatus": 20, 
          "createTime": "1638776887733", 
          "entrustType": 1, 
          "id": "6873528455326081024", 
          "leverage": 20, 
          "margin": "22.5", 
          "marketId": "100", 
          "modifyTime": "1638776887748", 
          "orderAlgos": [
              {
                  "bizType": 1, 
                  "createTime": "1638779420239", 
                  "id": "6873539077426126853", 
                  "priceType": 1, 
                  "priority": 0, 
                  "status": 0, 
                  "triggerPrice": "55200"
              }, 
              {
                  "bizType": 2, 
                  "createTime": "1638779420239", 
                  "id": "6873539077426126858", 
                  "priceType": 1, 
                  "priority": 0, 
                  "status": 0, 
                  "triggerPrice": "42200"
              }
          ], 
          "price": "45000", 
          "priority": 0, 
          "showStatus": 1, 
          "side": 1, 
          "sourceType": 4, 
          "status": 12, 
          "tradeAmount": "0", 
          "tradeValue": "0", 
          "type": 1, 
          "userId": "6838762652169152512", 
          "value": "450"
      }, 
      "desc": "操作成功"
  }
  ```

响应参数说明 data，参考 ``查询当前全部挂单``



## 6. 交易活动

跟交易活动相关的接口请在header中添加如下参数

```
subAccount: {periodId: 期id(activityPeriodId)}
例如：subAccount: "{\"periodId\": 1}"
```



### 6.1  购买入场券/返场

- /Server/api/v2/activity/buyTicket

- 接口类型: Http

- 请求类型: POST

- 请求参数:

  | 参数名 | 必选 | 类型    | 说明                                         |
      | :----- | :--- | :------ | :------------------------------------------- |
  | activityPeriodId | 是   | Integer  | | 参与的期 id

- 响应结果:

  ```json
  {
      "code": 10000,
      "desc": "success"
  }
  ```





## 7. 公共行情：Http

USDT合约地址：https://fapi.zb.com
QC合约地址：https://fapi.zb.com/qc

### 7.1 交易对
- URL: /Server/api/v2/config/marketList
- 接口类型: Http
- 请求类型: GET
- 请求参数:

  | 名称         | 类型     | 是否必须 | 描述      |
      | :---------- | :----- | :--- | :------ |
  | futuresAccountType | Integer | 否    | 合约类型，1:USDT合约（默认） |

- 响应结果:

```
  {
    "code": 1,
    "desc": "success",
    "data": [{
        "id": 100,
        "marketName": "BTC_USDT",
        "symbol": null,
        "marketType": 0,
        "buyerCurrencyId": 1041,
        "buyerCurrencyName": "USDT",
        "sellerCurrencyId": 1051,
        "sellerCurrencyName": "BTC",
        "marginCurrencyId": null,
        "marginCurrencyName": null,
        "amountDecimal": 8,
        "priceDecimal": 8,
        "minAmount": 0.01,
        "maxAmount": null,
        "minTradeMoney": null,
        "maxTradeMoney": null,
        "minFundingRate": null,
        "maxFundingRate": null,
        "maxLeverage": null,
        "riskWarnRatio": null,
        "defaultFeeRate": null,
        "contractType": null,
        "status": 1,
        "enableTime": 1481515932000,
        "lastTradePrice": 0,
        "defaultLeverage": 20,
        "defaultMarginMode": 1,
        "defaultPositionsMode": 2,
          "markPriceLimitRate": "0.1",
          "marketPriceLimitRate": "0.1"
      },
      ...
     ]
  }
```

| 名称         | 类型     | 示例 | 描述      |
  | :---------- | :----- | :--- | :------ |
| id | Long |     | 市场ID |
| marketName | String |     | 市场名称 |
| symbol | String |     | 唯一标识 |
| buyerCurrencyId | Long |     | 买方币种ID |
| buyerCurrencyName | String |     | 买方币种名称 |
| sellerCurrencyId | Long |     | 卖方币种ID |
| sellerCurrencyName | String |     | 卖方币种名称 |
| marginCurrencyId | Long |     | 保证金币种ID |
| marginCurrencyName | String |     | 保证金币种 |
| amountDecimal | Integer |     | 数量精度 |
| priceDecimal | Integer |     | 价格精度 |
| feeDecimal | Integer |     | 手续费精度 |
| marginDecimal | Integer |     | 保证金精度 |
| minAmount | BigDecimal |     | 最小委托量 |
| maxAmount | BigDecimal |     | 最大委托量 |
| minTradeMoney | BigDecimal |     | 最小交易额 |
| maxTradeMoney | BigDecimal |     | 最大交易额 |
| minFundingRate | BigDecimal |     | 最小资金费率 |
| maxFundingRate | BigDecimal |     | 最大资金费率 |
| maxLeverage | Integer |     | 最大杠杆倍数 |
| riskWarnRatio | BigDecimal |     | 风险提醒比例 |
| defaultFeeRate | BigDecimal |     | 默认费率 |
| contractType | Integer |     | 合约类型，1:usdt合约（默认） 2 qc合约 |
| duration | Integer |     | 合约时长，<br/>1:永续合约（默认），<br/>2:交割合约-当周，<br/>3:交割合约-次周，<br/>4:交割合约-当季，<br/>5:交割合约-次季 |
| status | Integer |     | 状态: 1:运行, 0:停止（默认） |
| createTime | Long |     | 创建时间 |
| enableTime | Long |     | 开盘时间 |
| defaultLeverage | Integer |     | 默认杠杆倍数 |
| defaultMarginMode | Integer |     | 默认保证金模式，<br/>1:逐仓（默认），<br/>2:全仓 |
| defaultPositionsMode | Integer |     | 默认仓位模式，<br/>1:单向持仓，<br/>2:双向持仓（默认） |
| markPriceLimitRate | BigDecimal | 0.1 | 下单标记价格限价幅度，0.1则表示10% |
| marketPriceLimitRate | BigDecimal | 0.1 | 下单市场价格限价幅度，0.1则表示10% |



### 7.2 全量深度

- URL: /api/public/v1/depth

- 接口类型: Http

- 请求类型: GET

- 说明：获取全量深度数据

- 请求参数:

  | 名称   | 类型    | 是否必须 | 描述                 |
      | :----- | :------ | :------- | :------------------- |
  | symbol | String  | 是       | 交易对，如：BTC_USDT |
  | size   | Integer | 否       | 条数                 |
  | scale  | Integer | 否       | 精度                 |

  size最大值为200，默认值为5

- 响应结果:

```
  {
      "code": 10000,
      "desc": "操作成功",
      "data":{
        "asks":[					 //卖盘
          [
            16146.91,				//价格
            0.029267				//数量
          ],
          [
            16146.93,
            0.129334
          ]
        ],
        "bids":[							//买盘
          [
            16131.41,
            8.866436
          ],
          [
            16131.36,
            8.85
          ]
        ],
        "time":  1630657743231  //当前服务器时间
      }
  }
```

### 7.3  k 线

- URL: /api/public/v1/kline
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型    | 是否必须 | 描述                      |
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | 是       | 交易对，如：BTC_USDT      |
| period | String  | 是       | 不种时间的kline。如1M，5M |
| size   | Integer | 否       |                           |

period可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D。M代表分钟，H代表小时，D代表天。

size最大值为1440，默认值为1

- 响应结果:

```
  {
      "code": 10000,
      "desc": "操作成功",
      "data": [
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1160.79137966,	//量
        1605265200	//时间
        ],
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1160.79137966,	//量
        1605266100	//时间
        ]
    ]
  } 
```

### 

### 7.4 成交

- URL: /api/public/v1/trade

- 接口类型: Http

- 请求类型: GET

- 请求参数:

  | 名称   | 类型    | 是否必须 | 描述                 |
      | :----- | :------ | :------- | :------------------- |
  | symbol | String  | 是       | 交易对，如：BTC_USDT |
  | size   | Integer | 否       | 条数                 |

  size最大值为100，默认值为50

- 响应结果:

```
  {
      "code": 10000,
      "desc": "操作成功",
      "data": [
          [
              16131.3,		//价格
              0.03749,		//数量
              -1,					//卖
              1605266072	//时间
          ],
          [
              16130.01,		//价格
              0.2,				//数量
              1,					//买
              1605266073	//时间
          ]      
      ]
  }
```

### 7.5 Ticker

- URL: /api/public/v1/ticker

- 接口类型: Http

- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |

- 响应结果:

  ```json
  {
      "code": 10000,
      "desc": "操作成功",
      "data": {
        "BTC_USDT":[
          16100.9,		//开盘价格
          16133.2,		//最高价
          16100.1,		//最低价
          16132.3,		//最新成交价
          1000,		    //成交量(最近的24小时)
          0.19502,		//24H涨跌幅
          1605266072,	//时间
          104190.4595	//以rmb为单位的最新成交价格
        ],
        "BCH_USDT":[
          16100.9,		//开盘价格
          16133.2,		//最高价
          16100.1,		//最低价
          16132.3,		//最新成交价
          1000,		    //成交量(最近的24小时)
          0.19502,		//24H涨跌幅
          1605266072,	//时间
          104190.4595	//以rmb为单位的最新成交价格
        ]
    }
  }
  ```

### 7.6  最新标记价格

- URL: /api/public/v1/markPrice
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |

- 响应结果:

  ```json
  {
      "code":10000,
      "desc":"操作成功",
      "data":{
          "EOS_USDT":"10.71673333",
          "BCH_USDT":"1253.45415974",
          "ETH_USDT":"3926.06",
          "BTC_USDT":"48962.19",
          "LTC_USDT":"316.383"
      }
  }
  ```

### 7.7  最新指数价格

- URL: /api/public/v1/indexPrice
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |

- 响应结果:

  ```json
  {
      "code":10000,
      "desc":"操作成功",
      "data":{
          "EOS_USDT":"10.71673333",
          "BCH_USDT":"1253.45415974",
          "ETH_USDT":"3926.06",
          "BTC_USDT":"48962.19",
          "LTC_USDT":"316.383"
      }
  }
  ```

### 7.8  标记价格k 线

- URL: /api/public/v1/markKline
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型    | 是否必须 | 描述                      |
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | 是       | 交易对，如：BTC_USDT      |
| period | String  | 是       | 不种时间的kline。如1M，5M |
| size   | Integer | 否       |                           |

period可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D。M代表分钟，H代表小时，D代表天。

size最大值为1440，默认值为1

- 响应结果:

  ```json
  {
      "code": 10000,
      "desc": "操作成功",
      "data": [
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605265200	//时间
        ],
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605266100	//时间
        ]
    ]
  } 
  ```

###  7.9  指数价格k 线

- URL: /api/public/v1/indexKline
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型    | 是否必须 | 描述                      |
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | 是       | 交易对，如：BTC_USDT      |
| period | String  | 是       | 不种时间的kline。如1M，5M |
| size   | Integer | 否       |                           |

period可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D。M代表分钟，H代表小时，D代表天。

size最大值为1440，默认值为1

- 响应结果:

  ```json
  {
      "code": 10000,
      "desc": "操作成功",
      "data": [
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605265200	//时间
        ],
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605266100	//时间
        ]
    ]
  } 
  ```



### 7.10 资金费率和下次结算时间

- URL: /api/public/v1/fundingRate
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 是       | 交易对，如：BTC_USDT |

- 响应结果:

  ```json
  {
      "code":10000,
      "desc":"操作成功",
      "data":{
          "fundingRate":-0.297589,	//资金费率
          "nextCalculateTime":"2021-01-15 00:00:00"	//下次结算时间
      }
  }
  ```



### 7.11 最新标记价格和资金费率

- URL: /Server/api/v2/premiumIndex
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |

- 响应结果:

  ```json
  {
      "code":10000,
      "data":[
          {
              "symbol":"BTC_USDT",
              "markPrice":"53821.58",
              "indexPrice":"53829.75",
              "lastFundingRate":"0"
          },
          {
              "symbol":"ETH_USDT",
              "markPrice":"2415.66",
              "indexPrice":"2415.63",
              "lastFundingRate":"0.00049"
          },
          {
              "symbol":"LTC_USDT",
              "markPrice":"260.096",
              "indexPrice":"260.143",
              "lastFundingRate":"0"
          },
          {
              "symbol":"EOS_USDT",
              "markPrice":"6.34083333",
              "indexPrice":"6.3416",
              "lastFundingRate":"0"
          },
          {
              "symbol":"BCH_USDT",
              "markPrice":"908.63975288",
              "indexPrice":"908.87333333",
              "lastFundingRate":"-0.0005"
          }
      ],
      "desc":"操作成功"
  }
  ```



### 7.12 查询资金费率历史

- URL: /Server/api/v2/fundingRate
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |
| startTime | Long | 否       | 起始时间 |
| endTime | Long | 否       | 结束时间,默认当前时间 |
| limit | String | 否       | 从endTime倒推算起的数据条数，默认值:100 最大值:1000 |

- 响应结果:

  ```json
  {
      "code":10000,
      "data":[
          {
              "symbol":"ETH_USDT",
              "fundingRate":"0.000485",
              "fundingTime":"1616680800000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.000049",
              "fundingTime":"1616677200000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.000175",
              "fundingTime":"1616673600000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.002657",
              "fundingTime":"1616670000000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.001207",
              "fundingTime":"1616666400000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.000896",
              "fundingTime":"1616662800000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"0.000344",
              "fundingTime":"1616659200000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"0.000042",
              "fundingTime":"1616655600000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.000018",
              "fundingTime":"1616652000000"
          },
          {
              "symbol":"ETH_USDT",
              "fundingRate":"-0.000144",
              "fundingTime":"1616648400000"
          }
      ],
      "desc":"操作成功"
  }
  ```



### 7.13 查询市场强平订单

- URL: /Server/api/v2/allForceOrders
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 否       | 交易对，如：BTC_USDT |
| startTime | Long | 否       | 起始时间 |
| endTime | Long | 否       | 结束时间,默认当前时间 |
| limit | String | 否       | 从endTime倒推算起的数据条数，默认值:100 最大值:1000 |

- 响应结果:

  ```json
  {
      "code":10000,
      "data":[
          {
              "symbol":"ETH_USDT",
              "price":"1151.16",
              "amount":"156.566",
              "tradeAmount":"156.566",
              "tradeAvgPrice":"1134.59",
              "side":"平空",
              "status":"已完成",
              "time":"1611304581850"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1237.2",
              "amount":"60.028",
              "tradeAmount":"0",
              "tradeAvgPrice":"0",
              "side":"平空",
              "status":"完全取消",
              "time":"1611373325930"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1237.2",
              "amount":"60.028",
              "tradeAmount":"0",
              "tradeAvgPrice":"0",
              "side":"平空",
              "status":"完全取消",
              "time":"1611373326366"
          },
          {
              "symbol":"ETH_USDT",
              "price":"711.38",
              "amount":"59.377",
              "tradeAvgPrice":"0",
              "side":"平多",
              "status":"未知状态",
              "time":"1611650013343"
          },
          {
              "symbol":"ETH_USDT",
              "price":"893.01",
              "amount":"20.142",
              "tradeAvgPrice":"0",
              "side":"平多",
              "status":"未知状态",
              "time":"1611650013384"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1151.54",
              "amount":"151.518",
              "tradeAvgPrice":"0",
              "side":"平多",
              "status":"未知状态",
              "time":"1611650013394"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1302.98",
              "amount":"11.767",
              "tradeAmount":"11.767",
              "tradeAvgPrice":"1302.98",
              "side":"平空",
              "status":"已完成",
              "time":"1611813611693"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1302.98",
              "amount":"11.767",
              "tradeAmount":"0",
              "tradeAvgPrice":"0",
              "side":"平空",
              "status":"已完成",
              "time":"1611828091110"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1339.44",
              "amount":"59.384",
              "tradeAmount":"53.245",
              "tradeAvgPrice":"1312.16",
              "side":"平空",
              "status":"完全取消",
              "time":"1611842353847"
          },
          {
              "symbol":"ETH_USDT",
              "price":"1339.44",
              "amount":"6.156",
              "tradeAmount":"0",
              "tradeAvgPrice":"0",
              "side":"平空",
              "status":"完全取消",
              "time":"1611842356831"
          }
      ],
      "desc":"操作成功"
  }
  ```



### 7.14 大户账户数多空比

- URL: /Server/api/v2/data/topLongShortAccountRatio
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 是       | 交易对，如：BTC_USDT |
| period | String | 是       | 周期，如："5m","15m","30m","1h","2h","4h","6h","12h","1d" |
| startTime | Long | 否       | 起始时间 |
| endTime | Long | 否       | 结束时间,默认当前时间 |
| limit | String | 否       | 从endTime倒推算起的数据条数，默认值:30 最大值:500 |

- 响应结果:

  ```json
  {
      "code":10000,
      "data":[
          {
              "symbol":"ETH_USDT",
              "timestamp":"1619068500000",
              "longAccount":"5",
              "shortAccount":"6",
              "longShortRatio":"0.83"
          },
          {
              "symbol":"ETH_USDT",
              "timestamp":"1619068800000",
              "longAccount":"5",
              "shortAccount":"6",
              "longShortRatio":"0.83"
          }
      ],
      "desc":"操作成功"
  }
  ```



### 7.15 大户持仓量多空比

- URL: /Server/api/v2/data/topLongShortPositionRatio
- 接口类型: Http
- 请求类型: GET

- 请求参数:

| 名称   | 类型   | 是否必须 | 描述                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | 是       | 交易对，如：BTC_USDT |
| period | String | 是       | 周期，如："5m","15m","30m","1h","2h","4h","6h","12h","1d" |
| startTime | Long | 否       | 起始时间 |
| endTime | Long | 否       | 结束时间,默认当前时间 |
| limit | String | 否       | 从endTime倒推算起的数据条数，默认值:30 最大值:500 |

- 响应结果:

  ```json
  {
      "code":10000,
      "data":[
          {
              "symbol":"ETH_USDT",
              "timestamp":"1619068800000",
              "longPosition":"5570.414",
              "shortPosition":"5533.141",
              "longShortRatio":"1.01"
          },
          {
              "symbol":"ETH_USDT",
              "timestamp":"1619069100000",
              "longPosition":"5572.847",
              "shortPosition":"5535.575",
              "longShortRatio":"1.01"
          }
      ],
      "desc":"操作成功"
  }
  ```



## 8. 公共行情：ws

- 接口类型: WebSocket

- USDT合约URL: wss://fapi.zb.com/ws/public/v1
- QC合约URL: wss://fapi.zb.com/qc/ws/public/v1
- 请求参数使用json编码

### 8.1 订阅

- 请求参数

| 名称    | 类型     | 是否必须 | 描述                                                         |
| :------ | :------- | :------- | ------------------------------------------------------------ |
| action  | String   | 是       | subscribe                                                    |
| channel | String   | 是       | 频道<br />格式: 市场名称.数据类型<br />盘口:  BTC_USDT.Depth<br />成交:  BTC_USDT.Trade<br />k线： BTC_USDT.KLine_15M, 可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D |
| size    | Interger | 否       | 记录条数。<br />kline：最大值1440，默认值1<br />全量深度: 最大值10，默认值5<br />成交：最大值100，默认值为50<br /> |

- 请求示例

  ```json
  {
    "action": "subscribe",
    "channel":"BTC_USDT.KLine_15M",
    "size":100					//不同的channel，data会不一样
  }
  
  ```

- 失败格式

  ```json
  {
   	"channel":"BTC_USDT.KLine_15M",
    "errorCode": ,
    "errorMsg":
  }
  ```



### 8.2 取消订阅

- 请求参数

| 名称    | 类型   | 是否必须 | 描述                                                         |
| :------ | :----- | :------- | :----------------------------------------------------------- |
| action  | String | 是       | unsubscribe                                                  |
| channel | String | 是       | 频道<br />格式: 市场名称.数据类型<br />盘口:  BTC_USDT.Depth<br />成交:  BTC_USDT.Trade<br />k线： BTC_USDT.1M, 可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D |

- 请求示例

  ```json
  {
    "action": "unsubscribe",
    "channel":"BTC_USDT.KLine_15M"
  }
  
  ```

### 8.3 全量深度

- 更新频率：200ms一次
- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.DepthWhole@0.01",	//全量5档深度，@后面是指盘口精度。如果没有@精度，则当作默认精度(精度列表的第一个)
	"size": 5
}
```

size最大值为10，默认值为5

- 响应格式

  买盘是以价格降序排序，卖盘是以价格升序排列

```json
{
  "channel": "BTC_USDT.DepthWhole@0.01",
	"data": {
    "asks":[					 //卖盘
      [
        16146.91,				//价格
        0.029267				//数量
      ],
      [
        16146.93,
        0.129334
      ]
    ],
    "bids":[							//买盘
      [
        16131.41
        8.866436
      ],
      [
        16131.36,
        2
      ]
    ],
    "time":  1630657743231  //当前服务器时间
	}
}
```

### 8.4 增量深度

- 每隔5分钟更新一次全量深度。客户端收到全量时，直接替换本地的深度表
- 更新频率：实时。客户端收到增量时，需用增量数据来更新本地的深度表
- size为空时，默认为50。最大为1000。

```json
{ 
     "action": "subscribe",
     "channel": "BTC_USDT.Depth@0.01",   //@后面是指盘口精度。如果没有@精度，则当作默认精度(精度列表的第一个)
     "size": 50
}
```

- 增量响应格式

```json
{
  "channel": "BTC_USDT.Depth@0.01",
	"data":{
    "asks":[					//卖盘
		[
			16146.91,				//价格
			0.029267				//数量
		],
		[
			16146.93,
			0.129334
		]
	],
	"bids":[							//买盘
		[
			16131.41,
			8.866436
		],
		[
			16131.36,
			8.85
		]
	],
  "time":  1630657743231  //当前服务器时间
  }
}
```

- 全量响应格式

  买盘是以价格降序排序，卖盘是以价格升序排列

```json
{
  "channel": "BTC_USDT.Depth@0.01",	//@后面是指盘口精度。如果没有@精度，则当作默认精度(精度列表的第一个)
  "type": "Whole",									//Whole:全量 Update:增量 默认值为Update
  "data":{
    "asks":[					//卖盘
		[
			16146.91,				//价格
			0.029267				//数量
		],
		[
			16146.93,
			0.129334
		]
	],
	"bids":[							//买盘
		[
			16131.41,
			8.866436
		],
		[
			16131.36,
			2
		]
	],
  "time":  1630657743231  //当前服务器时间
  }
}
```

### 8.5 k线

- 更新频率：100ms
- 请求参数

```json
{ 
     "action": "subscribe",
     "channel": "BTC_USDT.KLine_15M",
  	 "size": 1440
}
```

size最大值为1440，默认值为1

KLine可选范围:1M,5M,15M, 30M, 1H, 6H, 1D, 5D

增量k线只有1条和2条二种情况。处于k线周期时间点时，就有2条，别的时候是1条。

全量时就可能会超过2条。

- 响应格式

```json
{
  "channel":"BTC_USDT.KLine_15M",
  "type":"Whole",	//Whole:全量 Update:增量 默认值为Update
  "data":[
    [
      16199,			//开
      16212.3,		//高
      16087.42,		//低
      16131.4,		//收
      1160.79137966,	//量
      1605265200	//时间
  	],
    [
      16199,			//开
      16212.3,		//高
      16087.42,		//低
      16131.4,		//收
      1160.79137966,	//量
      1605266100	//时间
  	]
  ]
}
//kline的时间由小到大排列
```


### 8.6 成交

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.Trade",
  "size": 50,	//s 
}
```

size最大值为100，默认值为50



- 响应格式

```json
{
  "channel": "BTC_USDT.Trade",
  "data":[
		[
			16131.3,		//价格
			0.03749,		//数量
			-1,					//卖
			1605266072	//时间
		],
		......
		[
			16130.01,		//价格
			0.2,				//数量
			1,					//买
			1605266073	//时间
		]      
	]
}
```

### 8.7 Ticker

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.Ticker"
}
```

- 响应格式

```json
{
  "channel": "BTC_USDT.Ticker",
  "data":[
		16100.9,		//开盘价格
  	16133.2,		//最高价
  	16100.1,		//最低价
  	16132.3,		//最新成交价
    1000,		    //成交量(最近的24小时)
		0.19502,		//24H涨跌幅
		1605266072	//时间
	]
}
```

### 8.8 全部Ticker

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "All.Ticker"
}
```

- 第一次会把全部交易对的ticker全部下发。然后只会下发新ticker数据。
- 响应格式

```json
{
  "channel": "All.Ticker",
  "data":{
    "BTC_USDT":[
      16100.9,		//开盘价格
      16133.2,		//最高价
      16100.1,		//最低价
      16132.3,		//最新成交价
      1000,		    //成交量(最近的24小时)
      0.19502,		//24H涨跌幅
      1605266072	//时间
		],
    "BCH_USDT":[
      16100.9,		//开盘价格
      16133.2,		//最高价
      16100.1,		//最低价
      16132.3,		//最新成交价
      1000,		    //成交量(最近的24小时)
      0.19502,		//24H涨跌幅
      1605266072	//时间
		]
    ......
  }
}
```

### 8.9 指数价格和标记价格

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.mark"	//BTC_USDT.index. mark表示标记价格，index表示指数价格
}
```

- 响应格式

```json
{
  "channel":"BTC_USDT.index",
  "data":"38550.57"
}
```



### 8.10 指数价格K线和标记价格K线

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.mark_15M",	//BTC_USDT.index_15M. mark表示标记价格，index表示指数价格
  "size": 50,	//s 
}
```

size最大值为100，默认值为1



- 响应格式

```json
{
  "channel": "BTC_USDT.mark",	//BTC_USDT.index_15M
  "data":[
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605265200	//时间
      ],
      [
        16199,			//开
        16212.3,		//高
        16087.42,		//低
        16131.4,		//收
        1605266100	//时间
      ]
    ]
}
```



### 8.11 资金费率和下次结算时间

- 请求参数

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.FundingRate"
}
```

- 响应格式

```json
{
    "channel":"BTC_USDT.FundingRate",
    "data":{
        "fundingRate":-0.297589,	//资金费率
        "nextCalculateTime":"2021-01-15 00:00:00"	//下次资金费用结算时间
    }
}
```

### 8.12 ping

建议用户进行以下操作:

1，每次接收到消息后，用户设置一个定时器 ，定时N秒。

2，如果定时器被触发（N 秒内没有收到新消息），发送字符串 'ping'。

3，期待一个文字字符串'pong'作为回应。如果在 N秒内未收到，请发出错误或重新连接。

出现网络问题会自动断开连接

- **请求参数：**

  | 参数名 | 必选 | 类型   | 说明 |
      | :----- | :--- | :----- | :--- |
  | action | 是   | String | ping |


- 请求示例

```json
{
  "action": "ping"
}
```

- 成功响应格式

```json
{
	"action":"pong"
}
```



## 9. 用户数据：ws

### 9.1概述

- 接口类型: WebSocket

- USDT合约URL: wss://fapi.zb.com/ws/private/api/v2
- QC合约URL: wss://fapi.zb.com/qc/ws/private/api/v2

- **每个请求都必须有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                             |
      | :------ | :--- | :----- | :----------------------------------------------- |
  | action  | 是   | String | subscribe:订阅  unSubscribe:取消订阅  login:登录 |
  | channel | 是   | String | 频道，代表不同的订阅内容                         |


- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.change",
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- 成功响应格式

```json
{
	"channel":"Fund.change",
	"data":	//不同频道，返回的内容不同，具体查看各频道说明
}
```

- 失败响应格式

```json
{
	"channel":"Fund.change",
	"errorCode":,
  "errorMsg":
}
```

#### 9.1.1 ping

建议用户进行以下操作:

1，每次接收到消息后，用户设置一个定时器 ，定时N秒。

2，如果定时器被触发（N 秒内没有收到新消息），发送字符串 'ping'。

3，期待一个文字字符串'pong'作为回应。如果在 N秒内未收到，请发出错误或重新连接。

出现网络问题会自动断开连接

- **请求参数：**

  | 参数名 | 必选 | 类型   | 说明 |
      | :----- | :--- | :----- | :--- |
  | action | 是   | String | ping |


- 请求示例

```json
{
  "action": "ping"
}
```

- 成功响应格式

```json
{
	"action":"pong"
}
```


### 9.2 登录

建立连接后，需要先登录，才能进行频道订阅。以后的频道订阅时，就不需要带上ZB-APIKEY，ZB-TIMESTAMP和ZB-SIGN。

- **请求参数：**

  | 参数名       | 必选 | 类型   | 说明                                             |
      | :----------- | :--- | :----- | :----------------------------------------------- |
  | action       | 是   | String | login:登录                                       |
  | ZB-APIKEY    | 是   | String | 由zb平台生成用户的api key                        |
  | ZB-TIMESTAMP | 是   | String | 请求时间，为ISO格式，如`2021-01-05T14:05:28.616Z |
  | ZB-SIGN      | 是   | String | 签名                                             |


- 请求示例

```json
{
  "action": "login",
  "ZB-APIKEY":"a55caded-eef9-426b-af7c-faf53c78e2ae",
  "ZB-TIMESTAMP":"2021-01-22T02:08:54.312Z",
  "ZB-SIGN":"flsToYwO39sGJ8Pp6gAfIOsUBLLRa3F3daDcYqddGKc="
}
```

- 成功响应格式

```json
{
	"action":"login",
	"data":	"success"
}
```

#### 9.2.1签名规则

- 服务器对发起的请求进行签名检验，确认请求来源；

- 请勿将secretKey在请求或响应中传输；

- ZB-SIGN字段是对``timestamp`` + ``"GET"``  + ``login``(+表示字符串连接)，以及SecretKey，使用HMAC SHA256方法加密，通过Base64编码输出而得到的；

  如：`sign=CryptoJS.enc.Base64.Stringify(CryptoJS.HmacSHA256(timestamp + 'GET' + 'login', SecretKey))`

  其中，`timestamp`的值与`ZB-TIMESTAMP`请求头相同，为ISO格式，如`2021-01-05T14:05:28.616Z`。

  SecretKey为用户申请APIKey时所生成，需用sha1加密。如：`ceb892e0-0367-4cc1-88d1-ef9289feb053`，加密SecretKey得到：c9a206b430d6c6a43322a05806acb5f9514ac488

  在线加密工具: http://tool.oschina.net/encrypt?type=2

### 9.3资金

- **资金请求都必须有的参数：**

| 参数名             | 必选 | 类型    | 说明           |
| :----------------- | :--- | :------ | :------------- |
| futuresAccountType | 是   | Integer | 1:USDT永续合约 |

#### 9.3.1、资金变动

- 用户资金有变动就会推送给客户，持续推送

- **特有的参数：**

  | 参数名   | 必选 | 类型   | 说明        |
      | :------- | :--- | :----- | :---------- |
  | channel  | 是   | String | Fund.change |
  | currency | 是   | String | 币种，如BTC |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.change",	//资金变动
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- 响应格式

```json
{
  "channel":"Fund.change",
  "data":{
    "amount":"6.2026735",
    "createTime":"1610972128891",
    "currencyId":"6",
    "freezeAmount":"31604.57491827923445",
    "id":"6756906844096047104",
    "modifyTime":"1611198648373",
    "userId":"6756829323044333568"
  }
}
```

- 响应参数说明

| 参数名           | 类型       | 说明           |
| :--------------- | :--------- | :------------- |
| userId           | Long       | 用户id         |
| currencyId       | Long       | 币种id         |
| currencyName     | String     | 币种名字       |
| amount           | BigDecimal | 可用资产量     |
| freezeAmount     | BigDecimal | 冻结量         |
| id               | Long       | 资金id         |
| createTime       | Long       | 创建时间       |


#### 9.3.2、资金查询

- 只会推送一次当前用户的资金

- **特有的参数：**

  | 参数名   | 必选 | 类型   | 说明         |
      | :------- | :--- | :----- | :----------- |
  | channel  | 是   | String | Fund.balance |
  | currency | 否   | String | 币种，如BTC  |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.balance",
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- 响应格式

```json
{
    "channel":"Fund.balance",
    "data":[{
				"amount":"1001000201.96515424",
				"freezeAmount":"1.9441555",
				"currencyName":"usdt",
				"createTime":"1614841089612",
 				"id":"6773134441524176896",
				"currencyId":"6",
				"userId":"6755772669834045440"
     }]
}
```

- 响应参数说明

| 参数名           | 类型       | 说明           |
| :--------------- | :--------- | :------------- |
| userId           | Long       | 用户id         |
| currencyId       | Long       | 币种id         |
| currencyName     | String     | 币种名字       |
| amount           | BigDecimal | 可用资产量     |
| freezeAmount     | BigDecimal | 冻结量         |
| id               | Long       | 资金id         |
| createTime       | Long       | 创建时间       |



#### 9.3.3、查询用户bill账单

- 只会推送一次当前用户的资金

- **特有的参数：**

  | 参数名    | 必选 | 类型    | 说明             |
      | :-------- | :--- | :------ | ---------------- |
  | channel   | 是   | String  | Fund.getBill     |
  | currency  | 否   | String  | 币种，如BTC      |
  | type      | 否   | Integer | 账单类型         |
  | startTime | 否   | Long    | 开始时间戳       |
  | endTime   | 否   | Long    | 结束时间戳       |
  | pageNum   | 否   | Integer | 页码             |
  | pageSize  | 否   | Integer | 每页行数，默认10 |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.getBill",
  "futuresAccountType":1,

  "currency": "USDT"
}
```

- 响应格式

```json
{
  "channel":"Fund.getBill",
  "data":{
    "pageSize":100,
    "list":[
      {
        "symbol":"ETH_USDT",
        "available":"1001000206.70609902",
        "remark":"",
        "type":1,
        "changeAmount":"0.01966",
        "userId":"6755772669834045440",
        "freezeId":"0",
        "marketId":"101",
        "fundId":"6773134441524176896",
        "beforeAmount":"1001000206.68643902",
        "beforeFreezeAmount":"0",
        "unit":"usdt",
        "modifyTime":"0",
        "createTime":"1616769725796",
        "id":"6781223727985076239",
        "currencyId":"6",
        "outsideId":"6781223728001851392",
        "operatorId":"0",
        "isIn":1
      },
      {
        "symbol":"ETH_USDT",
        "available":"1001000204.7922627",
        "remark":"",
        "type":1,
        "changeAmount":"0.01966",
        "userId":"6755772669834045440",
        "freezeId":"0",
        "marketId":"101",
        "fundId":"6773134441524176896",
        "beforeAmount":"1001000204.7726027",
        "beforeFreezeAmount":"16.67189997",
        "unit":"usdt",
        "modifyTime":"0",
        "createTime":"1616769724121",
        "id":"6781223720959617059",
        "currencyId":"6",
        "outsideId":"6781223720968004069",
        "operatorId":"0",
        "isIn":1
      }
    ],
    "pageNum":1
  }
}
```

- 响应参数说明

| 参数名             | 必选 | 类型       | 说明               |
| :----------------- | :--- | :--------- | :----------------- |
| userId             | 是   | Long       | 用户id             |
| freezeId           | 是   | String     | 冻结id             |
| type               | 是   | BigDecimal | 账单类型           |
| changeAmount       | 是   | BigDecimal | 变更资金量         |
| feeRate            | 否   | BigDecimal | 费率               |
| fee                | 否   | BigDecimal | 手续费             |
| operatorId         | 否   | Long       | 操作者id           |
| beforeAmount       | 是   | BigDecimal | 变更前账户资金     |
| beforeFreezeAmount | 是   | BigDecimal | 变更前冻结资金     |
| marketId           | 否   | Long       | 市场id             |
| outsideId          | 否   | Long       | 外部幂等id         |
| id                 | 否   | Long       | 账单id             |
| isIn               | 否   | Integer    | 1：增加  0： 减少  |
| available          | 否   | BigDecimal | 当前可用资产       |
| unit               | 否   | String     | 币种名称，数量单位 |
| createTime         | 否   | Long       | 创建时间戳         |
| modifyTime         | 否   | Long       | 更新时间戳         |
| extend             | 否   | String     | 备用字段           |

#### 9.3.4、合约的账户详情变动

- 持续推送

- **特有的参数：**

  | 参数名      | 必选 | 类型   | 说明                                                         |
      | :---------- | :--- | :----- | :----------------------------------------------------------- |
  | channel     | 是   | String | Fund.assetChange                                             |
  | convertUnit | 否   | String | 折合单位，页面显示上"≈"号后面的数字单位，可选：cny，usd,btc,默认cny |

    - 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.assetChange",
  "futuresAccountType":1,

  "convertUnit": "cny"
}
```

- 响应格式

```json
{
  "channel":"Fund.assetChange",
  "data":{
    "accountBalance":"9996553.0184782",
    "accountBalanceConvert":"64672699.7530447149",
    "allMargin":"0",
    "allMarginConvert":"0",
    "allUnrealizedPnl":"-3418.13584",
    "allUnrealizedPnlConvert":"-22113.62981688",
    "available":"9984355.9603782",
    "availableConvert":"64593790.8856667649",
    "convertUnit":"cny",
    "freeze":"15615.19394",
    "freezeConvert":"101022.49719483",
    "futuresAccountType":1,
    "percent":"-47.9900%",
    "unit":"usdt",
    "userId":"6755772669834045440"
  }
}
```

- 响应参数说明

| 参数名                  | 类型       | 说明                                                         |
| :---------------------- | :--------- | :----------------------------------------------------------- |
| accountBalance          | BigDecimal | 账户余额：可用+冻结+所以仓位未实现盈亏                       |
| allMargin               | BigDecimal | 所有仓位保证金                                               |
| available               | BigDecimal | 可用资产量                                                   |
| freeze                  | BigDecimal | 冻结量                                                       |
| allUnrealizedPnl        | BigDecimal | 所有对应仓位的累积未实现盈亏                                 |
| accountBalance          | BigDecimal | 账户余额：可用+冻结+所以仓位未实现盈亏                       |
| unit                    | String     | 固定返回，如果是u本位，返回usdt，如果是币本位返回btc，如果是qc合约返回qc，统计数据的单位 |
| allMarginConvert        | BigDecimal | 所有仓位保证金折合                                           |
| availableConvert        | BigDecimal | 可用资产量折合                                               |
| freezeConvert           | BigDecimal | 冻结量折合                                                   |
| allUnrealizedPnlConvert | BigDecimal | 所有对应仓位的累积未实现盈亏折合                             |
| convertUnit             | String     | 折合单位，页面显示上"≈"号后面的数字单位，如：cny，usd,btc    |
| percent                 | BigDecimal | 未实现盈亏/所有仓位保证金*100%                               |



#### 9.3.5  查询合约的账户详情

- 只会推送一次

- **特有的参数：**

  | 参数名      | 必选 | 类型   | 说明                                                         |
      | :---------- | :--- | :----- | :----------------------------------------------------------- |
  | channel     | 是   | String | Fund.assetInfo                                               |
  | convertUnit | 否   | String | 折合单位，页面显示上"≈"号后面的数字单位，可选：cny，usd,btc,默认cny。不能同时订阅多种折合单位。后面订阅会自动取消前面的订阅。 |

    - 请求示例

```json
{
  "action": "subscribe",
  "channel":"Fund.assetInfo",	//资金变动
  "futuresAccountType":1,

  "convertUnit": "cny"
}
```

- 响应结果:

```json
{
  "channel":"Fund.assetInfo",
  "data":{
    "accountBalanceConvert":"6652947691.815372649962",
    "allMarginConvert":"12.92144069965",
    "availableConvert":"6652947642.321004625312",
    "available":"1001000201.96515424",
    "allUnrealizedPnlConvert":"36.572927325",
    "percent":"283.0400%",
    "userId":"6755772669834045440",
    "allMargin":"1.9441555",
    "allUnrealizedPnl":"5.50275",
    "unit":"usdt",
    "convertUnit":"cny",
    "freeze":"1.9441555",
    "freezeConvert":"12.92144069965",
    "futuresAccountType":1,
    "accountBalance":"1001000209.41205974"
  }
}
```

- 响应参数说明

  参考资产汇总变动的响应参数说明

### 9.4仓位

用户仓位只有用户仓位变动Positions.change是有变动就会推送。别的接口都是只推送一次。

- **仓位请求都必须有的参数：**

  | 参数名             | 必选 | 类型    | 说明           |
      | :----------------- | :--- | :------ | :------------- |
  | futuresAccountType | 是   | Integer | 1:USDT永续合约 |


#### 9.4.1、仓位变动

- 用户仓位有变动就会推送给客户，持续推送

- **特有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                       |
      | :------ | :--- | :----- | :----------------------------------------- |
  | channel | 是   | String | Positions.change                           |
  | symbol  | 否   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.change",
  "futuresAccountType":1,

  "symbol":"BTC_USDT"
}
```

- 如果没有symbol，表示仓位的任何变动都会推送给客户。如果指定了symbol，则只会推送此market的仓位变动给客户。

- 响应格式

```json
{
  "channel":"Positions.change",
  "data":{
    "amount":"179.21",
    "autoLightenRatio":"0",
    "avgPrice":"1714.85",
    "contractType":1,
    "createTime":"1616641679860",
    "freezeAmount":"4.26",
    "id":"6780686664403527685",
    "leverage":2,
    "liquidateLevel":2,
    "liquidatePrice":"803.16",
    "maintainMargin":"2180.79583",
    "margin":"164053.23943148",
    "marginBalance":"204814.55393148",
    "marginMode":1,
    "marginRate":"0.010647",
    "marketId":"101",
    "marketName":"ETH_USDT",
    "nominalValue":"327921.46402",
    "originId":"6780686664403527710",
    "positionsMode":2,
    "returnRate":"0.2652",
    "side":1,
    "status":1,
    "unrealizedPnl":"40761.3145",
    "userId":"6779951231092664320"
  }
}
```

-  响应参数说明

| 参数名         | 必选 | 类型       | 说明                                    |
| :------------- | :--- | :--------- | :-------------------------------------- |
| userId         | 是   | Long       | 用户id                                  |
| marketId       | 是   | Long       | 市场id                                  |
| symbol         | 是   | String     | 市场名称                                |
| side           | 是   | Integer    | 开仓方向,开多：1 开空：0                |
| leverage       | 否   | Integer    | 杠杆倍数                                |
| amount         | 否   | BigDecimal | 持有仓位数量                            |
| freezeAmount   | 是   | BigDecimal | 下单冻结仓位数量                        |
| avgPrice       | 是   | BigDecimal | 开仓均价                                |
| liquidatePrice | 是   | BigDecimal | 强平价格                                |
| margin         | 是   | BigDecimal | 保证金                                  |
| marginMode     | 是   | Integer    | 保证金模式：1逐仓（默认），2全仓        |
| positionsMode  | 是   | Integer    | 1:单向持仓，2: 双向持仓                 |
| status         | 是   | Integer    | 状态: 1 可用、2:锁定、3:冻结、4：不显示 |
| unrealizedPnl  | 否   | BigDecimal | 未实现盈亏                              |
| marginBalance  | 是   | BigDecimal | 保证金余额                              |
| maintainMargin | 是   | BigDecimal | 维持保证金                              |
| marginRate     | 是   | BigDecimal | 保证金率                                |
| nominalValue   | 是   | BigDecimal | 头寸的名义价值                          |
| id             | 是   | Long       | 仓位id                                  |
| createTime     | 是   | Long       | 创建时间                                |
| modifyTime     | 是   | Long       | 修改时间                                |
| extend         | 否   | Long       | 备用字段                                |

#### 9.4.2、仓位查询

- 只会推送一次

- **特有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                       |
      | :------ | :--- | :----- | :----------------------------------------- |
  | channel | 是   | String | Positions.getPositions                     |
  | symbol  | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.getPositions",
  "futuresAccountType":1,

  "symbol":"BTC_USDT"
}
```

- 如果没有symbol，表示所有的仓位都会推送给客户。如果指定了symbol，则只会推送此market的仓位。

- 响应字段说明与上面的用户仓位变动的字段是一样的

- 响应格式

```json
{
  "channel":"Positions.getPositions",
  "data":[
    {
      "leverage":20,
      "returnRate":"2.9524",
      "avgPrice":"1690.4",
      "contractType":1,
      "marginMode":1,
      "marketId":"101",
      "marginRate":"0.023228",
      "freezeAmount":"0",
      "originId":"6781405543660529684",
      "autoLightenRatio":"0.9",
      "id":"6780839890322991104",
      "marginBalance":"7.6835755",
      "amount":"0.023",
      "margin":"1.9441555",
      "side":1,
      "liquidatePrice":"1612.32",
      "userId":"6755772669834045440",
      "marketName":"ETH_USDT",
      "createTime":"1616813074031",
      "unrealizedPnl":"5.73942",
      "liquidateLevel":1,
      "positionsMode":2,
      "maintainMargin":"0.17847448",
      "nominalValue":"38.98109",
      "status":1
    }
  ]
}
```

- 响应参数说明

| 参数名         | 必选 | 类型       | 说明                                    |
| :------------- | :--- | :--------- | :-------------------------------------- |
| userId         | 是   | Long       | 用户id                                  |
| marketId       | 是   | Long       | 市场id                                  |
| symbol         | 是   | String     | 市场名称                                |
| side           | 是   | Integer    | 开仓方向,开多：1 开空：0                |
| leverage       | 否   | Integer    | 杠杆倍数                                |
| amount         | 否   | BigDecimal | 持有仓位数量                            |
| freezeAmount   | 是   | BigDecimal | 下单冻结仓位数量                        |
| avgPrice       | 是   | BigDecimal | 开仓均价                                |
| liquidatePrice | 是   | BigDecimal | 强平价格                                |
| margin         | 是   | BigDecimal | 保证金                                  |
| marginMode     | 是   | Integer    | 保证金模式：1逐仓（默认），2全仓        |
| positionsMode  | 是   | Integer    | 1:单向持仓，2: 双向持仓                 |
| status         | 是   | Integer    | 状态: 1 可用、2:锁定、3:冻结、4：不显示 |
| unrealizedPnl  | 否   | BigDecimal | 未实现盈亏                              |
| marginBalance  | 是   | BigDecimal | 保证金余额                              |
| maintainMargin | 是   | BigDecimal | 维持保证金                              |
| marginRate     | 是   | BigDecimal | 保证金率                                |
| nominalValue   | 是   | BigDecimal | 头寸的名义价值                          |
| id             | 是   | Long       | 仓位id                                  |
| createTime     | 是   | Long       | 创建时间                                |
| modifyTime     | 是   | Long       | 修改时间                                |
| extend         | 否   | Long       | 备用字段                                |



#### 9.4.3、保证金信息查询

- 只会推送一次

- **特有的参数：**

  | 参数名      | 必选 | 类型   | 说明                 |
      | :---------- | :--- | :----- | :------------------- |
  | channel     | 是   | String | Positions.marginInfo |
  | positionsId | 是   | Long   | 仓位id               |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.marginInfo",
  "futuresAccountType":1,

  "positionsId":"6742095107924699136"	//仓位id
}
```



- 响应格式

```json
{
  "channel":"Positions.marginInfo",
  "data":{
    "positionsId": "6742095107924699136",	//
    "maxAdd": 1212.12,	//最大保证金增加数量
    "maxSub": 1212.12,	//最大保证金提取数量
    "liquidatePrice": 121212.12	//预计强平价格
  }
}
```

#### 9.4.4、提取或增加保证金

- 只会推送一次

- **特有的参数：**

  | 参数名      | 必选 | 类型       | 说明                   |
      | :---------- | :--- | :--------- | :--------------------- |
  | channel     | 是   | String     | Positions.updateMargin |
  | positionsId | 是   | Long       | 仓位id                 |
  | amount      | 是   | BigDecimal | 变动数量               |
  | type        | 是   | Integer    | 1: 增加  0：减少       |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.updateMargin",
  "futuresAccountType":1,

  "positionsId":"6742095107924699136",
  "amount": 1,
  "type":1
}
```

- 响应格式

```json
{
  "channel":"Positions.updateMargin",
  "data":{
    "leverage":20,
    "avgPrice":"2013.94",
    "bankruptcyPrice":"2121.33",
    "marginMode":1,
    "marketId":"101",
    "marginRate":"0",
    "freezeAmount":"0",
    "modifyTime":"1617872786967",
    "originId":"6785805193553389618",
    "id":"6785805193549195299",
    "marginBalance":"0",
    "amount":"0.15",
    "margin":"16.10917",
    "side":0,
    "liquidatePrice":"2112.89",
    "keyMark":"6755772669834045440-101-0-",
    "userId":"6755772669834045440",
    "marketName":"ETH_USDT",
    "createTime":"1617862032307",
    "unrealizedPnl":"0.066",
    "liquidateLevel":1,
    "positionsMode":2,
    "maintainMargin":"0",
    "nominalValue":"302.0637",
    "open":false,
    "status":1
  }
}
```

- 响应参数说明

  见用户仓位查询



#### 9.4.5、仓位配置信息查询

- 只会推送一次

- **特有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                       |
      | :------ | :--- | :----- | :----------------------------------------- |
  | channel | 是   | String | Positions.getSetting                       |
  | symbol  | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.getSetting",
  "futuresAccountType":1,

  "symbol":"BTC_USDT"
}
```



- 响应格式

```json
{
  "channel":"Positions.setLeverage",
  "data":{
    "leverage":12,
    "modifyTime":"1617951800483",
    "createTime":"1617881408203",
    "positionsMode":2,
    "id":"6785886461951485952",
    "marginMode":1,
    "keyMark":"6755772669834045440-101-",
    "userId":"6755772669834045440",
    "marketId":"101"
  }
}
```

#### 9.4.6、仓位杠杆设置

- 只会推送一次

- **特有的参数：**

  | 参数名   | 必选 | 类型    | 说明                                       |
      | :------- | :--- | :------ | :----------------------------------------- |
  | channel  | 是   | String  | Positions.setLeverage                      |
  | symbol   | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | leverage | 是   | Integer | 杠杆倍数                                   |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.setLeverage",
  "futuresAccountType":1,

  "symbol":"BTC_USDT",
  "leverage": 20
}
```



- 响应格式

```json
{
  "channel":"Positions.setPositionsMode",
  "data":{
    "leverage":13,
    "modifyTime":"1617955003674",
    "createTime":"1617881408203",
    "positionsMode":1,
    "id":"6785886461951485952",
    "marginMode":1,
    "keyMark":"6755772669834045440-101-",
    "userId":"6755772669834045440",
    "marketId":"101"
  }
}
```



#### 9.4.7、仓位持仓模式设置

- 只会推送一次

- **特有的参数：**

  | 参数名        | 必选 | 类型    | 说明                                       |
      | :------------ | :--- | :------ | :----------------------------------------- |
  | channel       | 是   | String  | Positions.setPositionsMode                 |
  | symbol        | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | positionsMode | 是   | Integer | 1:单向持仓，2: 双向持仓                    |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.setPositionsMode",
  "futuresAccountType":1,

  "symbol":"BTC_USDT",
  "positionsMode":1
}
```

- 响应格式

```json
{
  "channel":"Positions.setMarginMode",
  "data":{
    "leverage":13,
    "modifyTime":"1617955003674",
    "createTime":"1617881408203",
    "positionsMode":1,
    "id":"6785886461951485952",
    "marginMode":1,
    "keyMark":"6755772669834045440-101-",
    "userId":"6755772669834045440",
    "marketId":"101"
  }
}
```

#### 9.4.8、仓位保证金模式设置

- 只会推送一次

- **特有的参数：**

  | 参数名     | 必选 | 类型    | 说明                                       |
      | :--------- | :--- | :------ | :----------------------------------------- |
  | channel    | 是   | String  | Positions.setMarginMode                    |
  | symbol     | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | marginMode | 是   | Integer | 1逐仓（默认），2全仓                       |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.setMarginMode",
  "futuresAccountType":1,

  "symbol":"BTC_USDT",
  "marginMode":1
}
```

- 响应格式

```json
{
  "channel":"Positions.setMarginMode",
  "data":{
    "leverage":13,
    "modifyTime":"1617955003674",
    "createTime":"1617881408203",
    "positionsMode":1,
    "id":"6785886461951485952",
    "marginMode":1,
    "keyMark":"6755772669834045440-101-",
    "userId":"6755772669834045440",
    "marketId":"101"
  }
}
```

#### 9.4.9、查看用户当前头寸

- 只会推送一次

- **特有的参数：**

  | 参数名  | 必选 | 类型    | 说明                                       |
      | :------ | :--- | :------ | :----------------------------------------- |
  | channel | 是   | String  | Positions.getNominalValue                  |
  | symbol  | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | side    | 是   | Integer | 方向：1：开多   0 开空                     |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Positions.getNominalValue",
  "futuresAccountType":1,

  "symbol":"BTC_USDT",
  "side":1
}
```

- 响应格式

```json
{
  "channel":"Positions.getNominalValue",
  "data":{
    "side":1,
    "openOrderNominalValue":"0",
    "nominalValue":"0",
    "marketId":"100"
  }
}
```

- 响应参数说明：

| 参数名                | 必选 | 类型       | 说明                 |
| :-------------------- | :--- | :--------- | :------------------- |
| nominalValue          | 是   | BigDecimal | 用户仓位头寸名义价值 |
| marketId              | 是   | Long       | 市场id               |
| openOrderNominalValue | 是   | BigDecimal | 委托单头寸名义价值   |

### 9.5订单和交易

#### 9.5.1、订单变动

- 用户订单有变动就会推送给客户，持续推送

- **特有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                       |
      | :------ | :--- | :----- | :----------------------------------------- |
  | channel | 是   | String | trade.orderChange                          |
  | symbol  | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.orderChange"

  "symbol":"BTC_USDT"
}
```

- 如果没有symbol，表示仓位的任何变动都会推送给客户。如果指定了symbol，则只会推送此market的仓位变动给客户。
- 响应结果

```json
{
  "channel":"Trade.orderChange",
  "data":{
    "action":1,
    "amount":"1",
    "availableAmount":"1",
    "availableValue":"2022.1",
    "avgPrice":"0",
    "canCancel":true,
    "cancelStatus":20,
    "createTime":"1617955686930",
    "entrustType":1,
    "id":"6786198009513254912",
    "leverage":13,
    "margin":"155.560153",
    "marketId":"101",
    "orderCode":"6786198009530034176",
    "price":"2022.1",
    "showStatus":1,
    "side":1,
    "sourceType":5,
    "status":12,
    "tradeAmount":"0",
    "tradeValue":"0",
    "type":1,
    "userId":"6755772669834045440",
    "value":"2022.1"
  }
}
```

- 响应参数说明

​		参考``5.6查询当前全部挂单`` 返回结果说明



#### 9.5.2、下单

- 只会推送一次

- **特有的参数：**

  | 参数名         | 必选 | 类型    | 说明                                                         |
    | :------------ | ---- | :------ | :----------------------------------------------------------- |
  | channel       | 是   | String  | trade.order                                                  |
  | symbol        | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT                   |
  | price         | 是   | Decimal | 价格                                                         |
  | amount        | 是   | Decimal | 数量                                                         |
  | actionType    | 是   | Integer | 1   限价<br/>11 对手价<br/>12 最优5档<br/>3   IOC<br/>31 对手价IOC<br/>32 最优5档IOC<br/>4   只做 maker<br/>5   FOK<br/>51 对手价FOK<br/>52 最优5档FOK<br/> |
  | side          | 是   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
  | clientOrderId | 否   | String | 自定义id |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.order",

  "symbol":"BTC_USDT",
  "price":"65536",
  "amount":1,
  "actionType":1,
  "side":1
}
```

- 响应结果

```json
{
  "channel":"Trade.order",
  "data": {
    "orderId":"6848243828432838656",
    "orderCode":"01aa0ff5b1974d9ab09167b77e6dd116"
  }
}
```

- 响应参数说明

| 参数名    | 必选 | 类型   | 说明         |
| :-------- | :--- | :----- | :----------- |
| orderId   | 是   | String | 订单id       |
| orderCode | 是   | String | 自定义订单号 |

#### 9.5.3、查询订单明细

- 只会推送一次

- **特有的参数：**

  | 参数名        | 必选 | 类型   | 说明                                       |
      | ------------- | ---- | :----- | :----------------------------------------- |
  | channel       | 是   | String | trade.getOrder                             |
  | symbol        | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | orderId       | 否   | Long   | 订单ID                                     |
  | clientOrderId | 否   | String | 自定义id                                   |

  orderId和clientOrderId二选一

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.getOrder",

  "symbol":"BTC_USDT",
  "orderId":6753263247702368256
}
```

- 响应结果

```json
{
  "channel":"Trade.getOrder",
  "data":{
    "leverage":10,
    "avgPrice":"0",
    "cancelStatus":20,
    "type":1,
    "marketId":"101",
    "modifyTime":"1617886532837",
    "availableAmount":"1",
    "price":"2022.1",
    "action":1,
    "id":"6785907956199202816",
    "value":"2022.1",
    "amount":"1",
    "margin":"202.21",
    "side":1,
    "availableValue":"2022.1",
    "tradeValue":"0",
    "showStatus":1,
    "userId":"6755772669834045440",
    "tradeAmount":"0",
    "createTime":"1617886532831",
    "sourceType":5,
    "orderCode":"6785907956220176394",
    "entrustType":1,
    "canCancel":true,
    "status":12
  }
}
```

- 响应参数说明

  参考订单变动的响应参数说明



#### 9.5.4、取消订单

- 只会推送一次

- **特有的参数：**

  | 参数名        | 必选 | 类型   | 说明                                       |
      | ------------- | ---- | :----- | :----------------------------------------- |
  | channel       | 是   | String | trade.cancelOrder                          |
  | symbol        | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | orderId       | 否   | Long   | 订单ID                                     |
  | clientOrderId | 否   | String | 自定义id                                   |

- orderId和clientOrderId二选一

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.cancelOrder",

  "symbol":"BTC_USDT",
  "orderId":6753263256262942720
}
```

- 响应结果

```json
{
  "channel":"Trade.cancelOrder",
  "data":"6753263256262942720" // 订单号
}
```

#### 9.5.5、批量取消委托

- 只会推送一次

- **特有的参数：**

| 参数名         | 必选 | 类型     | 说明                                       |
| -------------- | ---- | :------- | :----------------------------------------- |
| channel        | 是   | String   | trade.batchCancelOrder                     |
| symbol         | 是   | String   | 合约，即市场交易对唯一标识符，如：BTC_USDT |
| orderIds       | 否   | Long[]   | 订单ID列表                                 |
| clientOrderIds | 否   | String[] | 自定义id列表                               |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.batchCancelOrder",

  "symbol":"BTC_USDT",
  "orderIds":[1753262282144227328, 6753260246627524608]
}
```

- 成功响应

```json
{
  "channel":"Trade.batchCancelOrder",
  "data":[],
}
```

- 失败响应

```json
{
  "channel":"Trade.batchCancelOrder",
  "data":[
    {
      "code":12012,
      "data":"6786122846578941952",
      "desc":"订单不存在"
    },
    {
      "code":12012,
      "data":"6786122900735795200",
      "desc":"订单不存在"
    }
  ]
}
```

#### 9.5.6、取消所有订单

- 只会推送一次

- **特有的参数：**

| 参数名  | 必选 | 类型   | 说明                                       |
| ------- | ---- | :----- | :----------------------------------------- |
| channel | 是   | String | trade.cancelAllOrders                      |
| symbol  | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.cancelAllOrders",

  "symbol":"BTC_USDT"
}
```

- 响应结果

```json
{
  "channel":"Trade.cancelAllOrders",
  "data":[],
}
```

#### 9.5.7、查询当前全部挂单(未完成的订单列表)

- 只会推送一次

- **特有的参数：**

  | 参数名   | 必选 | 类型    | 说明                                       |
      | -------- | ---- | :------ | :----------------------------------------- |
  | channel  | 是   | String  | trade.getUndoneOrders                      |
  | symbol   | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | pageNum  | 是   | Integer | 页码，从1开始                              |
  | pageSize | 是   | Integer | 分页大小                                   |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.getUndoneOrders",

  "symbol":"BTC_USDT"
}
```

- 响应结果

```json
{
  "channel":"Trade.getUndoneOrders",
  "data":{
    "pageSize":10,
    "list":[
      {
        "leverage":20,
        "amount":"1",
        "margin":"42.27596046",
        "side":2,
        "availableValue":"426",
        "avgPrice":"0",
        "cancelStatus":20,
        "tradeValue":"0",
        "showStatus":1,
        "type":-1,
        "userId":"1499",
        "marketId":"104",
        "tradeAmount":"0",
        "modifyTime":"1610103429879",
        "availableAmount":"1",
        "createTime":"1610103429870",
        "sourceType":1,
        "price":"426",
        "action":1,
        "entrustType":1,
        "id":"6753263256317468672",
        "value":"426",
        "canCancel":true,
        "status":12
      },
      {
        "leverage":20,
        "amount":"1",
        "margin":"43.27596046",
        "side":2,
        "availableValue":"425",
        "avgPrice":"0",
        "cancelStatus":20,
        "tradeValue":"0",
        "showStatus":1,
        "type":-1,
        "userId":"1499",
        "marketId":"104",
        "tradeAmount":"0",
        "modifyTime":"1610103429866",
        "availableAmount":"1",
        "createTime":"1610103429857",
        "sourceType":1,
        "price":"425",
        "action":1,
        "entrustType":1,
        "id":"6753263256262942720",
        "value":"425",
        "canCancel":true,
        "status":12
      }
    ],
    "pageNum":1
  }
}
```

#### 9.5.8、查询所有订单

- 只会推送一次

- **特有的参数：**

  | 参数名    | 必选 | 类型    | 说明                                       |
      | --------- | ---- | :------ | :----------------------------------------- |
  | channel   | 是   | String  | trade.getAllOrders                         |
  | symbol    | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | startTime | 否   | Long    | 开始时间                                   |
  | endTime   | 否   | Long    | 结束时间                                   |
  | pageNum   | 是   | Integer | 页码，从1开始                              |
  | pageSize  | 是   | Integer | 分页大小                                   |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.getAllOrders",

  "symbol":"BTC_USDT"
}
```

- 响应结果

```json
{
  "channel":"Trade.getAllOrders",
  "data":{
    "pageSize":10,
    "list":[
      {
        "leverage":13,
        "avgPrice":"0",
        "cancelStatus":20,
        "type":1,
        "marketId":"101",
        "modifyTime":"1617955672776",
        "availableAmount":"1",
        "price":"2022.1",
        "action":1,
        "id":"6786197950126104576",
        "value":"2022.1",
        "amount":"1",
        "margin":"155.560153",
        "side":1,
        "availableValue":"2022.1",
        "tradeValue":"0",
        "showStatus":1,
        "userId":"6755772669834045440",
        "tradeAmount":"0",
        "createTime":"1617955672771",
        "sourceType":5,
        "orderCode":"6786197950142883840",
        "entrustType":1,
        "canCancel":true,
        "status":12
      },
      {
        "leverage":10,
        "avgPrice":"0",
        "cancelStatus":23,
        "type":1,
        "marketId":"101",
        "modifyTime":"1617937836671",
        "availableAmount":"1",
        "price":"2022.1",
        "action":1,
        "id":"6786122846578941952",
        "value":"2022.1",
        "amount":"1",
        "margin":"202.21",
        "side":1,
        "availableValue":"2022.1",
        "tradeValue":"0",
        "showStatus":5,
        "userId":"6755772669834045440",
        "tradeAmount":"0",
        "createTime":"1617937766690",
        "sourceType":5,
        "orderCode":"6786122846595721226",
        "entrustType":1,
        "canCancel":false,
        "status":12
      }
    ],
    "pageNum":1
  }
}
```

#### 9.5.9、查询成交明细

- 只会推送一次

- **特有的参数：**

  | 参数名  | 必选 | 类型   | 说明                                       |
      | ------- | ---- | :----- | :----------------------------------------- |
  | channel | 是   | String | trade.getTradeList                         |
  | symbol  | 是   | String | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | orderId | 是   | Long   | 订单ID                                     |

- 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.getTradeList",
  "orderId":"6785805407710355456",
  "symbol":"BTC_USDT"，
}
```

- 响应结果

```json
{
  "channel":"Trade.getTradeList",
  "data":{
    "pageSize":10,
    "list":[
      {
        "feeAmount":"0.00402802",
        "amount":"0.01",
        "side":2,
        "createTime":"1617862083588",
        "orderId":"6785805407710355456",
        "price":"2014.01",
        "feeCurrency":"USDT",
        "maker":true,
        "relizedPnl":"0",
        "userId":"6755772669834045440"
      },
      {
        "feeAmount":"0.00402802",
        "amount":"0.01",
        "side":2,
        "createTime":"1617862083425",
        "orderId":"6785805407710355456",
        "price":"2014.01",
        "feeCurrency":"USDT",
        "maker":true,
        "relizedPnl":"0",
        "userId":"6755772669834045440"
      }
    ],
    "pageNum":1
  }
}
```

- 响应参数说明

| 参数名      | 必选 | 类型    | 说明                                                         |
| :---------- | :--- | :------ | :----------------------------------------------------------- |
| orderId     | 是   | Long    | 订单id                                                       |
| price       | 是   | Decimal | 成交价格                                                     |
| amount      | 是   | Decimal | 成交数量                                                     |
| feeAmount   | 是   | Decimal | 手续费                                                       |
| feeCurrency | 是   | String  | 手续费币种                                                   |
| relizedPnl  | 是   | Decimal | 已实现盈亏                                                   |
| side        | 是   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
| maker       | 是   | Boolean | 是否maker,否则为taker                                        |
| createTime  | 是   | Long    | 成交时间戳                                                   |

#### 9.5.10、查询历史成交记录

- 只会推送一次

- **特有的参数：**

  | 参数名    | 必选 | 类型    | 说明                                       |
      | --------- | ---- | :------ | :----------------------------------------- |
  | channel   | 是   | String  | trade.tradeHistory                         |
  | symbol    | 是   | String  | 合约，即市场交易对唯一标识符，如：BTC_USDT |
  | startTime | 否   | Long    | 开始时间                                   |
  | endTime   | 否   | Long    | 结束时间                                   |
  | pageNum   | 是   | Integer | 页码，从1开始                              |
  | pageSize  | 是   | Integer | 分页大小                                   |

-

    - 请求示例

```json
{
  "action": "subscribe",
  "channel":"Trade.tradeHistory",

  "symbol":"BTC_USDT"，
}
```

- 响应结果

```json
{
  "channel":"Trade.tradeHistory",
  "data":{
    "pageSize":10,
    "list":[
      {
        "feeAmount":"0.00402802",
        "amount":"0.01",
        "side":2,
        "createTime":"1617862083588",
        "orderId":"6785805407710355456",
        "price":"2014.01",
        "feeCurrency":"USDT",
        "maker":true,
        "relizedPnl":"0",
        "userId":"6755772669834045440"
      },
      {
        "feeAmount":"0.00402788",
        "amount":"0.01",
        "side":2,
        "createTime":"1617862032282",
        "orderId":"6785805175605960704",
        "price":"2013.94",
        "feeCurrency":"USDT",
        "maker":true,
        "relizedPnl":"0",
        "userId":"6755772669834045440"
      }
    ],
    "pageNum":1
  }
}
```

- 响应参数说明

  参考查询成交明细的响应参数说明

#### 9.5.11、批量下单

- 只会推送一次

**特有的参数：**

| 名称       | 类型   | 是否必须 | 描述                                       |
| :--------- | :----- | :------- | :----------------------------------------- |
| channel    | 是     | String   | Trade.batchOrder                           |
| orderDatas | String | 是       | 订单列表，JSON类型的字符串，参数同下单接口 |

- **请求示例**

```json
{
  "action": "subscribe",
  "channel":"Trade.batchOrder",

  "orderDatas": [{"symbol":"ETH_USDT","amount":1,"side":1,"price":"1100","action":1, "orderCode": "test01"},{"symbol":"ETH_USDT","amount":1,"side":1,"price":"1000","action":1, "orderCode": "test02"}]
}
```

- 响应结果:

```
{
  "channel":"Trade.batchOrder",
  "data": [
    {
      "sCode": 1,
      "orderId": "6754725173120933888",
      "orderCode": "6754725172671948800",
      "sMsg": "success"
    },
    {
      "sCode": 1,
      "orderId": "6754725173074796544",
      "orderCode": "6754725172676143104",
      "sMsg": "success"
    }
  ]
}

```
响应参数说明 data：

| 名称      | 类型   | 是否必须 | 描述                                 |
| :-------- | :----- | :------- | :----------------------------------- |
| sCode     | Int    | 是       | 结果的code，1代表成功                |
| sMsg      | String | 是       | 结果描述                             |
| orderId   | String | 否       | 订单ID                               |
| orderCode | String | 否       | 自定义订单ID，如空缺系统会自动赋值。 |



## 10.错误码

| 代码   | 描述                                             |
| :----- | :----------------------------------------------- |
| 10000  | 操作成功                                         |
| 10001  | 操作失败                                         |
| 10002  | 操作被禁止                                       |
| 10003  | 数据已存在                                       |
| 10004  | 数据不存在                                       |
| 10005  | 禁止访问接口                                     |
| 10006  | token无效或已过期                                |
| 10007  | {0}                                              |
| 10008  | 操作失败: {0}                                    |
| 10009  | URL错误                                          |
| 10010  | API KEY不存在                                    |
| 10011  | API KEY已关闭                                    |
| 10012  | 用户API已被冻结，请联系客服处理                  |
| 10013  | api校验失败                                      |
| 10014  | 无效的签名(1001)                                 |
| 10015  | 无效的签名(1002)                                 |
| 10016  | 无效的ip                                         |
| 10017  | 没有权限                                         |
| 10018  | 用户已被冻结，请联系客服处理                     |
| 10019  | 请求时间已失效                                   |
| 10020  | {0}参数不能为空                                  |
| 10021  | {0}参数值无效                                    |
| 10022  | 请求method错误                                   |
| 10023  | 请求频率过快，超过该接口允许的限额               |
| 10024  | 登录失败                                         |
| 10025  | 非本人操作                                       |
| 10026  | 请求接口失败，请您重试                           |
| 10027  | 请求超时，请稍后再试                             |
| 10028  | 系统繁忙，请稍后再试                             |
| 10029  | 操作频繁，请稍后再试                             |
| 10030  | 币种已存在                                       |
| 10031  | 币种不存在                                       |
| 10032  | 市场已存在                                       |
| 10033  | 市场不存在                                       |
| 10034  | 币种错误                                         |
| 10035  | 市场未开放                                       |
| 10036  | 无效的市场类型                                   |
| 10037  | 用户id不能为空                                   |
| 10038  | 市场id不能为空                                   |
| 10039  | 标记价格获取失败                                 |
| 10040  | 开仓保证金配置获取失败                           |
| 10041  | 维持保证金配置获取失败                           |
| 10042  | avg price error                                  |
| 10043  | 强平价格获取异常                                 |
| 10044  | 未实现盈亏获取异常                               |
| 10045  | jdbc数据源获取失败                               |
| 10046  | 无效的开仓方向                                   |
| 10047  | 已超过当前杠杆倍数允许的最大头寸                 |
| 10048  | 已超过最大允许的下单数量                         |
| 10049  | 最新成交价格获取失败                             |
| 10100  | 抱歉！系统维护中，停止操作                       |
| 11000  | 资金变更失败                                     |
| 11001  | 仓位变更失败                                     |
| 11002  | 资金不存在                                       |
| 11003  | 冻结记录不存在                                   |
| 11004  | 冻结资金不足                                     |
| 11005  | 仓位不足                                         |
| 11006  | 冻结仓位不足                                     |
| 11007  | 仓位不存在                                       |
| 11008  | 该合约有持仓,禁止修改                            |
| 11009  | 查询数据失败                                     |
| 110110 | 超过市场最大杠杆倍数                             |
| 110011 | 超过仓位允许最大杠杆倍数                         |
| 11012  | 保证金不足                                       |
| 11013  | 超出精度限制                                     |
| 11014  | 账单类型无效                                     |
| 11015  | 添加默认账户失败                                 |
| 11016  | 账户不存在                                       |
| 11017  | 资金未冻结或已解冻                               |
| 11018  | 资金不足                                         |
| 11019  | 账单不存在                                       |
| 11021  | 资金划转币种不一致                               |
| 11023  | 交易币种相同                                     |
| 11030  | 仓位被锁定，禁止操作                             |
| 11031  | 账单变化数量为零                                 |
| 11032  | 有相同请求处理中，请勿重复提交。                 |
| 11033  | 仓位配置数据为空                                 |
| 11034  | 资金费正在结算，请勿操作                         |
| 11035  | 只减仓下单和同向挂单不兼容                       |
| 12000  | 下单价格无效                                     |
| 12001  | 下单数量无效                                     |
| 12002  | 订单类型无效                                     |
| 12003  | 价格精度无效                                     |
| 12004  | 数量精度无效                                     |
| 12005  | 下单数量小于最小值或大于最大值                   |
| 12006  | 自定义的订单号格式错误                           |
| 12007  | side错误                                         |
| 12008  | 下单类型错误                                     |
| 12009  | 委托类型错误                                     |
| 12010  | 下单失败，以此价格下单成交亏损金额将超过保证金   |
| 12011  | it's not a buz order                             |
| 12012  | 订单不存在                                       |
| 12013  | 订单用户不匹配                                   |
| 12014  | 订单仍在交易中                                   |
| 12015  | 订单预处理失败                                   |
| 12016  | 订单不能取消                                     |
| 12017  | 成交记录不存在                                   |
| 12018  | 下单失败                                         |
| 12019  | extend参数不能为空                               |
| 12020  | extend参数错误                                   |
| 12021  | 下单价格不在限价规则范围内！                     |
| 12022  | 系统计算资金费中，停止下单                       |
| 12023  | 没有需要平仓的仓位                               |
| 12024  | 禁止下单，敬请期待！                             |
| 12025  | 禁止撤单，敬请期待！                             |
| 12026  | 下单失败，自定义订单号已存在                     |
| 12027  | 委托繁忙，请稍后再试                             |
| 12028  | 该市场已禁止交易                                 |
| 12029  | 禁止下开仓单，敬请期待！                         |
| 12030  | 下单名义价值小于最小值或大于最大值               |
| 12031  | 订单已完成禁止修改                               |
| 12201  | 委托策略不存在或状态已变更                       |
| 12202  | 托策略状态已变更，不能取消                       |
| 12203  | orderType类型错误                                |
| 12204  | 触发价格无效                                     |
| 12205  | 触发价必须大于当前行情的卖1档价格或小于买1档价格 |
| 12206  | side和orderType不匹配                            |
| 12207  | 提交失败，超过允许添加的上限                     |
| 12208  | 触发价格精度无效                                 |
| 13001  | 用户不存在                                       |
| 13002  | 用户未开启合约                                   |
| 13003  | 用户被锁定                                       |
| 13003  | 保证金档位不连续                                 |
| 13004  | 保证金速算额小于0                                |
| 13005  | 您已超过了当天导出的次数                         |
| 13006  | 未收藏任何市场                                   |
| 13007  | 市场未收藏                                       |
| 13008  | 不在任何市场用户白名单                           |
| 13009  | 不在此市场用户白名单中                           |
| 14000  | {0} 不支持                                       |
| 14001  | 已登录，不需多次登录                             |
| 14002  | 还未登录，请先登录再订阅                         |
| 14003  | 这是用于一次性查询的频道，不需要取消订阅         |
| 14100  | 精度不支持                                       |
| 14101  | 请求超出限频次数                                 |
| 14200  | id为空                                           |
| 14300  | 活动期数不存在                                   |
| 14301  | 活动已开启，不能入场                             |
| 14302  | 已超过购买时间，不能入场                         |
| 14303  | 还未开放购买                                     |
| 14305  | 不能入场，已超过最大返场次数了                   |
| 14306  | 不能重复入场                                     |
| 14307  | 无法取消，状态已变更                             |
| 14308  | 无法取消，金额不一致                             |
| 14309  | 活动未开始                                       |
| 14310  | 活动已结束                                       |
| 14311  | 此活动不支持本市场下单                           |
| 14312  | 您还未参加本次活动                               |
| 14313  | 抱歉！购买失败，已达到最大可参与人数了           |
| 14314  | 活动期id错误                                     |
| 9999   | 未知错误                                         |
