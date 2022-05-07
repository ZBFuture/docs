* [1\. Request Rules](#1-request-rules)
    * [1\.1\. Request parameter mode convention](#11-request-parameter-mode-convention)
    * [1\.2\. Request header parameter](#12-request-header-parameter)
    * [1\.3\. Signature rules](#13-signature-rules)
        * [1\.3\.1\. ApiKey](#131-apikey)
        * [1\.3\.2\. Request verification](#132-request-verification)
        * [1\.3\.3\. request query/request body parameter ordering](#133-request-queryrequest-body-parameter-ordering)
        * [1\.3\.4\. Compose the final string to be calculated for signature](#134-compose-the-final-string-to-be-calculated-for-signature)
        * [1\.3\.5\. Time synchronization security](#135-time-synchronization-security)
        * [1\.3\.6\. Java code example](#136-java-code-example)
        * [1\.3\.7\. Python代码示例](#137-python代码示例)
        * [1\.3\.8\. requestPath](#138-requestpath)
    * [1\.4\. Access Limit Frequency Rules](#14-access-limit-frequency-rules)
* [2\. Response rules](#2-response-rules)
* [3\. Server address](#3-server-address)
* [4\. Accounts and transactions](#4-accounts-and-transactions)
    * [4\.1 Futures account information](#41-futures-account-information)
    * [4\.2 All Contract Positions/Single Contract Position(marketId\+side filter)](#42-all-contract-positionssingle-contract-positionmarketidside-filter)
    * [4\.3 Margin information query (the maximum amount of margin increase, the maximum amount of margin withdrawal, and the expected liquidation price)](#43-margin-information-query-the-maximum-amount-of-margin-increase-the-maximum-amount-of-margin-withdrawal-and-the-expected-liquidation-price)
    * [4\.4 Margin withdrawal or increase](#44-margin-withdrawal-or-increase)
    * [4\.5 Position leverage setting](#45-position-leverage-setting)
    * [4\.6 Position holding mode setting](#46-position-holding-mode-setting)
    * [4\.7 Margin mode setting](#47-margin-mode-setting)
    * [4\.8 View the user's current position](#48-view-the-users-current-position)
    * [4\.9 Query user bill](#49-query-user-bill)
    * [4\.10 Query bill type information list](#410-query-bill-type-information-list)
    * [4\.11 Isolated Margin change history](#411-isolated-margin-change-history)
    * [4\.12 Position configuration information query](#412-position-configuration-information-query)
    * [4\.13 Query funds through userid, currencyName](#413-query-funds-through-userid-currencyname)
    * [4\.14 Automatic margin call setting](#414-automatic-margin-call-setting)
    * [4\.15 Margin usage sequence setting](#415-margin-usage-sequence-setting)
    * [4\.16 Transfer of funds with zb](#416-transfer-of-funds-with-zb)
    * [4\.17 Query the freeze type information list](#417-query-the-freeze-type-information-list)
    * [4\.18 Query frozen list](#418-query-frozen-list)
        * [freeze字段说明](#freeze字段说明)
        * [freeze\.extend字段说明,有值的情况](#freezeextend字段说明有值的情况)
* [5\. Futures Trading](#5-futures-trading)
    * [5\.1 Place an order](#51-place-an-order)
        * [SP/SL Parameter Description](#spsl-parameter-description)
    * [<strong>5\.2</strong> Batch order](#52-batch-order)
    * [5\.3 Order Cancel](#53-order-cancel)
    * [5\.4 Batch order cancel](#54-batch-order-cancel)
    * [5\.5 All order cancel](#55-all-order-cancel)
    * [5\.6 Query all current pending orders](#56-query-all-current-pending-orders)
    * [5\.7 Query all orders (including historical orders)](#57-query-all-orders-including-historical-orders)
    * [5\.8 Order Information](#58-order-information)
    * [5\.9 Order transaction details](#59-order-transaction-details)
    * [5\.10 Query historical transaction records](#510-query-historical-transaction-records)
    * [5\.11 Order by strategy](#511-order-by-strategy)
    * [5\.12 Cancel Order by strategy](#512-cancel-order-by-strategy)
    * [5\.13 Order strategy query](#513-order-strategy-query)
    * [5\.14 Modify the order's TP and SL parameters](#514-modify-the-orders-tp-and-sl-parameters)
    * [Parameter description of take profit and stop loss](#parameter-description-of-take-profit-and-stop-loss)
* [6\. Trading activity](#6-trading-activity)
    * [6\.1 Buy ticket](#61-buy-ticket)
* [7\. Public market：Http](#7-public-markethttp)
    * [7\.1 Trading pair](#71-trading-pair)
    * [7\.2 Full depth](#72-full-depth)
    * [7\.3  Candlestick](#73--candlestick)
    * [7\.4 Trade](#74-trade)
    * [7\.5 Ticker](#75-ticker)
    * [7\.6 Latest mark price](#76-latest-mark-price)
    * [7\.7 Latest index price](#77-latest-index-price)
    * [7\.8 Mark price candlestick](#78-mark-price-candlestick)
    * [7\.9 Index price candlestick](#79-index-price-candlestick)
    * [7\.10 Funding rate and next settlement time](#710-funding-rate-and-next-settlement-time)
    * [7\.11 Latest mark price and funding rate](#711-latest-mark-price-and-funding-rate)
    * [7\.12 Query funding rate history](#712-query-funding-rate-history)
    * [7\.13 Query market liquidation orders](#713-query-market-liquidation-orders)
    * [7\.14 Long/Short ratio of large accounts](#714-longshort-ratio-of-large-accounts)
    * [7\.15 Long/Short ratio of large positions](#715-longshort-ratio-of-large-positions)
* [8\. Public market：ws](#8-public-marketws)
    * [8\.1 subscribe](#81-subscribe)
    * [8\.2 unsubscribe](#82-unsubscribe)
    * [8\.3 Full depth](#83-full-depth)
    * [8\.4 Increment depth](#84-increment-depth)
    * [8\.5 Candlestick](#85-candlestick)
    * [8\.6 Trade](#86-trade)
    * [8\.7 Ticker](#87-ticker)
    * [8\.8 All Ticker](#88-all-ticker)
    * [8\.9 Index price and mark price](#89-index-price-and-mark-price)
    * [8\.10 Index price candlestick and mark price candlestick](#810-index-price-candlestick-and-mark-price-candlestick)
    * [8\.11 Funding rate and next settlement time](#811-funding-rate-and-next-settlement-time)
    * [8\.12 ping](#812-ping)
* [9\. User data：ws](#9-user-dataws)
    * [9\.1 Overview](#91-overview)
        * [9\.1\.1 Ping](#911-ping)
    * [9\.2 Login](#92-login)
        * [9\.2\.1 Signature rules](#921-signature-rules)
    * [9\.3 Funds](#93-funds)
        * [9\.3\.1 Assets changes](#931-assets-changes)
        * [9\.3\.2 Fund inquiry](#932-fund-inquiry)
        * [9\.3\.3 Query user bill](#933-query-user-bill)
        * [9\.3\.4 Changes in futures account details](#934-changes-in-futures-account-details)
        * [9\.3\.5 Query the account details of futures](#935-query-the-account-details-of-futures)
    * [9\.4 Position](#94-position)
        * [9\.4\.1 Position changes](#941-position-changes)
        * [9\.4\.2 Position query](#942-position-query)
        * [9\.4\.3 Margin information query](#943-margin-information-query)
        * [9\.4\.4 Withdraw or increase margin](#944-withdraw-or-increase-margin)
        * [9\.4\.5 Position configuration information query](#945-position-configuration-information-query)
        * [9\.4\.6 Position leverage setting](#946-position-leverage-setting)
        * [9\.4\.7 Position mode setting](#947-position-mode-setting)
        * [9\.4\.8 Position margin mode setting](#948-position-margin-mode-setting)
        * [9\.4\.9 View the user’s current position](#949-view-the-users-current-position)
    * [9\.5 Orders and transactions](#95-orders-and-transactions)
        * [9\.5\.1 Order changes](#951-order-changes)
        * [9\.5\.2 Place an order](#952-place-an-order)
        * [9\.5\.3 Query order details](#953-query-order-details)
        * [9\.5\.4 Cancel order](#954-cancel-order)
        * [9\.5\.5 Batch cancel orders](#955-batch-cancel-orders)
        * [9\.5\.6 Cancel all order](#956-cancel-all-order)
        * [9\.5\.7 Query all pending orders (unfilled order list)](#957-query-all-pending-orders-unfilled-order-list)
        * [9\.5\.8 Query all orders](#958-query-all-orders)
        * [9\.5\.9 Query transaction details](#959-query-transaction-details)
        * [9\.5\.10 Query Historical transaction records](#9510-query-historical-transaction-records)
        * [9\.5\.11 Batch order](#9511-batch-order)
* [10\. Error code](#10-error-code)

## 1. Request Rules

### 1.1. Request parameter mode convention

- GET request：All queries use GET and use the request query method to pass parameters, namely key1=value1&key2=value2

- POST request：All operations except query use POST request and use request body to pass parameters. The POST request header needs to be declared as `Content-Type:application/json`

  

### 1.2. Request header parameter

Need to set the following request header information

```json
ZB-APIKEY: 72d41c5f-****-****-****-08b18902fab9

ZB-TIMESTAMP: Time the request was initiated（UTC），example：2021-01-05T14:05:28.616Z

ZB-SIGN: u4ALcTlk946vNin8pmhQsqt2Ky2DdnXKwrXrZYmnDIQ=

ZB-LAN: cn
```

Parameter Description：

- ZB-APIKEY: api key
- ZB-TIMESTAMP: Request time, in ISO format，example`2021-01-05T14:05:28.616Z
- ZB-SIGN：signature
- ZB-LAN: language，support cn(chinese)、en(english)和kr(korean)，the default is cn



### 1.3. Signature rules

#### 1.3.1. ApiKey

The user's api key is generated by the zb platform



#### 1.3.2. Request verification

-The server performs signature verification on the initiated request to confirm the source of the request and the integrity of the data；

- Do not transmit the secretKey in the request or response；

- The request header of ZB-SIGN is obtained by encrypting``timestamp`` + ``method``  + ``requestPath`` + ``request query/request body the string`` (+ means string connection) and SecretKey using the HMAC SHA256 method and outputting it through Base64 encoding.；

  example：`sign=CryptoJS.enc.Base64.Stringify(CryptoJS.HmacSHA256(timestamp + 'GET' + '/users/self/verify', SecretKey))`

  Among them, the value of `timestamp`is the same as the request header of`ZB-TIMESTAMP`in ISO format, such as`2021-01-05T14:05:28.616Z`.

  method is the request method, all uppercase letters：`GET/POST`.

  requestPath is the request interface path.example：`/Server/api/v1/trade/getOrder`

  request query/request Body string: It is sorted according to the ASCII code order, and each parameter is connected with the character "&"

  SecretKey is generated when users apply for APIKey，***<u>Sha encryption required</u>***。example：`ceb892e0-0367-4cc1-88d1-ef9289feb053`，encrypt the SecretKey to get：c9a206b430d6c6a43322a05806acb5f9514ac488
  
  Online encryption tool: http://tool.oschina.net/encrypt?type=2

  

#### 1.3.3. request query/request body parameter ordering

The parameters are sorted according to the ASCII code. For example, the following are the original parameters:

```
symbol=BTC_USDT
orderId=1234567890
```

After sorting, it should be:

```
orderId=1234567890
symbol=BTC_USDT
```

Follow the above sequence to connect each parameter with the character "&"

```
orderId=1234567890&symbol=BTC_USDT
```



#### 1.3.4. Compose the final string to be calculated for signature

For example：Request header ZB-TIMESTAMP: 2021-01-05T14:05:28.616Z，method: GET，Request interface path：/Server/api/v1/trade/getOrder，Then the final string for signature calculation is

```
2021-01-05T14:05:28.616ZGET/Server/api/v1/trade/getOrderorderId=1234567890&symbol=BTC_USDT
```



#### 1.3.5. Time synchronization security

- The signature interface needs to pass the `timestamp` parameter, and its value should be the unix timestamp (milliseconds) of the time the request was sent.

- When the server receives the request, it will judge the timestamp in the request. If it is sent 1 minute ago, the request will be considered invalid. This time window value can be customized by sending the optional parameter `recvWindow`.

- In addition, if the server calculates that the client's timestamp is more than 3 seconds ‘in the future’ of the server’s time, the request will also be rejected.

- Logical pseudo code：

  ```java
  if (timestamp < (serverTime + 3000) && (serverTime - timestamp) <= recvWindow) {
    // process request
  } else {
    // reject request
  }
  ```



#### 1.3.6. Java code example

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
 * Description: Use Hmac SHA256 + base64 to generate signatures and verify signatures
 *
 * @author micheal
 * Date 2020/12/3 4:46 pm
 * Version V1.0
 */
public class HmacSHA256Base64Utils {

    private static final int MAX_FAST_TIME = 3000;                  // The maximum allowable number of milliseconds faster than the server
    private static final int MAX_SLOW_TIME = 1 * 60 * 1000;        // The maximum allowable number of milliseconds slower than the server

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
     * Verify signature
     *
     * @param timestamp     Time
     * @param method        Request method：GET/POST
     * @param requestPath   Request interface path
     * @param params        Request parameter
     * @param apiKey        api key
     * @param secretKey     api secretKey
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
     * Generate signature
     * For timestamp + method + requestPath + request query/request body string (+ Means string concatenation)，And SecretKey, encrypted using the HMAC SHA256 method, and output through Base64 encoding.
     *
     * @param timestamp     Time
     * @param method        Request method：GET/POST
     * @param requestPath   Request interface path
     * @param params        Request params
     * @param apiKey        api key
     * @param secretKey     api secretKey
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
     * Sort by ASCII code
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
    }

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

#### 1.3.7. Python代码示例

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


#### 1.3.8. requestPath

请求接口路径，USDT合约以/usdt开头，QC合约以/qc开头。如：`/usdt/Server/api/v1/trade/getOrder`


### 1.4. Access Limit Frequency Rules

- Rest API
  The default number of requests for a single interface is 100 times/2s

- Websocket API
  The default limit for the number of requests for a single interface is 200 times/2s


## 2. Response rules

**Response parameters**

| Parameter name| Type   | Required | Description                                    |
| -------- | ------ | -------- | --------------------------------------- |
| code     | Int    | Yes       | Result code, 10000 means success, others are error codes |
| desc     | string | No       | Result description                                |
| data     | json   | Yes       | Precise data                                |

**Response example**

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



## 3. Server address

https://fapi.zb.com



## 4. Accounts and transactions

### 4.1 Futures account information

  - URL: /Server/api/v2/Fund/getAccount
  - Interface Type: Http
  - Request type: GET
  - Request parameter:

| Parameter name | Type  | Reqiured | Description                                    |
| -------- | ------ | -------- | --------------------------------------- |
| futuresAccountType     | Int    | No      | Contract type，1: USDT contract |
|convertUnit |String  |No | Converted unit, the page displays the number unit after the "≈" sign，Optional options：cny，usd,usdt,btc,the default is cny    |

  - Response result:

  ```json
    {
      "code": 1,
      "desc": "success",
      "data": {
        "account": {//Account information, including available balance, margin balance, unrealized profit and loss
          "accountBalance": 996.12,
          "allMargin": 1000.13,
          "available": 1002.1,
          "freeze": 2304.1212,
          "allUnrealizedPnl": -123.789,
          "accountNetBalance":"873.12",
          "accountBalanceConvert": 996.12,
          "allMarginConvert": 1000.13,
          "availableConvert": 1002.1,
          "freezeConvert": 2304.1212,
          "allUnrealizedPnlConvert": -123.789,
          "accountNetBalanceConvert":"873.12",
          "convertUnit": "cny",
          "unit": "usdt",
          "percent": "12.12%"
        },   
        "assets": [{//Asset information, including available and frozen
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
  - assets data instruction
  - 
     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |userId |Yes  |Long |User id   |
     |currencyId |Yes  |Long | Currency id    |
     |currencyName |Yes  |String | Currency name    |
     |amount     |Yes  |BigDecimal | Available assets    |
     |freezeAmount     |Yes  |BigDecimal | Freeze Amount    |
     |id     |No  |Long | Fund id    |
     |allMargin     |No  |Long | Account margin    |
     |createTime     |No  |Long | Create time    |
     |modifyTime     |Yes  |Long | Update time    |
     |extend     |Yes  |String | Spare field    |

  - account Data instruction
  - 
     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |accountBalance |Yes  |BigDecimal |Account balance: available + frozen + all position unrealized P&L   |
     |allMargin |Yes  |BigDecimal | Margin for all positions    |
     |available     |Yes  |BigDecimal | Available assets    |
     |freeze     |Yes  |BigDecimal | Frozen amount    |
     |allUnrealizedPnl     |Yes  |BigDecimal | Cumulative unrealized profit and loss of all corresponding positions    |
     |unit     |Yes  |String | Fixed return, if it is usdt-M, it returns usdt, if it is coin-M, it returns btc, if it is a qc contract, it returns qc, the unit of statistical data    |
     |allMarginConvert |Yes  |BigDecimal | All positions margin equivalent    |
     |availableConvert     |Yes  |BigDecimal | Equivalent amount of available assets    |
     |accountBalanceConvert |Yes  |BigDecimal |accountBalanceConvert：availableConvert+freezeConvert   |
     |accountNetBalanceConvert     |Yes  |Long | accountNetBalanceConvert=available+freeze+allUnrealizedPnlConvert    |
     |freezeConvert     |Yes  |BigDecimal | Frozen amount equivalent    |
     |allUnrealizedPnlConvert     |Yes  |BigDecimal | Cumulative unrealized profit and loss for all corresponding positions    |
     |convertUnit     |Yes  |String | Converted unit, the page displays the number unit after the "≈" sign，example：cny，usd,btc    |
     |percent     |Yes  |BigDecimal | unrealized PNL/Margin for all positions*100%    |

### 4.2 All Contract Positions/Single Contract Position(marketId+side filter)
  - URL: /Server/api/v2/Positions/getPositions
  - Interface Type: Http
  - Request type: GET
  - Request parameter: 

     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |marketId |No  |Long | Must choose one of market id and market name    |
     |symbol |No  |String | Must choose one of market id and market name    |
     |side |No  |Integer | 1 Long  0 Short    |
     |futuresAccountType |Yes  |Integer | 1:USDT-M perpetual futures    |
     
  - Response result:
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
                 "positionsMode": 2,
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

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |User id   |
    |marketId |Yes  |Long | Market id    |
    |marketName     |Yes  |String | Market Name    |
    |side     |Yes  |Integer | Position type, two-way open long: 1 two-way open short: 0 one-way position: 2    |
    |leverage     |No  |Integer | Leverage multiple    |
    |amount     |No  |BigDecimal | Number of positions held    |
    |freezeAmount     |Yes  |BigDecimal | Order frozen position quantity    |
    |avgPrice     |Yes  |BigDecimal | Average opening price    |
    |liquidatePrice |Yes  |BigDecimal |Liquidation price   |
    |margin |Yes  |BigDecimal | Margin    |
    |marginMode     |Yes  |Integer | Margin mode：1isolated（default），2Cross    |
    |status     |Yes  |Integer | State: 1 Available、2:locked、3:freeze、4：Not shown    |
    |unrealizedPnl     |No  |BigDecimal | Unrealized PNL    |
    |marginBalance     |Yes  |BigDecimal | Margin balance    |
    |maintainMargin     |Yes  |BigDecimal | Maintenance margin    |
    |marginRate     |Yes  |BigDecimal | Margin rate    |
    |nominalValue     |Yes  |BigDecimal | Nominal value of the position    |
    |liquidateLevel |Yes  |Integer |Liquidation gear, that is, the maintenance margin gear corresponding to the position   |
    |autoLightenRatio     |Yes  |BigDecimal | The ratio of automatic lightening, ranging from 0 to 1. The higher the number, the higher the risk of automatic lightening    |
    |returnRate     |Yes  |BigDecimal | rate of return    |
    |id |Yes  |Long |Position id   |
    |createTime |Yes  |Long | Creat time    |
    |modifyTime     |Yes  |Long | Change time    |
    |extend     |No  |Long | Notes    |
    
     
    
     

### 4.3 Margin information query (the maximum amount of margin increase, the maximum amount of margin withdrawal, and the expected liquidation price)
  - If there is no record, an empty record will not be created
  - URL: /Server/api/v2/Positions/marginInfo
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 

     |Name|required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |positionsId |Yes  |Long | Position Id    |
     |futuresAccountType |Yes  |Integer | 1:USDT-M prepetual futures   |
     
  - Response result:
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

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |maxAdd |Yes  |BigDecimal |Maximum increase margin   |
    |maxSub |Yes  |BigDecimal | Maximum reduce margin    |
    |liquidatePrice     |YEs  |BigDecimal | Estimated liquidation price    |

### 4.4 Margin withdrawal or increase
  - URL: /Server/api/v2/Positions/updateMargin
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter: 
      ```
    {
        "positionsId":6742095107924699136,
        "amount":0.1,
        "futuresAccountType":1,
        "type":0
    }
    
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |positionsId |Yes  |Long | Position id    |
    |amount |Yes  |BigDecimal | Change amount    |
    |type |Yes  |Integer | 1: increase  0：reduce    |
    |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures    |
    
  - Response results:
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
    
     Response parameter description data：
     Refer to Position query interface

### 4.5 Position leverage setting
- URL: /Server/api/v2/setting/setLeverage
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter: 
      ```
    {
        "symbol":"BTC_USDT",
        "leverage":12,
        "futuresAccountType":1
    }
    
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |marketId |No  |Long | Must choose one of market id and market name    |
    |symbol |No  |String | Must choose one of market id and market name    |
    |leverage |Yes  |Integer | Leverage multiple    |
    |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures 2     |
  
  - response result:
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

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |User id   |
    |marketId |Yes  |Long | Market id    |
    |leverage     |Yes  |BigDecimal | Leverage multiple    |
    |marginMode     |Yes  |Integer | Margin mode：1Isolated（default），2Cross    |
    |positionsMode     |No  |Integer | 1:one-way position，2: two-way position    |
    |id     |No  |Long | Position id    |
    |maxAppendAmount |Yes  |BigDecimal |The maximum margin call may be modified, if it is 0, the automatic margin increase will be disabled   |
    |enableAutoAppend |Yes  |Integer | Whether to open automatic margin call 1:Open  0 ：Not open    |
    |marginCoins |Yes  |String | Configured sequentially frozen margin，such us eth,usdt,qc    |
    |createTime     |No  |Long | Create time    |
    |modifyTime     |Yes  |Long | Modify time    |
    |extend     |Yes  |String | Notes    |

### 4.6 Position holding mode setting

- URL: /Server/api/v2/setting/setPositionsMode
    - Interface Type: Http
    - Request Type: POST
    - Request Parameter:
      ```
      {
          "marketId":100,
          "positionsMode":1,
          "futuresAccountType":1
      }
      
      ```

      |Name|Required|Type|Description|
                |:----    |:---|:----- |:-----   |
      |marketId |No  |Long | market id   |
      |symbol |No  |String | Must choose one of market id and market name    |
      |positionsMode |Yes  |Integer | 1:one way，2: two way    |
      |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures  2:QC perpetual futures    |

    - response result :
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
      |userId |Yes  |Long |User id   |
      |marketId |Yes  |Long | Market id    |
      |leverage     |Yes  |BigDecimal | Leverage multiple    |
      |marginMode     |Yes  |Integer | Margin mode：1Isolated（default），2Cross    |
      |positionsMode     |No  |Integer | 1:one-way position，2: two-way position    |
      |id     |No  |Long | Position id    |
      |maxAppendAmount |Yes  |BigDecimal |The maximum margin call may be modified, if it is 0, the automatic margin increase will be disabled   |
      |enableAutoAppend |Yes  |Integer | Whether to open automatic margin call 1:Open  0 ：Not open    |
      |marginCoins |Yes  |String | Configured sequentially frozen margin，such us eth,usdt,qc    |
      |createTime     |No  |Long | Create time    |
      |modifyTime     |Yes  |Long | Modify time    |
      |extend     |Yes  |String | Notes    |



### 4.7 Margin mode setting
- Not yet opened, currently only supports isolated by default

### 4.8 View the user's current position
  - URL: /Server/api/v2/Positions/getNominalValue
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 

     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |marketId |No  |Long | Must choose one of market id and market name    |
     |symbol |No  |String | Must choose one of market id and market name    |
     |side |No  |Integer | Side：1：open long   0 open short    |
     |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures 2 QC perpetual futures  |
   
  - Response results:
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
    
    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |marketId |Yes  |Long | Market id    |
    |side |Yes  |Long | 1:Long 0：Short    |
    |nominalValue |No  |BigDecimal |Notional value of user positions （Return when passing side）  |
    |openOrderNominalValue     |No  |BigDecimal | Nominal value of order position（Return when passing side）    |
    |longNominalValue |No  |BigDecimal |Notional value of user long positions （Return when side is not passed）  |
    |shortNominalValue |No  |BigDecimal |Notional value of user short positions （Return when side is not passed）  |
    |openOrderLongNominalValue     |No  |BigDecimal | Nominal value of order long position （Return when side is not passed）   |
    |openOrderShortNominalValue     |No  |BigDecimal | Nominal value of order short position （Return when side is not passed）   |

### 4.9 Query user bill
  - URL: /Server/api/v2/Fund/getBill
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 

     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |currencyId |No  |Long | Currency id    |
     |currencyName |No  |String | Currency name    |
     |type |No  |Integer |Bill Name   |
     |startTime |No  |Long | Start timestamp    |
     |endTime |No  |Long |End timestamp   |
     |pageNum |No  |Integer | Page    |
     |pageSize |No  |Integer | Number of rows per page, default 10    |
    |isHistory |No  |Integer | 0: query recent 1: query history more     |    
  - |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures  2: QC perpetual futures  |

  - Response result:
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

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |Userid   |
    |freezeId |Yes  |String | Freeze id    |
    |type     |Yes  |BigDecimal | Bill type    |
    |changeAmount     |Yes  |BigDecimal | Change in funds    |
    |feeRate     |No  |BigDecimal | Rate    |
    |fee     |No  |BigDecimal | Handling fee    |
    |operatorId     |No  |Long | Operator id    |
    |beforeAmount     |Yes  |BigDecimal | Account funds before the change    |
    |beforeFreezeAmount     |Yes  |BigDecimal | Freeze funds before the change    |
    |marketId     |No  |Long | Market id   |
    |outsideId     |No  |Long | Outside id    |
    |id     |No  |Long | Bill id    |
    |isIn     |No  |Integer | 1：Increase  0： Reduce    |
    |available     |No  |BigDecimal | Currently available assets    |
    |unit     |No  |String | Currency name, quantity unit    |
    |createTime     |No  |Long | Create timestamp    |
    |modifyTime     |No  |Long | Modify timestamp    |
    |extend     |No  |String | Notes    |

### 4.10 Query bill type information list
  - URL: /Server/api/v2/Fund/getBillTypeList
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 
    none
    
  - Response results:
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
         "desc": "Success"
     }
    ```

    |Name|Required|Type|Instruction|
    |:----    |:---|:----- |:-----   |
    |code |Yes  |Integer |Bill type   |
    |cnDesc |Yes  |String | Chinese description of bill type    |
    |enDesc     |Yes  |String | English description of bill type    |

### 4.11 Isolated Margin change history
- Use location: automatic additional guarantee business, user manual adjustment of the margin

- URL: /Server/api/v2/Fund/marginHistory
    - Interface Type: Http
    - Request Type: GET
    - Request Parameter:
        ```
        
        ```

      |Name|Required|Type|Description|
      |:----    |:---|:----- |:-----   |
      |symbol |No  |String | Market, such as ETH_USDT    |
      |startTime |No  |Long | Millisecond timestamp    |
      |endTime |No  |Long | Millisecond timestamp    |
      |type |No  |Integer | Adjust direction 1: Increase isolated margin，0: Reduce cross margin    |
      |pageNum |No  |Integer | Page number, default 1    |
      |pageSize |No  |Integer | Page size default 10    |

    - Response result: return position object information
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
         "desc": "Success"
       }
      
      ```

      |Name|Required|Type|Description|
      |:----    |:---|:----- |:-----   |
      |symbol |Yes  |String |Market, such as ETH_USDT   |
      |asset |Yes  |String | Margin currency, there may be one or more, such as USDT, ETH    |
      |amount     |Yes  |String | The amount of margin, there may be more than one, such as USDT:121210.00001, ETH:0.0002    |
      |type     |Yes  | | Adjust direction 1: Increase isolated margin，0: Reduce isolated margin   |
      |isAuto     |No  |Integer | Whether it is automatic, default is no 0，1 is yes    |
      |contractType     |No  |Long | Contract type    |
      |positionSide |Yes  |String |Position side:LONG SHORT BOTH   If one-way position is LONG/SHORT   two-way position：BOTH   |
      |createTime |Yes  |Integer | Create time    |




​    

### 4.12 Position configuration information query
- URL: /Server/api/v2/setting/get
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 
      - marketId: Market id

     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |marketId |Yes  |Long | Market id    |
     |symbol |Yes  |String | Market name    |
     |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures  2:QC perpetual futures  |
     
  - Response result:
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

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |User id   |
    |marketId |Yes  |Long | Market id    |
    |leverage     |Yes  |BigDecimal | Leverage multiple    |
    |marginMode     |Yes  |Integer | MarginMode：1isolated （default），2cross    |
    |positionsMode     |No  |Integer | 1:One-way position，2: Two-way position    |
    |id     |No  |Long | Position id    |
    |maxAppendAmount |Yes  |BigDecimal |The maximum margin call may be modified, if it is 0, the automatic margin increase will be disabled   |
    |enableAutoAppend |Yes  |Integer | Whether to open automatic margin call 1: open 0: not open    |
    |marginCoins |Yes  |String | Configured sequentially frozen margin, such as eth, usdt, qc    |
    |createTime     |No  |Long | Create time    |
    |modifyTime     |Yes  |Long | Modify time    |
    |extend     |Yes  |String | Notes    |
    
     
    
     

### 4.13 Query funds through userid, currencyName
  - If there is no record, an empty record will not be created
  - URL: /Server/api/v2/Fund/balance
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter: 

     |Name|Required|Type|Description|
     |:----    |:---|:----- |:-----   |
     |currencyId |No  |String | Currency id    |
     |currencyName |No  |String | Currency name    |
     |futuresAccountType |Yes  |Integer | 1:USDT-M perpetual futures    |
     
  - Response result:
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
        "desc":"Success"
    }
    ```
    
    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |User id   |
    |currencyId |Yes  |Long | Currency id    |
    |currencyName |Yes  |String | Currency name    |
    |amount     |Yes  |BigDecimal | Available assets amount    |
    |allowTransferOutAmount     |Yes  |BigDecimal | allow transfer out amount    |
    |freezeAmount     |Yes  |BigDecimal | Frozen amount    |
    |id     |No  |Long | Fund id    |
    |accountBalance     |No  |BigDecimal | Account Balance    |
    |allUnrealizedPnl     |No  |BigDecimal | All unrealized Pnl    |
    |allMargin     |No  |BigDecimal | Account margin    |
    |createTime     |No  |Long | Create time    |
    
     
    
    

### 4.14 Automatic margin call setting
- URL: /Server/api/v2/Positions/updateAppendUSDValue
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter: 
      ```
    {
        "maxAdditionalUSDValue":1212.12,
        "positionsId":123123123123,
        "futuresAccountType":1
    }
    
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |positionsId |Yes  |Long | Position ID    |
    |maxAdditionalUSDValue |Yes  |BigDecimal | Set the amount of margin to increase, if it is 0, the automatic margin increase will be turned off    |
    |futuresAccountType |Yes  |Integer | 1:USDT perpetual    |
    
  - Response result: return position object information
    ```json
     {
       "code": 10000,
       "data": "6740243890479048704-674024389",
       "desc": "Success"
     }
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |data |Yes  |String |The clientId of this operation is composed of second timestamp + position ID   |

### 4.15 Margin usage sequence setting
- Use position: Order freezing order, opening freezing order, handling fee deduction order, realized loss deduction order, closing position thawing order, increase and decrease margin order

- URL: /Server/api/v2/Positions/setMarginCoins
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter: 
      ```
    {
        "marginCoins":"eth,usdt,qc",
        "symbol":"BTC_USDT",
        "futuresAccountType":1
    }
    
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |symbol |Yes  |String | Market name    |
    |marginCoins |Yes  |String | Set margin sequence    |
    |futuresAccountType |Yes  |Integer | 1:USDT perpetual futures  2:QC perpetual futures  |
    
  - Response result: return position object information
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
       "desc": "Success"
     }
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |userId |Yes  |Long |User id   |
    |marketId |Yes  |Long | Market id    |
    |leverage     |Yes  |BigDecimal | leverage multiple    |
    |marginMode     |Yes  |Integer | Margin mode：1isolated（default），2cross    |
    |positionsMode     |No  |Integer | 1:One-way position，2: Two-way position    |
    |id     |No  |Long | Position id    |
    |maxAppendAmount |Yes  |BigDecimal |The maximum margin call may be modified, if it is 0, the automatic margin increase will be disabled   |
    |enableAutoAppend |Yes  |Integer | Whether to enable automatic margin call 1: Enable 0: Disable    |
    |marginCoins |Yes  |String | Configured sequentially frozen margin, such as eth, usdt, qc    |
    |createTime     |No  |Long | Creat time    |
    |modifyTime     |Yes  |Long | Modify rime    |
    |extend     |Yes  |String | Notes    |

### 4.16 Transfer of funds with zb

- URL: /Server/api/v2/Fund/transferFund
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter: 
      ```
    {
        "currencyName":"USDT",
        "amount":"12.12",
        "clientId"："2sdfsdfsdf232342",
        "side"："1"
    }
    
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |currencyName |Yes  |String | Currency name    |
    |amount |Yes  |BigDecimal | Transfer amount, progress refer to currency information    |
    |clientId |Yes  |String | Unique id, keep idempotence, cannot be empty or length cannot exceed 18    |
    |side |Yes  |Integer | 1：Deposit (zb account -> futures account)，0：Withdrawal (futures account -> zb account)    |
    
  - Response result: return position object information
    ```json
     {
       "code": 10000,
       "data": "2sdfsdfsdf232342",
       "desc": "Success"
     }
    ```

    |Name|Required|Type|Description|
    |:----    |:---|:----- |:-----   |
    |data |Yes  |String |Return idempotent id if the operation is successful, otherwise return null   |





### 4.17 Query the freeze type information list
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



### 4.18 Query frozen list
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






## 5. Futures Trading

### 5.1 Place an order

  - URL: /Server/api/v2/trade/order
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter:

| Name          | Type       | Required | Description                                                         |
| :------------ | :--------- | :------- | :----------------------------------------------------------- |
| symbol        | String     | Yes       | Trading pair, such as: BTC_USDT                                         |
| action        | Integer    | No       | Order price type:  <br/>1   Limit price<br/>11 Best-Bid-Offer<br/>12 Optimal 5<br/>13 Optimal 10 <br/>14 Optimal 20 <br/>19 The best limit file, that is, the best price at the upper or lower limit of the price limit<br/>3   IOC<br/>31 Best-Bid-Offer IOC<br/>32 Optimal 5 IOC<br/>33 Optimal 10 IOC<br/>34 Optimal 20 IOC<br/>39 The optimal limit IOC, that is, the optimal price IOC at the upper or lower limit of the price limit<br/>4   Post only<br/>5   FOK<br/>51 Best-Bid-Offer FOK<br/>52 Optimal 5 FOK<br/>53 Optimal 10 FOK<br/>54 Optimal 20 FOK<br/>59 The best limit file FOK, that is, the best price FOK at the upper or lower limit of the price limit<br/>Default is 1 |
| side          | Integer    | Yes       | Side：<br/>**two-way position**<br/>1 Open long（buy）<br/>2 Open short（sell）<br/>3 Close long（sell）<br />4 Close short（buy) ）<br/>**one-way position**<br/>5 buy<br/>6 sell<br/>0 only close|
| amount        | BigDecimal | Yes       | Number of orders                                                     |
| price         | BigDecimal | No       | The commission price, when it is BBO or the best 5 price (that is, action11, 12, 31, 32, 51 or 52) can be empty, all others are required |
| clientOrderId | String     | No       | The user-defined order number cannot be repeated in the pending order. Must meet the rules `^[a-zA-Z0-9-_]{1,36}$` |
| extend        | Map        | No       | Extended parameters, currently supports the setting of order strategy (stop profit and stop loss) for opening positions, for example："extend":{"orderAlgos":[{"bizType":1,"priceType":1,"triggerPrice":"70000"},{"bizType":2,"priceType":1,"triggerPrice":"40000"}]} |

#### SP/SL Parameter Description				

| Name       | Required | Type    | description                               |
| :----------- | :--- | :------ | :--------------------------------- |
| bizType      | Yes   | Integer | Type，1：SP，2：SL             |
| priceType    | Yes   | Integer | priceType，1：Mark Price，2：Last Price |
| triggerPrice | Yes  | Decimal | Trigger price                           | 

  - Response result:

  ```json
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

Response parameter description data：

| Name    | Required | Type   | description         |
| :-------- | :--- | :----- | :----------- |
| orderId   | Yes   | String | Order id       |
| orderCode | Yes   | String | Custom order number |

### **5.2** Batch order

  - URL: /Server/api/v2/trade/batchOrder

  - Interface Type: Http

  - Request Type: POST

  - Request Parameter:

    Example

  ```json

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

| Name       | Type | Required | description           |
| :--------- | :--- | :------- | :------------- |
| orderDatas | List | Yes       | Order list, array |

  - Response result:

  ```json
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
    "desc": "Success"
}
  ```

Response parameter description data：

| Name      | Type   | Required | description                                 |
| :-------- | :----- | :------- | :----------------------------------- |
| sCode     | Int    | Yes       | The code of the result, 1 means success               |
| sMsg      | String | Yes       | Result description                             |
| orderId   | String | No       | Order ID                               |
| orderCode | String | No       | Custom order ID, if vacant, the system will automatically assign a value.|

### 5.3 Order Cancel

  - URL: /Server/api/v2/trade/cancelOrder
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter:

| Name          | Type   | Required | description                 |
| :------------ | :----- | :------- | :------------------- |
| symbol        | String | Yes       | Trading pair, such as: BTC_USDT |
| orderId       | long   | No       | Order ID               |
| clientOrderId | String | No       | Custom order ID         |

Optional orderId and clientOrderId

  - Response result:

  ```json
{
    "code": 10000,
    "desc": "success",
    "cnDesc": "操作成功",
    "data": "6747737516411133952"
}
  ```

Response parameter description data：

| Name  | Required | Type   | description   |
| :------ | :--- | :----- | :----- |
| orderId | Yes   | String | User id |



### 5.4 Batch order cancel

  - URL: /Server/api/v2/trade/batchCancelOrder

  - Interface Type: Http

  - Request Type: POST

  - Request Parameter:

    Example：

    ```json
    {
      "symbol": "ETH_USDT",
      "orderIds": [6747737380100448256, 6747737516411133952]
    }
    ```

Request parameter description：

| Name           | Type   | Required | description                 |
| :------------- | :----- | :------- | :------------------- |
| symbol         | String | Yes       | Trading pair, such as: BTC_USDT |
| orderIds       | List   | No       | Order ID list           |
| clientOrderIds | List   | No       | Custom order ID list     |

Optional orderIds and clientOrderIds

  - Response result:

If the cancellation fails, the details of the failure will be listed

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

Response parameter description data array element：

| Name  | Required | Type   | description             |
| :------ | :--- | :----- | :--------------- |
| orderId | Yes   | String | The id of the order that failed to cancel |

### 5.5 All order cancel

  - URL: /Server/api/v2/trade/cancelAllOrders
  - Interface Type: Http
  - Request Type: POST
  - Request Parameter:

| Name   | Type   | Required | description                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | Yes       | Trading pair, such as: BTC_USDT |

  - Response result:

  ```json
{
    "code": 10000,
    "data": [ ],
    "desc": "success"
}
  ```

 If there is data in the data, it means that there are orders that have failed to delete. For the specific data format, refer to ``Batch Cancellation Interface''

### 5.6 Query all current pending orders

  - URL: /Server/api/v2/trade/getUndoneOrders
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter:

| Name     | Type   | Required | Description                                                         |
| :------- | :----- | :------- | :----------------------------------------------------------- |
| symbol   | String | Yes       | Trading pair, such as: BTC_USDT                                         |
| type     | No     | Integer  | Type: -1 sell, 1 buy， 0 or empty to query all                          |
| side     | No     | Integer  | Direction:<br/>**Two-way position**<br/>1 Open long (buy)<br/>2 Open short (sell)<br/>3 Close long (sell)<br/>4 Close Short (Buy)<br/>**One-Way Position**<br/>5 Buy<br/>6 Sell<br/>0 Close Only |
| action   | No     | Integer  | Order price type， 0 or empty to query all  <br/>1   Limit price<br/>11 BBO<br/>12 Optimal 5<br/>3   IOC<br/>31 BBO IOC<br/>32  optimal 5 IOC<br/>4   Only Maker<br/>5   FOK<br/>51 BBO FOK<br/>52 optimal 5 FOK |
| pageNum  | INT    | NO       | Page number, starting from 1, the default is 1                                      |
| pageSize | INT    | No       | The number of result sets returned by pagination, the maximum is 100, if you don’t fill in, 30 will be returned by default            |

  - Response result:

  ```json
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

Response parameter description data

| Name           | Required | Type       | Description                                                         |
| :--------------- | :--- | :--------- | :----------------------------------------------------------- |
| id               | Yes   | String     | Order id                                                       |
| orderCode        | Yes   | String     | Custom order ID                                                 |
| marketId         | Yes   | Long       | Market id                                                       |
| price            | Yes   | Decimal    | Order price                                                     |
| amount           | Yes   | Decimal    | Order amount                                                     |
| value            | No   | Decimal    | Order value, namely Order price * Order quantity                              |
| availableAmount  | No   | Decimal    | available order Amount                                                 |
| availableValue   | Yes   | Decimal    | Available order value                                                 |
| tradeAmount      | Yes   | Decimal    | Completed volume, It will increase every time a transaction is made                                 |
| tradeValue       | Yes   | Decimal    | Completed value,  It will increase every time the transaction is completed                               |
| type             | Yes   | Integer    | Order type: -1 sell, 1 buy                                        |
| action           | Yes   | Integer    | Order price type:  <br/>1   Limit price<br/>11 BBO<br/>12 Optimal 5<br/>13 Optimal 10<br/>14 Optimal 20<br/>19 The optimal limit file, that is, the optimal price at the upper or lower limit of the price limit<br/>3   IOC<br/>31 BBO IOC<br/>32 Optimal 5 IOC<br/>33 Optimal 10 IOC<br/>34 Optimal 20 IOC<br/>39 The optimal limit IOC, that is, the optimal price IOC at the upper or lower limit of the price limit<br/>4   Post only<br/>5   FOK<br/>51 BBO FOK<br/>52 Optimal 5 FOK<br/>53 optimal 10 FOK<br/>54 optimal 20 FOK<br/>59 The optimal limit file FOK, that is, the optimal price FOK at the upper or lower limit of the price limit |
| showStatus       | Yes   | Integer    | state: 1:Unexecuted、2:Partial executed（The order is still pending）、3:executed、4：Canceling、5:All cancel 、6：Cancel failed、7：Partial cancel（The order has been completed, part of the transaction） |
| entrustType      | Yes   | Integer    | Order type： <br/>1Limit Order <br/>2Force deleveraging <br/>3Force liquidation <br/>4Trigger Order <br/>5SP <br/>6SL <br/>7Force liquidation（having not over loss） <br/>8Force liquidation（Venture fund）<br/>9Force liquidation（ADL） |
| side             | Yes   | Integer    | Direction:<br/>**Two-way position**<br/>1 Open long (buy)<br/>2 Open short (sell)<br/>3 Close long (sell)<br/>4 Close short (buy)<br/>**One-way position**<br/>5 Buy<br/>6 Sell<br/>7 Only reduce position and close long<br/>8 Only reduce position and close short |
| sourceType       | Yes   | Integer    | source：<br/>1:WEB<br/>2:Android<br/>3:iOS<br/>4:Rest API<br/>5:WebSocket API<br/>6:System<br/>7:Plan Entrust(Trigger Order )<br/>8:Take Profit(TP/SL)<br/>9:Take Profit(TP) |
| leverage         | Yes   | Integer    | Leverage multiple                                                     |
| avgPrice         | Yes   | BigDecimal | Average transaction price                                                     |
| canCancel        | Yes   | Boolean    | Can it be cancelled                                                     |
| createTime       | Yes   | Long       | Order time, timestamp                                            |
| margin           | Yes   | Decimal    | Margin                                                       |
| **orderAlgos[]** |      |            |                                                              |
| bizType          | Yes   | Integer    | Type，1：TP，2：SL                                       |
| priceType        | Yes   | Integer    | Price type，1：Mark price，2：Last price                           |
| triggerPrice     | Yes   | Decimal    | Trigger price                                                     |
| status           | Yes   | Integer    | state，0：Not active，1：In force                                 |
| lastTradePrice   | 否   | Integer    | last Trade Price                                             |
| lastTradeAmount  | 否   | Integer    | last Trade Amount                                             |
| lastTradeId      | 否   | Integer    | last TradeId                                          |
| lastTradeTime    | 否   | Integer    | last Trade Time                                   |



### 5.7 Query all orders (including historical orders)

  - URL:  /Server/api/v2/trade/getAllOrders
  - Please note that if the order meets the following conditions, it will not be queried：
    - The final status of the order is `Cancelled` , **and** 
    - There is no transaction record for the order
  - Interface Type: Http
  - Request Type: GET
  - 
  - Request Parameter:

| Name      | Type   | Required | Description                                                         |
| :-------- | :----- | :------- | :----------------------------------------------------------- |
| symbol    | String | Yes       | Trading pair, such as: BTC_USDT                                         |
| type      | No     | Integer  | Type: -1 sell, 1 buy， 0 or empty to query all                          |
| side      | No     | Integer  | Side， 0 or empty to query all<br/>1Open long（buy）<br/>2Open short（sell）<br/>3Open long（sell）<br/>4Open short（buy） |
| dateRange | No     | Integer  | Query type<br/>0 Last order, default value<br/>1 More order               |
| action    | No     | Integer  | Order price type， 0 or empty to query all  <br/>1   Limit price<br/>11 BBO<br/>12 Optimal 5<br/>3   IOC<br/>31 BBO IOC<br/>32 Optimal 5 IOC<br/>4   Only Maker<br/>5   FOK<br/>51 BBO FOK<br/>52 Optimal 5 FOK |
| startTime | LONG   | No       | Start time                                                     |
| endTime   | LONG   | No       | End Time                                                     |
| pageNum   | INT    | No       | Page number, starting from 1, the default is 1                                       |
| pageSize  | INT    | No       | The number of result sets returned by pagination, the maximum is 100, if you don’t fill in, 30 will be returned by default            |

  - Response result:

  ```json
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

Response parameter description, refer to``5.6 Query all current pending orders``

### 5.8 Order Information

  - URL: /Server/api/v2/trade/getOrder
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter:

| Name          | Type   | Required | Description                 |
| :------------ | :----- | :------- | :------------------- |
| symbol        | String | Yes       | Trading pair, such as: BTC_USDT |
| orderId       | long   | No       | Order ID               |
| clientOrderId | String | No       | Custom order ID         |

Optional orderId and clientOrderId

  - Response result:

  ```json
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

Response parameter description, refer to``Query all current pending orders``



### 5.9 Order transaction details

  - URL: /Server/api/v2/trade/getTradeList
  - Interface Type: Http
  - Request Type: GET
  - Request Parameter:

| Name     | Type   | Required | Description                                    |
| :------- | :----- | :------- | :-------------------------------------- |
| symbol   | String | Yes       | Trading pair, such as: BTC_USDT                    |
| orderId  | long   | Yes       | Order ID                                  |
| pageNum  | int    | No       | Pagination page number, default is 1 if you don’t fill in                     |
| pageSize | int    | No       | The number of result sets returned by pagination, if not filled in, the default is 10, and the maximum is 100 |

  - Response result:

  ```json
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
    "desc": "Success"
}
  ```

Response parameter description data：

| Name      | Required | Type    | Description                                                         |
| :---------- | :--- | :------ | :----------------------------------------------------------- |
| orderId     | Yes   | Long    | Order id                                                       |
| price       | Yes   | Decimal | Transaction Price                                                     |
| amount      | Yes   | Decimal | Transaction amount                                                     |
| feeAmount   | Yes   | Decimal | Trading Fees                                                       |
| feeCurrency | Yes   | String  | Fee Currency                                                   |
| relizedPnl  | Yes   | Decimal | Relized Pnl                                                   |
| side        | Yes   | Integer | Side：1Open long（buy），2Open short（sell），3Close long（sell），4Close short（buy） |
| maker       | Yes   | Boolean | Whether maker, otherwise taker                                        |
| createTime  | Yes   | Long    | Transaction timestamp                                                   |



### 5.10 Query historical transaction records

- URL: /Server/api/v2/trade/tradeHistory

- Interface Type: Http

- Request Type: GET

- Request Parameter:

  Request parameter description body：

  | Name    | Required | Type    | Description                                                         |
  | :-------- | :--- | :------ | :----------------------------------------------------------- |
  | symbol    | Yes   | String  | Contract, the unique identifier of the market transaction pair, such as: BTC_USDT                   |
  | side      | No   | Integer | Side：<br/>1 Open long（buy）<br/>2 Open short（sell）<br/>3 Close long（sell）<br/>4 Close short（buy） |
  | dateRange | No   | Integer | Query type<br/>0 Recently order, default value<br/>1 More order               |
  | startTime | No   | Long    | Start time, millisecond format of Unix timestamp, such as `1608862284859`         |
  | endTime   | No   | Long    | End time, millisecond format of Unix timestamp, such as `1608862284859`         |
  | pageNum   | Yes   | Integer | Page number, starting from 1                                                |
  | pageSize  | Yes   | Integer | The number of result sets returned by pagination, if not filled in, the default is 10, and the maximum is 100                      |
  
  - Response result:
  
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
  
    Response parameter description data Same as the previous interface ``Order transaction details''



### 5.11 Order by strategy

- Description: Use different entrustment strategies to place orders

- URL: /Server/api/v2/trade/orderAlgo

  - Interface Type: Http

  - Request Type: POST

  - Request Parameter:

    **Request parameter（Universal）**

    | Name    | Required | Type    | Instruction                                                         |
    | :-------- | :--- | :------ | :----------------------------------------------------------- |
    | symbol    | Yes   | String  | Contract, the unique identifier of the market transaction pair, such as: BTC_USDT                   |
    | side      | Yes   | Integer | Direction:<br/>**Two-way position**<br/>1 Open long (buy)<br/>2 Open short (sell)<br/>3 Close long (sell)<br/>4 Close Short (Buy)<br/>**One-Way Position**<br/>5 Buy<br/>6 Sell<br/>0 Close Only |
    | orderType | Yes   | Integer | `1`：Trigger Order<br/>`2`：TP/SL                              |
    | amount    | Yes   | Decimal | Amount                                                         |



  ** Trigger Order Parameter**

| Name       | Required | Type    | Description                           |
| :----------- | :--- | :------ | :----------------------------- |
| triggerPrice | Yes   | Decimal | Trigger price, fill in the value 0\<X\<=1000000 |
| algoPrice    | Yes   | Decimal | Order price, fill in the value0\<X\<=1000000 |

​		**SP/SL parameters**

| Name       | Required | Type    | Description                           |
| :----------- | :--- | :------ | :----------------------------- |
| triggerPrice | Yes   | Decimal | Trigger price, fill in the value0\<X\<=1000000 |
| priceType    | Yes   | Integer | `1`:Mark price<br/>`2`:Last price  |
| algoPrice    | Yes   | Decimal | Order price, fill in the value0\<X\<=1000000 |
| bizType      | Yes   | Integer | `1`:TP<br/>`2`:SL          |

​			

  - Response result:

    ```json
    {
        "code": 10000, 
        "data": "6819520763146739712", 
        "desc": "Success"
    }
    ```

 Response parameter description data：

| Name | Required | Type   | Description       |
| :----- | :--- | :----- | :--------- |
| algoId | Yes   | String | Delegation strategy id |



### 5.12 Cancel Order by strategy		

- Description: Cancel plan orders and stop-profit and stop-loss orders

- URL: /Server/api/v2/trade/cancelAlgos

  - Interface Type: Http

  - Request Type: POST

  - Request example
T
    Single cancellation：`POST /Server/app/v1/trade/cancelAlgos{"symbol":"BTC_USDT", "ids":[6819506476072247296]}`

    Batch cancellation：`POST /Server/app/v1/trade/cancelAlgos{"symbol":"BTC_USDT","ids":[6819506476072247296,6819506476072247297]}`

  - Request parameter:

  | Name | Required | Type         | Description                                                         |
  | :----- | :--- | :----------- | :----------------------------------------------------------- |
  | symbol | Yes   | String       | Contract, the unique identifier of the market transaction pair, such as: BTC_USDT                   |
  | ids    | No   | List<String> | Cancel the specified order ID                                           |
  | side   | No   | Integer      | Direction:<br/>**Two-way position**<br/>1 Open long (buy)<br/>2 Open short (sell)<br/>3 Close long (sell)<br/>4 Close Short (Buy)<br/>**One-Way Position**<br/>5 Buy<br/>6 Sell<br/>0 Close Only |

  Priority is given to cancellation based on ids, if both ids and side are empty, all entrusted strategies in the market will be cancelled

  ​									

- Response result:

If the cancellation fails, the details of the failure will be listed

```json
# Cancel success
{
    "code": 10000, 
    "data": [ ], 
    "desc": "Success"
}

# Cancel fail
{
    "code": 10000, 
    "data": [
        {
            "code": 12201, 
            "data": "6819506476072247296", 
            "desc": "The Order strategy does not exist"
        }
    ], 
    "desc": "Success"
}
```

 ###Response parameter description data array element：

| Name      | Required | Type   | Description                 |
| :---------- | :--- | :----- | :------------------- |
| orderAlgoId | Yes   | String | Cancel the failed delegation strategy id |



### 5.13 Order strategy query

- URL: /Server/api/v2/trade/getOrderAlgos

  - Interface Type: Http

  - Request Type: GET

  - Request Parameter:
TP
    ###Request parameter description body：

    | Name    | Required | Type    |Description                                                         |
    | :-------- | :--- | :------ | :----------------------------------------------------------- |
    | symbol    | Yes   | String  | unique identifier of the market transaction pair, such as: BTC_USDT                   |
    | side      | No   | Integer | 方向：<br/>**双向持仓**<br/>1 开多（买入）<br/>2 开空（卖出）<br/>3 平多（卖出）<br/>4 平空（买入）<br/>**单向持仓**<br/>5 买入<br/>6 卖出<br/>0 仅平仓 |
    | orderType | Yes   | Integer | `1`：Plan order<br/>`2`：SP/SL                              |
    | bizType   | No   | Integer | For Plan order<br/>`1`:TP<br/>`2`:SL                       |
    | status    | No   | Integer | **For plan order**<br/>`1`:Waiting for order<br/>`2`:Cancelled<br/>`3`:Triggered<br/>`4`:Order failed<br/>`5`completed<br/>**For SP/SL**<br/>`1`:Not triggered<br/>`2`:Cancelled<br/>`3`:Trigger succeeded<br/>`4`:Trigger failed<br/>`5`completed |
    | startTime | No   | Long    | Start time                                                     |
    | endTime   | No   | Long    | End time                                                     |
    | pageNum   | Yes   | Integer | page Number，starting from 1                                                |
    | pageSize  | Yes   | Integer | Page size, default 10                                                 |

  - Response result:

    ```json
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
        "desc": "success"
    }
    ```

  

  - Response parameter description

| Parameter | Required | Type                              | Description     |
| :----- | :--- | :--------------------------------------- | :------- |
| data   | yes   | Page{pageNum, pageSize, list<OrderAlgo>} | Order strategy |

**Order strategy``OrderAlgo``**

| Parameter       | Required | Type     | Description                                                         |
| :----------- | :--- | :------ | :----------------------------------------------------------- |
| id           | yes   | Long    | Id                                                       |
| marketId     | yes   | Long    | market Id                                                       |
| triggerPrice | yes   | Decimal | trigger price                                                     |
| algoPrice    | yes   | Decimal | price                                                    |
| amount       | yes   | Decimal | amount                                                     |
| side         | yes   | Integer | Direction:<br/>**Two-way position**<br/>1 Open long (buy)<br/>2 Open short (sell)<br/>3 Close long (sell)<br/>4 Close Short (Buy)<br/>**One-Way Position**<br/>5 Buy<br/>6 Sell<br/>0 Close Only |
| orderType    | yes   | Integer | `1`：plan order<br/>`2`：TP/SL                              |
| priceType    | yes   | Integer | `1`:mark price<br/>`2`:last price                                |
| algoPrice    | yes   | Decimal | price，fill in the amount0\<X\<=1000000                               |
| bizType      | yes   | Integer | `1`:take profit<br/>`2`:stop loss                                        |
| leverage     | yes   | Integer | leverage                                                     |
| sourceType   | yes   | Integer | source：<br/>1:WEB<br/>2:Android<br/>3:iOS<br/>4:Rest API<br/>5:WebSocket API<br/>6:System<br/>7:Plan Entrust(plan order)<br/>8:Take Profit(TP/)<br/>9:Take Profit(stop loss) |
| canCancel    | yes   | Boolean | Can it be cancelled?                                                     |
| triggerTime  | no   | Long    | trigger time, timestamp                                             |
| tradedAmount | no   | Decimal | filled amount                                                   |
| errorDesc    | no   | String  | error message when placing an order after triggering                                   |
| createTime   | yes   | Long    | Create time，Timestamp                                             |
| status       | yes   | Integer | **for plan order**<br/>`1`:waiting for order <br/>`2`:canceled<br/>`3`:ordered<br/>`4`:order failed <br/>`5`:filled<br/>**for TP/SL  **<br/>`1`:untriggered<br/>`2`:canceled<br/>`3`:triggered successfully<br/>`4`:trigger failed<br/>`5`:filled |



### 5.14 Modify the order's TP and SL parameters

  - URL: /Server/api/v2/trade/updateOrderAlgo

  - Interface Type: Http

  - Request type: POST

  - Request parameter:

    | Parameter     | Required | Type   | Description                                                         |
    | :--------- | :--- | :----- | :----------------------------------------------------------- |
    | symbol     | yes   | String | Futures, that is, the unique identifier of the market trading pair, such as:：BTC_USDT                   |
    | orderId    | yes   | Long   | order number                                                       |
    | orderAlgos | yes   | List   | Take profit and stop loss parameters, such as:"orderAlgos":[{"bizType":1,"priceType":1,"triggerPrice":"70000"},{"bizType":2,"priceType":1,"triggerPrice":"40000"}] |

    ### Parameter description of take profit and stop loss				

    |Parameter       | Required | Type     | Description                               |
    | :----------- | :--- | :------ | :--------------------------------- |
    | bizType      | yes   | Integer | Type, 1: Take Profit, 2: Stop Loss             |
    | priceType    | yes   | Integer | Price type, 1: mark price, 2: last price |
    | triggerPrice | yes   | Decimal | Trigger price                           |

  - Response result:

    ```json
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
        "desc": "Success"
    }
    ```

 Response parameter description data, refer to ``Query all current pending orders`` 



## 6. Trading activity

Please add the following parameters in the header for interfaces related to trading activities

```
subAccount: {periodId: period id(activityPeriodId)}
For example：subAccount: "{\"periodId\": 1}"
```



### 6.1 Buy ticket

  - /Server/api/v2/activity/buyTicket

  - Interface Type: Http

  - Request type: POST

  - Request parameter:

    | Parameter | Required | Type    | Description                                         |
    | :----- | :--- | :------ | :------------------------------------------- |
    | activityPeriodId | yes   | Integer  | | Participation period id

  - Response result:

    ```json
    {
        "code": 10000,
        "desc": "success"
    }
    ```





## 7. Public market：Http

USDT futures：https://fapi.zb.com
QC futures：https://fapi.zb.com/qc

### 7.1 Trading pair
  - URL: /Server/api/v2/config/marketList
  - Interface Type: Http
  - Request type: GET
  - Request parameter: 

    | Parameter         | Type    | Required | Description      |
    | :---------- | :----- | :--- | :------ |
    | futuresAccountType | Integer | no    | Futures type, 1: USDT futures (default) |

  - Response result:

       ```json
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
    
    | Name         | Type     | Example | Description      |
    | :---------- | :----- | :--- | :------ |
    | id | Long |     | market ID |
    | marketName | String |     | market name |
    | symbol | String |     | uniquely identifies |
    | buyerCurrencyId | Long |     | buyer currency ID |
    | buyerCurrencyName | String |     | buyer currency name |
    | sellerCurrencyId | Long |     | seller currency ID |
    | sellerCurrencyName | String |     | seller currency name |
    | marginCurrencyId | Long |     | margin currency ID |
    | marginCurrencyName | String |     | margin currency |
    | amountDecimal | Integer |     | quantity accuracy |
    | priceDecimal | Integer |     | price accuracy |
    | feeDecimal | Integer |     | fee accuracy |
    | marginDecimal | Integer |     | margin accuracy |
    | minAmount | BigDecimal |     | minimum order amount |
    | maxAmount | BigDecimal |     | maximum order amount |
    | minTradeMoney | BigDecimal |     | minimum transaction amount |
    | maxTradeMoney | BigDecimal |     | mMaximum transaction amount |
    | minFundingRate | BigDecimal |     | minimum funding rate |
    | maxFundingRate | BigDecimal |     | maximum funding rate |
    | maxLeverage | Integer |     | maximum leverage |
    | riskWarnRatio | BigDecimal |     | risk reminder ratio |
    | defaultFeeRate | BigDecimal |     | default funding rate |
    | contractType | Integer |     | Futures type, 1: USDT futures (default) |
    | duration | Integer |     | Contract duration，<br/>1:Perpetual futures contract (default），<br/>2:Settlement contract-Weekly，<br/>3:Settlement contract-Bi-weekly，<br/>4:Settlement contract-Quarterly，<br/>5:Settlement contract-Bi-quarterly |
    | status | Integer |     | Status: 1: work, 0: stop (default) |
    | createTime | Long |     | Created time |
    | enableTime | Long |     | Opening time |
    | defaultLeverage | Integer |     | Default leverage |
    | defaultMarginMode | Integer |     | Default margin mode，<br/>1:isolated（default），<br/>2:cross |
    | defaultPositionsMode | Integer |     | Default position mode，<br/>1:one-way mode，<br/>2:hedge positions（in default） |
    | markPriceLimitRate | BigDecimal | 0.1 |  Order mark price limit range, 0.1 means 10%|
    | marketPriceLimitRate | BigDecimal | 0.1 | Order market price limit range, 0.1 means 10% |
    
    

### 7.2 Full depth

  - URL: /api/public/v1/depth

  - Interface Type: Http

  - Request type: GET 

  - Description: Get full depth data

  - Request parameter:

    | Parameter   | Type    | Required | Description                 |
    | :----- | :------ | :------- | :------------------- |
    | symbol | String  | yes       | Trading pairs, such as：BTC_USDT |
    | size   | Integer | no       | Number                  |
    | scale  | Integer | no       | Accuracy                 |

    The maximum size is 200, and the default value is 5

  - Response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data":{
          "asks":[					 //sell order
            [
              16146.91,				//price
              0.029267				//amount
            ],
            [
              16146.93,
              0.129334
            ]
          ],
          "bids":[							//buy order
            [
              16131.41,
              8.866436
            ],
            [
              16131.36,
              8.85
            ]
          ],
          "time":  1630657743231  //current server time
    	}
    }
    ```

### 7.3  Candlestick

  - URL: /api/public/v1/kCline
  - Interface Type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   | type    | Required | Description                      |
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | yes       | Trading pairs, such as：BTC_USDT      |
| period | String  | yes       | Candlestick at different times, such as：1M，5M |
| size   | Integer | no       |                           |

Optional range of period: 1M, 5M, 15M, 30M, 1H, 6H, 1D, 5D. M: minutes, H: hours, D: days.

The maximum size is 1440, and the default value is 1

  - Response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data": [
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1160.79137966,	//amount
          1605265200	//time
      	],
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1160.79137966,	//amount
          1605266100	//time
      	]
      ]
    } 
    ```

### 

### 7.4 Trade

  - URL: /api/public/v1/trade

  - Interface Type: Http

  - Request type: GET 

  - Request parameter:

    | Parameter   | Type    | Required | Description                 |
    | :----- | :------ | :------- | :------------------- |
    | symbol | String  | yes       | trading pairs，such as：BTC_USDT |
    | size   | Integer | no       | amount                 |

   The maximum size is 100, and the default value is 50

  - Response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data": [
    		[
    			16131.3,		//price
    			0.03749,		//amount
    			-1,					//sell
    			1605266072	//time
    		],
    		[
    			16130.01,		//price
    			0.2,				//amount
    			1,					/buy
    			1605266073	//time
    		]      
    	]
    }
    ```

### 7.5 Ticker

  - URL: /api/public/v1/ticker

  - Interface Type: Http

  - Request type: GET 

  - Request parameter:

    | Parameter   | Type   | Required |       Description           |
    | :----- | :----- | :------- | :------------------- |
    | symbol | String |yes       | trading pairs，such as：BTC_USDT |

  - Response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data": {
          "BTC_USDT":[
            16100.9,		//opening price
            16133.2,		//highest price
            16100.1,		//lowest price
            16132.3,		//latest transaction price
            1000,		    //volume (last 24 hours)
            0.19502,		//24H change
            1605266072,	//time
            104190.4595	//latest transaction price in RMB
          ],
          "BCH_USDT":[
            16100.9,		//opening price
            16133.2,		//highest price
            16100.1,		//lowest price
            16132.3,		//latest transaction price
            1000,		    //volume (last 24 hours)
            0.19502,		//24H change
            1605266072,	//time
            104190.4595	//latest transaction price in RMB
          ]
      }
    }
    ```

### 7.6 Latest mark price

  - URL: /api/public/v1/markPrice
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter  | Type   | Required |    Description                |
| :----- | :----- | :------- | :------------------- |
| symbol | String | no       | trading pairs，such as：BTC_USDT |

  - response result:

    ```json
    {
        "code":10000,
        "desc":"success",
        "data":{
            "EOS_USDT":"10.71673333",
            "BCH_USDT":"1253.45415974",
            "ETH_USDT":"3926.06",
            "BTC_USDT":"48962.19",
            "LTC_USDT":"316.383"
        }
    }
    ```

### 7.7 Latest index price

  - URL: /api/public/v1/indexPrice
  - Interface Type: Http
  -Request type: GET 

  - Request parameter:

| Parameter   | Type   | Whether it must | Description                 |
| :----- | :----- | :------- | :------------------- |
| symbol | String | no       | trading pairs，such as：BTC_USDT |

  - response result:

    ```json
    {
        "code":10000,
        "desc":"success",
        "data":{
            "EOS_USDT":"10.71673333",
            "BCH_USDT":"1253.45415974",
            "ETH_USDT":"3926.06",
            "BTC_USDT":"48962.19",
            "LTC_USDT":"316.383"
        }
    }
    ```

### 7.8 Mark price candlestick

  - URL: /api/public/v1/markKline
  - Interface Type: Http
  - Request type: GET 

  -  Request parameter:

| Parameter   | Type   | Required | Description                           |
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | yes       | trading pairs, such as：BTC_USDT      |
| period | String  | yes       | candlestick at different time，such as: 1M，5M |
| size   | Integer | no       |                           |

Optional range of period: :1M,5M,15M, 30M, 1H, 6H, 1D, 5D。M: minutes, H: hours, D: days.


The maximum size is 1440, and the default value is 1

  - response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data": [
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1605265200	//time
      	],
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1605266100	//time
      	]
      ]
    } 
    ```

###  7.9 Index price candlestick

  - URL: /api/public/v1/indexKline
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter         | Type    | Required | Description    
| :----- | :------ | :------- | :------------------------ |
| symbol | String  | yes       | trading pairs, such as：BTC_USDT      |
| period | String  | yes       | candlestick at different time，such as: 1M，5M |
| size   | Integer | no       |                           |

Optional range of period: 1M,5M,15M, 30M, 1H, 6H, 1D, 5D. M: minutes, H: hours, D: days.

The maximum size is 1440, default value is 1

  - response result:

    ```json
    {
        "code": 10000,
        "desc": "success",
        "data": [
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1605265200	//time
      	],
        [
          16199,			//open
          16212.3,		//high
          16087.42,		//low
          16131.4,		//close
          1605266100	//time
      	]
      ]
    } 
    ```



### 7.10 Funding rate and next settlement time

  - URL: /api/public/v1/fundingRate
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |Type  | Required | Description                   |
| :----- | :----- | :------- | :------------------- |
| symbol | String | yes       | traing pairs, such as：BTC_USDT |

  - response result:

    ```json
    {
        "code":10000,
        "desc":"success",
        "data":{
            "fundingRate":-0.297589,	//fuding fee
            "nextCalculateTime":"2021-01-15 00:00:00"	//next settlement time
        }
    }
    ```



### 7.11 Latest mark price and funding rate

  - URL: /Server/api/v2/premiumIndex
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :----- | :----- | :------- | :------------------- |
| symbol | String | no       | traing pairs, such as：BTC_USDT |

   - response result:

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
        "desc":"success"
    }
    ```



### 7.12 Query funding rate history

  - URL: /Server/api/v2/fundingRate
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :----- | :----- | :------- | :------------------- |
| symbol | String | no       | traing pairs, such as：BTC_USDT |
| startTime | Long | no       | start time |
| endTime | Long | no       | end time, current time by default |
| limit | String | no       | The number of data items calculated backwards from end time, default value: 100, maximum value: 1000 |

  - response result:

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
        "desc":"success"
    }
    ```



### 7.13 Query market liquidation orders

  - URL: /Server/api/v2/allForceOrders
 - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :----- | :----- | :------- | :------------------- |
| symbol | String | no       | traing pairs, such as：BTC_USDT |
| startTime | Long | no       | start time |
| endTime | Long | no       | end time, current time by default  |
| limit | String | no       | The number of data items calculated backwards from end time, default value: 100, maximum value: 1000 |

  - response result:

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
                "side":"close short",
                "status":"filled",
                "time":"1611304581850"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1237.2",
                "amount":"60.028",
                "tradeAmount":"0",
                "tradeAvgPrice":"0",
                "side":"close short",
                "status":"completely canceled",
                "time":"1611373325930"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1237.2",
                "amount":"60.028",
                "tradeAmount":"0",
                "tradeAvgPrice":"0",
                "side":"close short",
                "status":"completely canceled",
                "time":"1611373326366"
            },
            {
                "symbol":"ETH_USDT",
                "price":"711.38",
                "amount":"59.377",
                "tradeAvgPrice":"0",
                "side":"close long",
                "status":"unknown status",
                "time":"1611650013343"
            },
            {
                "symbol":"ETH_USDT",
                "price":"893.01",
                "amount":"20.142",
                "tradeAvgPrice":"0",
                "side":"close long",
                "status":"unknown status",
                "time":"1611650013384"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1151.54",
                "amount":"151.518",
                "tradeAvgPrice":"0",
                "side":"close long",
                "status":"unknown status",
                "time":"1611650013394"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1302.98",
                "amount":"11.767",
                "tradeAmount":"11.767",
                "tradeAvgPrice":"1302.98",
                "side":"close short",
                "status":"filled",
                "time":"1611813611693"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1302.98",
                "amount":"11.767",
                "tradeAmount":"0",
                "tradeAvgPrice":"0",
                "side":"close short",
                "status":"filled",
                "time":"1611828091110"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1339.44",
                "amount":"59.384",
                "tradeAmount":"53.245",
                "tradeAvgPrice":"1312.16",
                "side":"close short",
                "status":"completely canceled",
                "time":"1611842353847"
            },
            {
                "symbol":"ETH_USDT",
                "price":"1339.44",
                "amount":"6.156",
                "tradeAmount":"0",
                "tradeAvgPrice":"0",
                "side":"close short",
                "status":"completely canceled",
                "time":"1611842356831"
            }
        ],
        "desc":"success"
    }
    ```



### 7.14 Long/Short ratio of large accounts

  - URL: /Server/api/v2/data/topLongShortAccountRatio
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :----- | :----- | :------- | :------------------- |
| symbol | String | yes       | trading pairs, such as：BTC_USDT |
| period | String | yes       | period, such as："5m","15m","30m","1h","2h","4h","6h","12h","1d" |
| startTime | Long | no       | start time |
| endTime | Long | no       | end time, current time by default |
| limit | String | no      | The number of data items calculated backwards from end time, default value: 30, maximum value: 500 |

  - response result:

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
        "desc":"success"
    }
    ```



### 7.15 Long/Short ratio of large positions

  - URL: /Server/api/v2/data/topLongShortPositionRatio
  - Interface type: Http
  - Request type: GET 

  - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :----- | :----- | :------- | :------------------- |
| symbol | String | yes       | trading pairs, such as：BTC_USDT |
| period | String | yes       |period, such as："5m","15m","30m","1h","2h","4h","6h","12h","1d" |
| startTime | Long | no       | start time |
| endTime | Long | no       | end time, current time by default |
| limit | String | no        | The number of data items calculated backwards from end time, default value: 30, maximum value: 500 |

  -response result:

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
        "desc":"success"
    }
    ```



## 8. Public market：ws

- Interface type: WebSocket

- URL: wss://fapi.zb.com/ws/public/v1
- Use json encoding for request parameters

### 8.1 subscribe

 - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :------ | :------- | :------- | ------------------------------------------------------------ |
| action  | String   | yes       | subscribe                                                    |
| channel | String   | yes       | Channel<br />Format: Market name. Data type<br />order book:  BTC_USDT.Depth<br />filled:  BTC_USDT.Trade<br />Candlestick： BTC_USDT.KLine_15M, Optional range:1M,5M,15M, 30M, 1H, 6H, 1D, 5D |
| size    | Interger | no       | The number of records. <br />kline: The maximum value is 1440, the default value is 1<br />Full depth: maximum 10, default 5<br />Deal: the maximum value is 100, the default value is 50<br /> |

  - Request example

    ```json
    {
      "action": "subscribe",
     	"channel":"BTC_USDT.KLine_15M",
      "data":					//Different channels have different data
    }
    
    ```

- Failure format

  ```json
  {
   	"channel":"BTC_USDT.KLine_15M",
    "errorCode": ,
    "errorMsg":
  }
  ```

  

### 8.2 unsubscribe

 - Request parameter:

| Parameter   |  Type   | Required | Description               |
| :------ | :----- | :------- | :----------------------------------------------------------- |
| action  | String | yes       | unsubscribe                                                  |
| channel | String | yes      | Channel<br />Format: Market name. Data type<br />Order book:  BTC_USDT.Depth<br />Deal:  BTC_USDT.Trade<br />Candlestick： BTC_USDT.1M, Optional range: 1M,5M,15M, 30M, 1H, 6H, 1D, 5D |

  - Request example

    ```json
    {
      "action": "subscribe",
     	"channel":"BTC_USDT.KLine_15M"
    }
    
    ```

### 8.3 Full depth

- Update frequency: 200ms once
- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.DepthWhole@0.01",	//5 depths in full, @Behind refers to the accuracy of the handicap.If there is no @precision, it will be treated as the default precision (the first in the precision list)，
	"size": 5
}
```

The maximum size is 10, default value is 5

- Response format

 Buy orders are sorted by price in descending order, sell orders are sorted by price in ascending order

```json
{
  "channel": "BTC_USDT.DepthWhole@0.01",
	"data": {
    "asks":[					 //sell orders
      [
        16146.91,				//price
        0.029267				//quantity
      ],
      [
        16146.93,
        0.129334
      ]
    ],
    "bids":[							//buy orders
      [
        16131.41
        8.866436
      ],
      [
        16131.36,
        2
      ]
    ],
    "time":  1630657743231  //Current server time
	}
}
```

### 8.4 Increment depth

- Update the full depth every 5 minutes. When the client receives the full amount, it directly replaces the local depth meter
- Update frequency: real time. When the client receives the increment, it needs to update the local depth table with the increment data
- When size is empty, the default is 50. The maximum is 1000.

```json
{ 
     "action": "subscribe",
     "channel": "BTC_USDT.Depth@0.01",   //@Behind refers to the accuracy of the handicap. If there is no @precision, it will be treated as the default precision (the first in the precision list)
     "size": 50
}
```

- Increment response format

```json
{
  "channel": "BTC_USDT.Depth@0.01",
	"data":{
    "asks":[					//sell orders
		[
			16146.91,				//price
			0.029267				//quantity
		],
		[
			16146.93,
			0.129334
		]
	],
	"bids":[							//buy orders
		[
			16131.41,
			8.866436
		],
		[
			16131.36,
			8.85
		]
	],
  "time":  1630657743231  //Current server time
  }
}
```

- Full response format

  Buy orders are sorted by price in descending order, sell orders are sorted by price in ascending order

```json
{
  "channel": "BTC_USDT.Depth@0.01",	//@Behind refers to the accuracy of the handicap. If there is no @precision, it will be treated as the default precision (the first in the precision list)
  "type": "Whole",									//Whole:Full Update:Increment default value is Update
  "data":{
    "asks":[					//sell orders
		[
			16146.91,				//price
			0.029267				//quantity
		],
		[
			16146.93,
			0.129334
		]
	],
	"bids":[							//buy orders
		[
			16131.41,
			8.866436
		],
		[
			16131.36,
			2
		]
	],
  "time":  1630657743231  //current server time
  }
}
```

### 8.5 Candlestick

- Update frequency: 100ms
- Request parameter

```json
{ 
     "action": "subscribe",
     "channel": "BTC_USDT.KLine_15M",
  	 "size": 1440
}
```

The maximum size is 1440,  default value is 1

Candlestick optional range: 1M,5M,15M, 30M, 1H, 6H, 1D, 5D

There are only two cases of incremental candlestick: 1 and 2. When it is at the candlestick period point, there are two, and at other times it is one.

There may be more than 2 in the full amount.

- Response format

```json
{
  "channel":"BTC_USDT.KLine_15M",
  "type":"Whole",	//Whole:Full Update:Increment default value is Update
  "data":[
    [
      16199,			//open
      16212.3,		//high
      16087.42,		//low
      16131.4,		//close
      1160.79137966,	//volume
      1605265200	//time
  	],
    [
      16199,			//open
      16212.3,		//high
      16087.42,		//low
      16131.4,		//close
      1160.79137966,	//volume
      1605266100	//time
  	]
  ]
}
//The time of candlestick is arranged in descending order
```

## 

### 8.6 Trade

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.Trade",
  "size": 50,	//s 
}
```

The maximum size is 100,  default value is 50



- Response format

```json
{
  "channel": "BTC_USDT.Trade",
  "data":[
		[
			16131.3,		//price
			0.03749,		//quantity
			-1,					//sell
			1605266072	//time
		],
		......
		[
			16130.01,		//price
			0.2,				//quantity
			1,					//buy
			1605266073	//time
		]      
	]
}
```

### 8.7 Ticker

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.Ticker"
}
```

- Response format

```json
{
  "channel": "BTC_USDT.Ticker",
  "data":[
		16100.9,		//Opening price
  	16133.2,		//Highest price
  	16100.1,		//Lowest price
  	16132.3,		//Latest transaction price
    1000,		    //Volume (last 24 hours)
		0.19502,		//24H change
		1605266072	//Time
	]
}
```

### 8.8 All Ticker

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "All.Ticker"
}
```

- For the first time, all tickers of all trading pairs will be issued. Then only new ticker data will be issued.
- Response format

```json
{
  "channel": "All.Ticker",
  "data":{
    "BTC_USDT":[
      16100.9,		//Opening price
      16133.2,		//Highest price
      16100.1,		//Lowest price
      16132.3,		//Latest transaction price
      1000,		    //Volume (last 24 hours)
      0.19502,		//24H change
      1605266072	//Time
		],
    "BCH_USDT":[
      16100.9,		//Opening price
      16133.2,		//Highest price
      16100.1,		//Lowest price
      16132.3,		//Latest transaction price
      1000,		    //Volume (last 24 hours)
      0.19502,		//24H change
      1605266072	//Time
		]
    ......
  }
}
```

### 8.9 Index price and mark price

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.mark"	//BTC_USDT.index. mark means mark price, index means index price
}
```

- Response format

```json
{
  "channel":"BTC_USDT.index",
  "data":"38550.57"
}
```



### 8.10 Index price candlestick and mark price candlestick

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.mark_15M",	//BTC_USDT.index_15M. mark means mark price, index means index price
  "size": 50,	//s 
}
```

The maximum size is 100, default value is 1



- Response format

```json
{
  "channel": "BTC_USDT.mark",	//BTC_USDT.index_15M
  "data":[
      [
        16199,			//open
        16212.3,		//high
        16087.42,		//low
        16131.4,		//close
        1605265200	//time
      ],
      [
        16199,			//open
        16212.3,		//high
        16087.42,		//low
        16131.4,		//close
        1605266100	//time
      ]
    ]
}
```



### 8.11 Funding rate and next settlement time

- Request parameter

```json
{ 
	"action": "subscribe",
	"channel": "BTC_USDT.FundingRate"
}
```

- Response format

```json
{
    "channel":"BTC_USDT.FundingRate",
    "data":{
        "fundingRate":-0.297589,	//Funding rate
        "nextCalculateTime":"2021-01-15 00:00:00"	//The next funding fee settlement time
    }
}
```

### 8.12 ping

`It is recommended that the user do the following:

   1，After each message is received, the user sets a timer for N seconds.

   2，If the timer is triggered (no new message is received within N seconds), the string'ping' is sent.

   3，Expect a literal string'pong' as a response. If you do not receive it within N seconds, please send an error or reconnect.

   If there is a network problem, the connection will be automatically disconnected.
`
- ** Request parameter：**

 | Parameter         | Type    | Required | Description       |
  | :----- | :--- | :----- | :--- |
  | action | yes   | String | ping |


- Request example

```json
{
  "action": "ping"
}
```

- Successful response format

```json
{
	"action":"pong"
}
```



## 9. User data：ws

### 9.1 Overview

- Interface type: WebSocket

- URL: wss://fapi.zb.com/ws/private/api/v2

- **Parameters required for every request:**

 | Parameter         | Type    | Required | Description                                        |
  | :------ | :--- | :----- | :----------------------------------------------- |
  | action  | yes   | String | subscribe:subscribe  unSubscribe:unsubscribe  login:login |
  | channel | yes   | String | channels, representing different subscription content                         |


- Request example

```json
{
  "action": "subscribe",
  "channel":"Fund.change",
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- Successful response format

```json
{
	"channel":"Fund.change",
	"data":	//Different channels return different content, please check the description of each channel for details
}
```

- Failure response format

```json
{
	"channel":"Fund.change",
	"errorCode":,
  "errorMsg":
}
```

#### 9.1.1 Ping

It is recommended that the user do the following:

   1，After each message is received, the user sets a timer for N seconds.

   2，If the timer is triggered (no new message is received within N seconds), the string'ping' is sent.

   3，Expect a literal string'pong' as a response. If you do not receive it within N seconds, please send an error or reconnect.

   If there is a network problem, the connection will be automatically disconnected.

- **Request parameter：**

  | Parameter         | Type    | Required | Description                                        |
  | :----- | :--- | :----- | :--- |
  | action | yes   | String | ping |


- Request example

```json
{
  "action": "ping"
}
```

- Successful response format

```json
{
	"action":"pong"
}
```


### 9.2 Login

After the connection is established, you need to log in before you can subscribe to the channel. When subscribing to future channels, you do not need to bring ZB-APIKEY, ZB-TIMESTAMP and ZB-SIGN.

- **Request parameter：：**

  | Parameter         | Type    | Required | Description                                           |
  | :----------- | :--- | :----- | :----------------------------------------------- |
  | action       | yes   | String | login:login                                       |
  | ZB-APIKEY    | yes  | String | The user's api key is generated by the ZB platform                        |
  | ZB-TIMESTAMP | yes   | String | Request time, in ISO format, such as`2021-01-05T14:05:28.616Z |
  | ZB-SIGN      | yes   | String | sign                                             |


- Request example

```json
{
  "action": "login",
  "ZB-APIKEY":"a55caded-eef9-426b-af7c-faf53c78e2ae",
  "ZB-TIMESTAMP":"2021-01-22T02:08:54.312Z",
  "ZB-SIGN":"flsToYwO39sGJ8Pp6gAfIOsUBLLRa3F3daDcYqddGKc="
}
```

- Successful response format

```json
{
	"action":"login",
	"data":	"success"
}
```

#### 9.2.1 Signature rules

- The server performs signature verification on the initiated request to confirm the source of the request；

- Do not transmit the secretKey in the request or response；

- ZB-SIGN field is obtained by encrypting``timestamp`` + ``GET``  + ``login``(+means string connection))，and SecretKey，using the HMAC SHA256 method and outputting through Base64 encoding;

  For example：`sign=CryptoJS.enc.Base64.Stringify(CryptoJS.HmacSHA256(timestamp + 'GET' + 'login', SecretKey))`

  Among them，the value of `timestamp` is same as the request of `ZB-TIMESTAMP` in ISO format,such as `2021-01-05T14:05:28.616Z`。

  SecretKey is generated when the user applies for the APIKey and needs to be encrypted with sha1, such as：`ceb892e0-0367-4cc1-88d1-ef9289feb053`，Encrypt the SecretKey to obtain: c9a206b430d6c6a43322a05806acb5f9514ac488

  Online crypto tool: http://tool.oschina.net/encrypt?type=2

### 9.3 Funds

- **Required parameters for all funding requests:**

  | Parameter         | Type    | Required | Description           |
  | :----------------- | :--- | :------ | :------------- |
  | futuresAccountType | yes   | Integer | 1:USDT Perpetual futures 2:QC perpetual futures|

#### 9.3.1 Assets changes

  - Changes in user funds will be pushed to customers and continue to push

  - **Unique parameters：**

    | Parameter         | Type    | Required | Description        |
    | :------- | :--- | :----- | :---------- |
    | channel  | yes   | String | Assets changes |
    | currency | yes   | String | Currency, such as BTC |

  - Request example

```json
{
  "action": "subscribe",
  "channel":"Fund.change",	//funding changes
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- Response format

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

- Response parameter description

| Parameter         | Type    |  Description         |
| :--------------- | :--------- | :------------- |
| userId           | Long       | user id         |
| currencyId       | Long       | currency id         |
| currencyName     | String     | currency name        |
| amount           | BigDecimal | available assets     |
| freezeAmount     | BigDecimal | frozen amount         |
| id               | Long       | asset id         |
| createTime       | Long       | created time       |


#### 9.3.2 Fund inquiry

- Only push the current user's assets once

- **Unique parameters:**

  | Parameter         | Type    | Required | Description        |
  | :------- | :--- | :----- | :----------- |
  | channel  | yes   | String | Fund.balance |
  | currency | no   | String | Currency, such as BTC  |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Fund.balance",
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- Response format

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

- Response parameter description

| Parameter         | Type    |  Description               |
| :--------------- | :--------- | :------------- |
| userId           | Long       | user id         |
| currencyId       | Long       | currency id       |
| currencyName     | String     | currency name    |
| amount           | BigDecimal | available assets    |
| freezeAmount     | BigDecimal | fozen amount         |
| id               | Long       | asset id         |
| createTime       | Long       | created time         |


#### 9.3.3 Query user bill

- Only push the current user's assets once

- **Unique parameters：**

  | Parameter         | Type    | Required | Description        |
  | :-------- | :--- | :------ | ---------------- |
  | channel   | yes   | String  | Fund.getBill     |
  | currency  | no   | String  | Currency, such as BTC      |
  | type      | no   | Integer | Bill type       |
  | startTime | no   | Long    | Start timestamp       |
  | endTime   | no   | Long    | End timestamp      |
  | pageNum   | no   | Integer | Page             |
  | pageSize  | no   | Integer | Number of rows per page, default 10 |

- 

```json
{
  "action": "subscribe",
  "channel":"Fund.getBill",
  "futuresAccountType":1,
  
  "currency": "USDT"
}
```

- Response format

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

- Response parameter description

 | Parameter         | Type    | Required | Description                |
| :----------------- | :--- | :--------- | :----------------- |
| userId             | yes   | Long       | user id             |
| freezeId           | yes   | String     | frozen id             |
| type               | yes  | BigDecimal | bill type           |
| changeAmount       | yes   | BigDecimal | change the amount of assets         |
| feeRate            | no   | BigDecimal | funding fee              |
| fee                | no   | BigDecimal | commission             |
| operatorId         | no   | Long       | user id           |
| beforeAmount       | yes  | BigDecimal | account assets before the change     |
| beforeFreezeAmount | yes  | BigDecimal | frozen assets before the change   |
| marketId           | no   | Long       | market id             |
| outsideId          | no   | Long       | external idempotent id        |
| id                 | no   | Long       | bill id             |
| isIn               | no   | Integer    | 1：increase  0： decrease  |
| available          | no   | BigDecimal | currently available assets       |
| unit               | no   | String     | currency name, quantity unit |
| createTime         | no  | Long       | create timestamp       |
| modifyTime         | no   | Long       | update timestamp         |
| extend             | no   | String     | spare field           |

#### 9.3.4 Changes in futures account details

- Keep pushing

  - **Unique parameters：**

    | Parameter         | Type    | Required | Description                                                         |
    | :---------- | :--- | :----- | :----------------------------------------------------------- |
    | channel     | yes   | String | Fund.assetChange                                             |
    | convertUnit | no   | String | Converted unit, the number unit after "≈" is displayed on the page, optional: cny, usd, btc, default cny | |

  - Request example

```json
{
  "action": "subscribe",
  "channel":"Fund.assetChange",
  "futuresAccountType":1,
  
  "convertUnit": "cny"
}
```

- Response format

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

- Response parameter description

| Parameter         | Type    |  Description                                                           |
| :---------------------- | :--------- | :----------------------------------------------------------- |
| accountBalance          | BigDecimal | Account balance: available + frozen + unrealized profit and loss of all positions                       |
| allMargin               | BigDecimal | Margin for all positions                                             |
| available               | BigDecimal | Available assets                                                   |
| freeze                  | BigDecimal | Frozen amount                                                       |
| allUnrealizedPnl        | BigDecimal | Cumulative unrealized profit and loss of all corresponding positions                                 |
| accountBalance          | BigDecimal | Account balance: available + frozen + unrealized profit and loss of all positions                 |
| unit                    | String     | Fixed return, if it is u-margin, it returns usdt, if it is coin-margin, it returns btc, if it is a qc contract, it returns qc, the unit of statistical data |
| allMarginConvert        | BigDecimal | Margin for all positions converted                                          |
| availableConvert        | BigDecimal | Available asset volume equivalent                                               |
| freezeConvert           | BigDecimal | Frozen amount equivalent                                                   |
| allUnrealizedPnlConvert | BigDecimal | Cumulative unrealized profit and loss for all corresponding positions                             |
| convertUnit             | String     | Conversion unit, the page displays the number unit after the "≈" sign, such as:cny，usd,btc    |
| percent                 | BigDecimal | Unrealized profit/loss/margin for all positions*100%                            |



#### 9.3.5 Query the account details of futures

- Only push once

  - **Unique parameters：**

    | Parameter         | Type    | Required | Description                                                            |
    | :---------- | :--- | :----- | :----------------------------------------------------------- |
    | channel     | yes   | String | Fund.assetInfo                                               |
    | convertUnit | no   | String | Converted unit, the number unit after "≈" is displayed on the page, optional: cny, usd, btc, default cny.Multiple conversion units cannot be subscribed at the same time. Subsequent subscriptions will automatically cancel previous subscriptions. |

  - Request example

```json
{
  "action": "subscribe",
  "channel":"Fund.assetInfo",	//Funding changes
  "futuresAccountType":1,
  
  "convertUnit": "cny"
}
```

- Response result:

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

- Response parameter description

  Reference to the description of response parameters for changes in asset summary

### 9.4 Position

Only user position changes. Positions.change will be pushed if there is a change. All other interfaces are only pushed once.

- **Required parameters for position requests：**

 | Parameter         | Type    | Required | Description                |
  | :----------------- | :--- | :------ | :------------- |
  | futuresAccountType | yes   | Integer | 1:USDT Perpetual futures 2:QC perpetual futures |


#### 9.4.1 Position changes

- Changes in user positions will be pushed to customers and continue to push

- **Unique parameters：**

 | Parameter         | Type    | Required | Description                                |
  | :------ | :--- | :----- | :----------------------------------------- |
  | channel | yes   | String | Positions.change                           |
  | symbol  | no   | String | Futures, that is, the unique identifier of the market trading pair, such as: BTC_USDT|

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.change",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT"
}
```

  - If there is no symbol, it means that any changes in the position will be pushed to the customer. If the symbol is specified, only the position changes of this market will be pushed to the customer.

  - Response format

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

-  Response parameter description

| Parameter         | Type    | Required | Description                              |
| :------------- | :--- | :--------- | :-------------------------------------- |
| userId         | yes   | Long       | User id                                  |
| marketId       | yes   | Long       | Market id                                  |
| symbol         | yes   | String     | Market name                                |
| side           | yes   | Integer    | Position opening direction, open long: 1 open short: 0                |
| leverage       | no   | Integer    | Leverage                               |
| amount         | no   | BigDecimal | Number of holding positions                            |
| freezeAmount   | yes   | BigDecimal | Order frozen position number                        |
| avgPrice       | yes   | BigDecimal | Average price of open positions                                |
| liquidatePrice | yes   | BigDecimal | Liquidation price                               |
| margin         | yes  | BigDecimal | Margin                                  |
| marginMode     | yes  | Integer    | Margin mode: 1 isolated（default），2 cross        |
| positionsMode  | yes  | Integer    | 1:one-way position，2: hedge positions                |
| status         | yes   | Integer    | Status: 1 available, 2: locked, 3: frozen, 4: not displayed |
| unrealizedPnl  | no   | BigDecimal | Unrealized profit and loss                              |
| marginBalance  | yes   | BigDecimal | Margin balance                              |
| maintainMargin | yes   | BigDecimal | Maintenance margin                              |
| marginRate     | yes   | BigDecimal | Margin rate                                |
| nominalValue   | yes   | BigDecimal | Nominal value of the position                         |
| id             | yes  | Long       | Position id                                |
| createTime     | yes  | Long       | Created time                                |
| modifyTime     | yes   | Long       | Modified time                               |
| extend         | no   | Long       | Spare field                                |

#### 9.4.2 Position query


- Only push once

- **Unique parameters：**

  |   name  | required| type   | instruction                                       |
  | :------ | :--- | :----- | :----------------------------------------- |
  | channel | yes   | String | Positions. get positions                     |
  | symbol  | yes   | String | contract, that is, the unique identifier of the market transaction pair, such as: BTC_USDT |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.getPositions",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT"
}
```

- If no symbol，means that all positions will be pushed to the client. if the symbol is specified，only the position of this market will be pushed.

- The response field description is the same as the user position change field above.

- Response format

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

- Response parameter description

| name         | required | type       | description                                    |
| :------------- | :--- | :--------- | :-------------------------------------- |
| userId         | Yes  | Long       | user id                                  |
| marketId       | yes   | Long       | market id                                  |
| symbol         | yes  | String     | market name                                |
| side           | yes   | Integer    | side,long：1 short：0                |
| leverage       | No   | Integer    | leverage                                |
| amount         | no   | BigDecimal | amount                            |
| freezeAmount   | yes   | BigDecimal | freeze amount                        |
| avgPrice       | yes   | BigDecimal | avg price                               |
| liquidatePrice | yes   | BigDecimal | liquidate price                                |
| margin         | yes   | BigDecimal | margin                                  |
| marginMode     | yes  | Integer    | margin mode：1isolated（default），2cross        |
| positionsMode  | yes  | Integer    | 1:one-way position，2: two-way position                 |
| status         | yes   | Integer    | statues: 1 available, 2: locked, 3: frozen, 4: not displayed |
| unrealizedPnl  | no   | BigDecimal | unrealized PnL                             |
| marginBalance  | yes   | BigDecimal | margin balance                              |
| maintainMargin | yes   | BigDecimal | maintain margin                              |
| marginRate     | yes   | BigDecimal | margin rate                                |
| nominalValue   | yes   | BigDecimal | nominal value                          |
| id             | yes  | Long       | position id                                  |
| createTime     | yes   | Long       | create time                                |
| modifyTime     | yes   | Long       | modify time                                |
| extend         | no   | Long       | extend                               |

 

#### 9.4.3 Margin information query

- only push once

- **Unique parameters：**

  | name      | required | type  | description                |
  | :---------- | :--- | :----- | :------------------- |
  | channel     | yes   | String | Positions.marginInfo |
  | positionsId | yes   | Long   | position id               |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.marginInfo",
  "futuresAccountType":1,
  
  "positionsId":"6742095107924699136"	//position id
}
```



- Response format

```json
{
  "channel":"Positions.marginInfo",
  "data":{
    "positionsId": "6742095107924699136",	//
    "maxAdd": 1212.12,	//Maximum margin increase
		"maxSub": 1212.12,	//Maximum margin withdrawal amount
		"liquidatePrice": 121212.12	//Estimated liquidation price
  }
}
```

#### 9.4.4 Withdraw or increase margin

- Only push once

- **Unique parameters：**

  | name      | required | type   | description           |
  | :---------- | :--- | :--------- | :--------------------- |
  | channel     | yes   | String     | Positions.updateMargin |
  | positionsId | yes   | Long       | position id                 |
  | amount      | yes   | BigDecimal | change amount               |
  | type        | yes   | Integer    | 1: increase  0：deduct       |

- Request example

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

- Response format

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

- Response parameter description 

  See user position query



#### 9.4.5 Position configuration information query

- Only push once

- **Unique parameters：**

  |name  | required | type   | description                                      |
  | :------ | :--- | :----- | :----------------------------------------- |
  | channel | yes   | String | Positions.getSetting                       |
  | symbol  | yes   | String | contract，That is, the unique identifier of the market transaction pair, such as:BTC_USDT |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.getSetting",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT"
}
```



- Response format

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

#### 9.4.6 Position leverage setting

- Only push once

- **Unique parameters：**

  | name  | required | type   | description                                   |
  | :------- | :--- | :------ | :----------------------------------------- |
  | channel  | yes   | String  | Positions.setLeverage                      |
  | symbol   | yes   | String  | contract, that is, the unique identifier of the market transaction pair, such as：BTC_USDT |
  | leverage | yes   | Integer | leverages                                   |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.setLeverage",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT",
  "leverage": 20
}
```



- Response format

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



#### 9.4.7 Position mode setting

- Only push once

- **Unique parameters：**

  | name     | required | type   | description                                       |
  | :------------ | :--- | :------ | :----------------------------------------- |
  | channel       | yes   | String  | Positions.setPositionsMode                 |
  | symbol        | yes   | String  | contract, that is, the unique identifier of the market transaction pair, such as：BTC_USDT |
  | positionsMode | yes  | Integer | 1:one-way position，2: two-way position                    |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.setPositionsMode",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT",
  "positionsMode":1
}
```

- Response format

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

#### 9.4.8 Position margin mode setting

- Only push once

- **unique parameters：**

  |    name   | required | type   | description                            |
  | :--------- | :--- | :------ | :----------------------------------------- |
  | channel    | yes   | String  | Positions.setMarginMode                    |
  | symbol     | yes  | String  | contract, that is, the unique identifier of the market transaction pair, such as：BTC_USDT |
  | marginMode | yes   | Integer | 1isolated（default），2 cross          |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.setMarginMode",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT",
  "marginMode":1
}
```

- Response format

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

#### 9.4.9 View the user’s current position

- Only push once

- **unique parameters：**

  | name  | required | type   | description                                 |
  | :------ | :--- | :------ | :----------------------------------------- |
  | channel | yes   | String  | Positions.getNominalValue                  |
  | symbol  | yes   | String  | contract, that is, the unique identifier of the market transaction pair, such as：BTC_USDT |
  | side    | yes   | Integer | side：1： long   0 short                     |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Positions.getNominalValue",
  "futuresAccountType":1,
  
  "symbol":"BTC_USDT",
  "side":1
}
```

- Response format

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

  - Response parameter description：

| name.         | required | type      | description              |
| :-------------------- | :--- | :--------- | :------------------- |
| nominalValue          | yes   | BigDecimal | notional value of user positions |
| marketId              | yes   | Long       | marketid               |
| openOrderNominalValue | yes   | BigDecimal | nominal value of order position   |

### 9.5 Orders and transactions

#### 9.5.1 Order changes

- Changes in user orders will be pushed to customers, and continue to push


- **Unique parameters：**

  | name | Required | Type | Description                                 |
  | :------ | :--- | :----- | :----------------------------------------- |
  | channel | yes   | String | trade.orderChange                          |
  | symbol  |yes   | String | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.orderChange"
  
  "symbol":"BTC_USDT"
}
```

  - If no symbol，it means that any changes in the position will be pushed to the customer。if the symbol is specified, only the position change of. This market will be pushed to the customer.

  - Response result

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
        "value":"2022.1",
        "lastTradePrice": "40118.02",
        "lastTradeAmount: "0.31" ,
        "lastTradeId": "67559926698340432891",
        "lastTradeTime": 1617955686930
    }
}
```

- Response parameter description

​		Refer to ``5.6 Query all current pending orders'' Return result description




#### 9.5.2 Place an order

- Only push once

  - **Unique parameters：**

    | Name | Required | Type | Description                                         |
    | :------------ | ---- | :------ | :----------------------------------------------------------- |
    | channel       | yes   | String  | trade.order                                                  |
    | symbol        | yes   | String  | contract，the unique identifier of the market transaction pair, such as：BTC_USDT                   |
    | price         | yes   | Decimal | price                                                         |
    | amount        | yes   | Decimal | amount                                                        |
    | actionType    | yes   | Integer | 1   limited<br/>11 counterparty<br/>12 optimal 5<br/>3   IOC<br/>31 counterpartyIOC<br/>32 optimal 5 IOC<br/>4   only maker<br/>5   FOK<br/>51 counterpartyFOK<br/>52 optimal 5FOK<br/> |
    | side          | yes   | Integer | side：1open long（buy），2open short（sell），3close long（sell），4close short（buy） |
    | clientOrderId | no   | String | customizeid |
  
- Request example

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

- Response result

```json
{
  "channel":"Trade.order",
  "data": {
    	"orderId":"6848243828432838656",
  		"orderCode":"01aa0ff5b1974d9ab09167b77e6dd116"
  }
}
```

- Response paremeter description

| name    | required | type   | description         |
| :-------- | :--- | :----- | :----------- |
| orderId   | yes   | String | orderid       |
| orderCode | yes   | String | customizeordernumber |

#### 9.5.3 Query order details

- Only push once

  - **Unique parameters：**

    | name        | required | type   | description                                       |
    | ------------- | ---- | :----- | :----------------------------------------- |
    | channel       | yes   | String | trade.getOrder                             |
    | symbol        | yes   | String | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | orderId       | no   | Long   | orderID                                     |
    | clientOrderId | no   | String | customizeid                                   |

    order Id and client Order Id pick one of two

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.getOrder",
  
  "symbol":"BTC_USDT",
  "orderId":6753263247702368256
}
```

- Response result

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

- Response paremeter description

  Refer to order changed Response paremeter description

  

#### 9.5.4 Cancel order

- Only push once

  - **Unique parameters：**

    | name        | required | type   | description                                       |
    | ------------- | ---- | :----- | :----------------------------------------- |
    | channel       | yes   | String | trade.cancelOrder                          |
    | symbol        | yes   | String | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | orderId       | no   | Long   | orderID                                     |
    | clientOrderId | no   | String | customizeid                                   |

- orderId and clientOrderId pick one

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.cancelOrder",
  
  "symbol":"BTC_USDT",
  "orderId":6753263256262942720
}
```

- Response result

```json
{
    "channel":"Trade.cancelOrder",
    "data":"6753263256262942720" // order number
}
```

#### 9.5.5 Batch cancel orders

- Only push once

  - **Unique parameters：**

    | name         | required | type     | description                                       |
    | -------------- | ---- | :------- | :----------------------------------------- |
    | channel        | yes   | String   | trade.batchCancelOrder                     |
    | symbol         | yes   | String   | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | orderIds       | no   | Long[]   | orderIDlist                                 |
    | clientOrderIds | no   | String[] | customizeidlist                               |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.batchCancelOrder",
  
  "symbol":"BTC_USDT",
  "orderIds":[1753262282144227328, 6753260246627524608]
}
```

- Successful response

```json
{
  "channel":"Trade.batchCancelOrder",
  "data":[],
}
```

- Failed response


```json
{
    "channel":"Trade.batchCancelOrder",
    "data":[
        {
            "code":12012,
            "data":"6786122846578941952",
            "desc":"order not exist"
        },
        {
            "code":12012,
            "data":"6786122900735795200",
            "desc":"order not exist"
        }
    ]
}
```

#### 9.5.6 Cancel all order

- Only push once

  - **Unique parameters：**

    | name  | required | type   | description                                       |
    | ------- | ---- | :----- | :----------------------------------------- |
    | channel | yes   | String | trade.cancelAllOrders                      |
    | symbol  | yes   | String | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.cancelAllOrders",
  
  "symbol":"BTC_USDT"
}
```

- Response result

```json
{
    "channel":"Trade.cancelAllOrders",
	  "data":[],
}
```

#### 9.5.7 Query all pending orders (unfilled order list)

- Only push once

  - **Unique parameters：**

    | name   | required | type    | description                                       |
    | -------- | ---- | :------ | :----------------------------------------- |
    | channel  | yes   | String  | trade.getUndoneOrders                      |
    | symbol   | yes   | String  | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | pageNum  | yes   | Integer | page number，Start from 1                              |
    | pageSize | yes   | Integer | Paging Size                                  |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.getUndoneOrders",
  
  "symbol":"BTC_USDT"
}
```

- Response result

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

#### 9.5.8 Query all orders

- Only push once

  - **Unique parameters：**

    | name    | required | type    | description                                       |
    | --------- | ---- | :------ | :----------------------------------------- |
    | channel   | yes   | String  | trade.getAllOrders                         |
    | symbol    | yes   | String  | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | startTime | no   | Long    | starting time                                   |
    | endTime   | no   | Long    | ending time                                   |
    | pageNum   | yes   | Integer | page number，start from 1                        |
    | pageSize  | yes   | Integer | paging size                                   |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.getAllOrders",
  
  "symbol":"BTC_USDT"
}
```

- Response result

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

#### 9.5.9 Query transaction details

- Only push once

  - **Unique parameters：**

    | name  | required | type   | description                                       |
    | ------- | ---- | :----- | :----------------------------------------- |
    | channel | yes   | String | trade.getTradeList                         |
    | symbol  | yes   | String | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | orderId | yes   | Long   | orderID                                     |

- Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.getTradeList",
  "orderId":"6785805407710355456",
  "symbol":"BTC_USDT"，
}
```

- Response result

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

- Response paremeter description

| name      | required | type    | description                                                         |
| :---------- | :--- | :------ | :----------------------------------------------------------- |
| orderId     | yes   | Long    | orderid                                                       |
| price       | yes   | Decimal | price                                                     |
| amount      | yes   | Decimal | amount                                                     |
| feeAmount   | yes   | Decimal | fee                                                       |
| feeCurrency | yes   | String  | fee currency                                                   |
| relizedPnl  | yes   | Decimal | realized PnL                                                   |
| side        | yes   | Integer | side：1open long（buy），2open short（sell），3close long（sell），4close short（buy） |
| maker       | yes   | Boolean | yesnomaker,no as taker                                        |
| createTime  | yes   | Long    | deal time                                                   |

#### 9.5.10 Query Historical transaction records


- Only push once

  - **Unique parameters：**

    | name    | required | type    | description                                       |
    | --------- | ---- | :------ | :----------------------------------------- |
    | channel   | yes   | String  | trade.tradeHistory                         |
    | symbol    | yes   | String  | contract，the unique identifier of the market transaction pair, such as：BTC_USDT |
    | startTime | no   | Long    | starting time                                   |
    | endTime   | no   | Long    | ending time                                   |
    | pageNum   | yes   | Integer | page number，start from 1                              |
    | pageSize  | yes   | Integer | paging size                                   |

- 

  - Request example

```json
{
  "action": "subscribe",
  "channel":"Trade.tradeHistory",
  
  "symbol":"BTC_USDT"，
}
```

- Response result

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

- Response paremeter description

  refer to query deal order details Response paremeter description

#### 9.5.11 Batch order

- Only push once

**Unique parameters：**

| name       | type   | yesno required | description                                       |
| :--------- | :----- | :------- | :----------------------------------------- |
| channel    | yes     | String   | Trade.batchOrder                           |
| orderDatas | String | yes       | orderlist，JSONtype code，the parameters are same as the order interface |

- **Request example**

```json
{
  "action": "subscribe",
  "channel":"Trade.batchOrder",
  
    "orderDatas": [{"symbol":"ETH_USDT","amount":1,"side":1,"price":"1100","action":1, "orderCode": "test01"},{"symbol":"ETH_USDT","amount":1,"side":1,"price":"1000","action":1, "orderCode": "test02"}]
}
```

  - Response result:

  ```json
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

Response paremeter description data：

| name      | type   | yes no required | description                             |
| :-------- | :----- | :------- | :----------------------------------- |
| sCode     | Int    | yes       | result code，1Represents success           |
| sMsg      | String | yes       | result description                             |
| orderId   | String | no       | orderID                               |
| orderCode | String | no       | customizeorderID，If vacant, the system will automatically assign.|



## 10. Error code
 

| Code   | description                                             |
| :----- | :----------------------------------------------- |
| 10000  | Operation success                                         |
| 10001  | Operation failed                                         |
| 10002  | Operation is forbidden                                       |
| 10003  | Data existed                                     |
| 10004  | Date not exist                                       |
| 10005  | Forbidden to access the interface                                    |
| 10006  | Currency invalid or expired                                |
| 10007  | {0}                                              |
| 10008  | Operation failed: {0}                                    |
| 10009  | URL error                                          |
| 10010  | API KEY not exist                                    |
| 10011  | API KEY CLOSED                                   |
| 10012  | User API has been frozen, please contact customer service for processing                  |
| 10013  | API verification failed                                      |
| 10014  | Invalid signature(1001)                                 |
| 10015  | Invalid signature(1002)                                 |
| 10016  | Invalid ip                                         |
| 10017  | Permission denied                                         |
| 10018  | User has been frozen, please contact customer service                    |
| 10019  | Request time has expired                                   |
| 10020  | {0}Parameter cannot be empty                                 |
| 10021  | {0}Invalid parameter                                     |
| 10022  | Request method error                                   |
| 10023  | Request frequency is too fast, exceeding the limit allowed by the interface        |
| 10024  | Login failed                                         |
| 10025  | Non-personal operation                                       |
| 10026  | Failed to request interface, please try again                      |
| 10027  | Timed out, please try again later                        |
| 10028  | System busy, please try again later                            |
| 10029  | Frequent operation, please try again later                            |
| 10030  | Currency already exist                                     |
| 10031  | Currency does not exist                                       |
| 10032  | Market existed                                       |
| 10033  | Market not exist                                       |
| 10034  | Currency error                                         |
| 10035  | Market not open                                       |
| 10036  | Ineffective market type                                   |
| 10037  | User id cannot be empty                                   |
| 10038  | Market id cannot be empty                       |
| 10039  | Failed to get mark price                                 |
| 10040  | Failed to obtain the opening margin configuration                           |
| 10041  | Failed to obtain maintenance margin allocation                           |
| 10042  | Avg. price error                                  |
| 10043  | Abnormal acquisition of liquidation price                                 |
| 10044  | Unrealized profit and loss acquisition exception                               |
| 10045  | jdbcData source acquisition failed                    |
| 10046  | Invalid position opening direction                                  |
| 10047  | The maximum position allowed by the current leverage multiple has been exceeded    |
| 10048  |The maximum allowable order quantity has been exceeded         |
| 10049  | Failed to get the latest price                             |
| 10100  | Sorry! System maintenance, stop operation  |
| 11000  | Funding change failed                              |
| 11001  | Position change failed                                    |
| 11002  | Funding not exist                                       |
| 11003  | Freeze records not exist                                   |
| 11004  | Insufficient frozen funds                                   |
| 11005  | Insufficient positions                                       |
| 11006  | Insufficient frozen positions                                     |
| 11007  | Position not exist                                       |
| 11008  | The contract have positions, cannot be modified                      |
| 11009  | Failed to query data                                  |
| 110110 | Exceed the market's maximum leverage                            |
| 110011 | Exceeds the maximum leverage allowed by the position                        |
| 11012  | Insufficient margin                                       |
| 11013  | Exceeding accuracy limit                                     |
| 11014  | Invalid bill type                                     |
| 11015  | Failed to add default account                                 |
| 11016  | Account not exist                                       |
| 11017  | Funds are not frozen or unfrozen                              |
| 11018  | Insufficient funds                                      |
| 11019  | Bill does not exist                                       |
| 11021  | Inconsistent currency for funds transfer                        |
| 11023  | Same transaction currency                                     |
| 11030  | Position is locked, the operation is prohibited                          |
| 11031  | The number of bill changes is zero                                |
| 11032  | The same request is being processed, please do not submit it repeatedly              |
| 11033  | Position configuration data is empty                             |
| 11034  | Funding fee is being settled, please do not operate                         |
| 12000  | Invalid order price                                    |
| 12001  | Invalid order amount                                    |
| 12002  | Invalid order type                                     |
| 12003  | Invalid price accuracy                                     |
| 12004  | Invalid quantity precision                                   |
| 12005  | The order amount is less than the minimum or greater than the maximum          |
| 12006  | Customize's order number format is wrong                          |
| 12007  | Direction error                                         |
| 12008  | Order type error                                     |
| 12009  | Commission type error                                    |
| 12010  | Failed to place the order, the loss of the order placed at this price will exceed margin|
| 12011  | it's not a buz order                             |
| 12012  | order not exist                                       |
| 12013  | Order user does not match   |
| 12014  | Order is still in transaction                                   |
| 12015  | Order preprocessing failed                                  |
| 12016  | Order cannot be canceled                                    |
| 12017  | Transaction Record not exist                                   |
| 12018  | Order failed                                         |
| 12019  | extend parameter cannot be empty                 |
| 12020  | extend Parameter error                 |
| 12021  | The order price is not within the price limit rules!                     |
| 12022  | Stop placing an order while the system is calculating the fund fee                      |
| 12023  | There are no positions to close                             |
| 12024  | Orders are prohibited, stay tuned!                             |
| 12025  | Order cancellation is prohibited, so stay tuned!                           |
| 12026  | Order failed， customize order number exists                   |
| 12027  | System busy, please try again later                             |
| 12028  | The market has banned trading                                 |
| 12029  | Forbidden place order, stay tuned                         |
| 12005  | order value less than the minimum or greater than the maximum               |
| 12201  | Delegation strategy does not exist or the status has changed                      |
| 12202  | Delegation strategy has been changed, cannot be canceled |
| 12203  | Wrong order type                               |
| 12204  | Invalid trigger price                                     |
| 12205  | The trigger price must be greater than the market’s selling price or lower than the buying price. |
| 12206  | Direction and order type do not match                           |
| 12207  | Submission failed, exceeding the allowed limit                     |
| 13001  | User not exist                                       |
| 13002  | User did not activate futures                                  |
| 13003  | User is locked                                       |
| 13003  | Margin gear is not continuous                                |
| 13004  | The margin quick calculation amount is less than 0                              |
| 13005  | You have exceeded the number of exports that day                         |
| 13006  | No markets are bookmarked                                  |
| 13007  | Market not favorited                          |
| 13008  | Not in any market user whitelist                         |
| 13009  | Not in the whitelist of users in this market                         |
| 14000  | {0}not support                                      |
| 14001  | Already logged in, no need to log in multiple times                           |
| 14002  | Not logged in yet, please log in before subscribing                        |
| 14003  | This is a channel for one-time queries, no need to unsubscribe        |
| 14100  | Accuracy does not support                                      |
| 14101  | Request exceeded frequency limit                       |
| 14200  | id empty                                           |
| 14300  | activity not exist                                       |
| 14301  | The event has been opened and cannot be admitted                            |
| 14302  | The purchase time has passed and cannot be admitted                    |
| 14303  | Not yet open for the purchase                                   |
| 14305  | Cannot enter, the maximum number of returns has been exceeded                |
| 14306  | Cannot repeat admission                      |
| 14307  | Unable to cancel, status has been changed                            |
| 14308  | Unable to cancel, the amount does not match                             |
| 14309  | Activity has not started                                  |
| 14310  | Activity is over                                      |
| 14311  | The activity does not support orders placed in this market                        |
| 14312  | You have not participated in this activity                              |
| 14313  | Sorry! The purchase failed, the maximum number of participants has been reached        |
| 14314  | Active period id error                                    |
| 9999   | Unknown error                                        |
