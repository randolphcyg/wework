# github.com/randolphcyg/wework

将企业微信接口与企业微信的加解密接口打包在一起，方便用户直接生成客户端使用

## 1. install

```shell
go get github.com/randolphcyg/wework
```

## 2. Usage1 调用普通接口

初始化客户端`*api.CorpAPI`， 然后调接口即可：

```go
package main

import (
	"encoding/json"
	"errors"
	"github.com/randolphcyg/wework/api"
	"项目名称/conf"
)

var (
	CorpAPIOrder *api.CorpAPI
)

func InitWework() {
	CorpAPIOrder = api.NewCorpAPI(conf.Conf.Wework.CorpId, conf.Conf.Wework.OrderAppSecret)
}

// GetOrderDetail 获取工单详情
func GetOrderDetail(spNo uint64) (err error, res []byte) {
	if spNo == uint64(0) {
		return errors.New("工单号为空"), nil
	}
	response, err := CorpAPIOrder.GetApprovalDetail(map[string]interface{}{
		"sp_no": spNo,
	})
	if err != nil {
		return errors.New("fail to get approval detail: " + err.Error()), nil
	}

	res, err = json.Marshal(response)
	if err != nil {
		return
	}

	return
}
```

## 3. Usage2 接收企业微信服务端消息

企业微信服务器认证接口

```go
// verifyURL 验证URL有效性[同步请求] 企业微信审批应用保存回调地址用
func verifyURL(ctx *gin.Context) {
	var err error
	echoStr := ctx.Query("echostr")
	// 验证签名
	if err = wework.ValidSignature(ctx.Query("timestamp"), ctx.Query("nonce"), ctx.Query("msg_signature"),
		conf.Conf.Wework.Token, echoStr); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"errMsg": err, "status": http.StatusInternalServerError})
		return
	}

	// 解密
	var msg []byte
	if _, msg, _, err = wework.AESDecryptMsg(echoStr, conf.Conf.Wework.EncodingAeskey); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"errMsg": err, "status": http.StatusInternalServerError})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"msg": msg, "status": http.StatusOK})
	return
}
```

处理企业微信服务器post过来的消息

```go
// handleWeworkOrder 处理单个企业微信工单 [错误全部在这一层记录，千万不可以传到上层协程中，否则将会引发ctx并发安全问题]
func handleWeworkOrder(ctx *gin.Context) {
	reqData, err := ctx.GetRawData()
	if err != nil {
		log.Log.Error(errors.Wrapf(err, "%v", ErrParseMsgFromWeworkServer))
		return
	}
	if len(reqData) == 0 {
		log.Log.Error(errors.Wrapf(err, "%v", ErrGetNilMsgFromWeworkServer))
		return
	}

	// 解密消息
	msg, err := wework.DecryptMsg(ctx.Query("timestamp"), ctx.Query("nonce"), ctx.Query("msg_signature"),
		conf.Conf.Wework.Token, conf.Conf.Wework.EncodingAeskey, reqData)
	if err != nil {
		log.Log.Error(errors.Wrap(err, "文件解密失败"))
		return
	}

	// 判断工单不在自动工单清单中，直接返回 上层不打印这个错误
	topic, isOrderExist := cache.IsOrderExist(msg.ApprovalInfo.SpName)
	if !isOrderExist {
		if gin.IsDebugging() {
			log.Log.Warning(WarnNoRecordAutoOrder)
		}
		return
	}

	// 企业微信消息去重 使用FromUsername和CreateTime联合判断
	isReqExist, err := cache.ZExist(conf.Conf.Redis.ReqCacheKey, strconv.Itoa(int(msg.CreateTime)))
	if err != nil {
		log.Log.Error(err)
		return
	}
	if !isReqExist { // 若缓存中未存这个请求 若存在此请求直接忽略
		log.Log.Info(msg.ApprovalInfo.SpName, " ", msg.ToUsername, " ", msg.CreateTime)
		// 将工单企业微信ID+工单创建时间组成的唯一值存入缓存 用来去重
		if err = cache.ZAdd(conf.Conf.Redis.ReqCacheKey, msg.ToUsername+strconv.Itoa(int(msg.CreateTime))); err != nil {
			log.Log.Error(err)
			return
		}

		// 将工单详情存储到MQ
		err, data := GetOrderDetail(msg.ApprovalInfo.SpNo)
		if err != nil {
			log.Log.Error(errors.Wrap(err, "查询工单详情报错"))
			return
		}
		tag, err := utils.CovertHanzToPinYin(msg.ApprovalInfo.SpName)
		if err != nil {
			log.Log.Error(errors.Wrap(err, "转换汉字错误"))
			return
		}
		err = mq.Send(topic, tag, []string{msg.ToUsername + strconv.Itoa(int(msg.CreateTime))}, data)
		if err != nil {
			log.Log.Error(errors.Wrap(err, "存储到MQ报错"))
			return
		}
	}

	return
}
```

