package wework

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// RecMsg 企业微信系统发送的消息
type RecMsg struct {
	ToUsername string `xml:"ToUserName"`
	Encrypt    string `xml:"Encrypt"`
	AgentId    string `xml:"AgentID"`
}

// MsgContent 消息内容
type MsgContent struct {
	ToUsername   string `xml:"ToUserName" json:"ToUserName"`
	FromUsername string `xml:"FromUserName" json:"FromUserName"`
	CreateTime   uint32 `xml:"CreateTime" json:"CreateTime"`
	MsgType      string `xml:"MsgType" json:"MsgType"`
	Event        string `xml:"Event" json:"Event"`
	AgentID      uint32 `xml:"AgentID" json:"AgentID"`

	ApprovalInfo struct {
		SpNo       uint64 `xml:"SpNo" json:"SpNo"`
		SpName     string `xml:"SpName" json:"SpName"`
		SpStatus   uint8  `xml:"SpStatus" json:"SpStatus"`
		TemplateId string `xml:"TemplateId" json:"TemplateId"`
		ApplyTime  uint32 `xml:"ApplyTime" json:"ApplyTime"`
		Applyer    struct {
			UserId string `xml:"UserId" json:"UserId"`
			Party  uint32 `xml:"Party" json:"Party"`
		} `xml:"Applyer" json:"Applyer"`
		SpRecord struct {
			SpStatus     uint32 `xml:"SpStatus" json:"SpStatus"`
			ApproverAttr uint32 `xml:"ApproverAttr" json:"ApproverAttr"`
			Details      struct {
				Approver struct {
					UserId string `xml:"UserId" json:"UserId"`
				} `xml:"Approver" json:"Approver"`
				Speech   []string `xml:"Speech" json:"Speech"`
				SpStatus uint32   `xml:"SpStatus" json:"SpStatus"`
				SpTime   uint32   `xml:"SpTime" json:"SpTime"`
			} `xml:"Details" json:"Details"`
		} `xml:"SpRecord" json:"SpRecord"`
		StatuChangeEvent uint32 `xml:"StatuChangeEvent" json:"StatuChangeEvent"`
	} `xml:"ApprovalInfo" json:"ApprovalInfo"`
}

/*
随机字符串逻辑
*/

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GetRandStringWithCharset 获取指定字符集下 指定长度的随机字符串
func GetRandStringWithCharset(length int, charset string) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// GetRandString 获取指定长度的随机字符串
func GetRandString(length int) string {
	return GetRandStringWithCharset(length, charset)
}

/*
加解密核心逻辑
*/

// 把整数 n 格式化成 4 字节的网络字节序
func encodeNetworkByteOrder(b []byte, n uint32) {
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
}

// 从 4 字节的网络字节序里解析出整数
func decodeNetworkByteOrder(b []byte) (n uint32) {
	return uint32(b[0])<<24 |
		uint32(b[1])<<16 |
		uint32(b[2])<<8 |
		uint32(b[3])
}

// AESEncryptMsg 消息加密
// ciphertext = AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
func AESEncryptMsg(random, rawXMLMsg []byte, appId string, encodingAESKey string) (ciphertext string, err error) {
	aesKey, _ := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	const (
		BLOCK_SIZE = 32             // PKCS#7
		BLOCK_MASK = BLOCK_SIZE - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	appIdOffset := 20 + len(rawXMLMsg)
	contentLen := appIdOffset + len(appId)
	amountToPad := BLOCK_SIZE - contentLen&BLOCK_MASK
	plaintextLen := contentLen + amountToPad

	plaintext := make([]byte, plaintextLen)

	// 拼接
	copy(plaintext[:16], random)
	encodeNetworkByteOrder(plaintext[16:20], uint32(len(rawXMLMsg)))
	copy(plaintext[20:], rawXMLMsg)
	copy(plaintext[appIdOffset:], appId)

	// PKCS#7 补位
	for i := contentLen; i < plaintextLen; i++ {
		plaintext[i] = byte(amountToPad)
	}

	// 加密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}
	mode := cipher.NewCBCEncrypter(block, aesKey[:16])
	mode.CryptBlocks(plaintext, plaintext)

	return base64.StdEncoding.EncodeToString(plaintext), nil
}

// AESDecryptMsg 消息解密
// ciphertext = AES_Encrypt[random(16B) + msg_len(4B) + rawXMLMsg + appId]
func AESDecryptMsg(base64CipherText string, encodingAESKey string) (random, rawXMLMsg, appId []byte, err error) {
	ciphertext, err := base64.StdEncoding.DecodeString(base64CipherText)
	if err != nil {
		return
	}

	aesKey, err := base64.StdEncoding.DecodeString(encodingAESKey + "=")
	if err != nil {
		return
	}

	const (
		BLOCK_SIZE = 32             // PKCS#7
		BLOCK_MASK = BLOCK_SIZE - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	if len(ciphertext) < BLOCK_SIZE {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(ciphertext))
		return
	}
	if len(ciphertext)&BLOCK_MASK != 0 {
		err = fmt.Errorf("ciphertext is not a multiple of the block size, the length is %d", len(ciphertext))
		return
	}

	plaintext := make([]byte, len(ciphertext)) // len(plaintext) >= BLOCK_SIZE

	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}
	mode := cipher.NewCBCDecrypter(block, aesKey[:16])
	mode.CryptBlocks(plaintext, ciphertext)

	// PKCS#7 去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BLOCK_SIZE {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	// 反拼接
	// len(plaintext) == 16+4+len(rawXMLMsg)+len(appId)
	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}
	rawXMLMsgLen := int(decodeNetworkByteOrder(plaintext[16:20]))
	if rawXMLMsgLen < 0 {
		err = fmt.Errorf("incorrect msg length: %d", rawXMLMsgLen)
		return
	}
	appIdOffset := 20 + rawXMLMsgLen
	if len(plaintext) <= appIdOffset {
		err = fmt.Errorf("msg length too large: %d", rawXMLMsgLen)
		return
	}

	random = plaintext[:16:20]
	rawXMLMsg = plaintext[20:appIdOffset:appIdOffset]
	appId = plaintext[appIdOffset:]
	return
}

// AESDecryptData 数据解密
func AESDecryptData(cipherText []byte, aesKey []byte, iv []byte) (rawData []byte, err error) {

	const (
		BLOCK_SIZE = 32             // PKCS#7
		BLOCK_MASK = BLOCK_SIZE - 1 // BLOCK_SIZE 为 2^n 时, 可以用 mask 获取针对 BLOCK_SIZE 的余数
	)

	if len(cipherText) < BLOCK_SIZE {
		err = fmt.Errorf("the length of ciphertext too short: %d", len(cipherText))
		return
	}

	plaintext := make([]byte, len(cipherText)) // len(plaintext) >= BLOCK_SIZE

	// 解密
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, cipherText)

	// PKCS#7 去除补位
	amountToPad := int(plaintext[len(plaintext)-1])
	if amountToPad < 1 || amountToPad > BLOCK_SIZE {
		err = fmt.Errorf("the amount to pad is incorrect: %d", amountToPad)
		return
	}
	plaintext = plaintext[:len(plaintext)-amountToPad]

	// 反拼接
	// len(plaintext) == 16+4+len(rawXMLMsg)+len(appId)
	if len(plaintext) <= 20 {
		err = fmt.Errorf("plaintext too short, the length is %d", len(plaintext))
		return
	}

	rawData = plaintext

	return

}

// ParseRecMsg parse raw messages
func ParseRecMsg(reqData []byte) (res RecMsg, err error) {
	if err := xml.Unmarshal(reqData, &res); nil != err {
		return res, err
	}
	return res, nil
}

// ParseMsgContent parse the message content
func ParseMsgContent(reqData []byte) (res MsgContent, err error) {
	if err := xml.Unmarshal(reqData, &res); nil != err {
		return res, err
	}
	return res, nil
}

// ValidSignature verify signature
func ValidSignature(reqTimestamp, reqNonce, reqMsgSign, token, encrypt string) (err error) {
	strs := []string{
		reqTimestamp,
		reqNonce,
		token,
		encrypt,
	}
	sort.Strings(strs)

	h := sha1.New()
	_, _ = io.WriteString(h, strings.Join(strs, ""))
	signature := fmt.Sprintf("%x", h.Sum(nil))
	if strings.Compare(signature, reqMsgSign) != 0 {
		err = fmt.Errorf("signature err: %s != %s", signature, reqMsgSign)
		return
	}
	return
}

// DecryptMsg decrypt message
func DecryptMsg(reqTimestamp, reqNonce, reqMsgSign, token, aesKey string, reqData []byte) (res MsgContent, err error) {
	// parse the original content
	recMsg, err := ParseRecMsg(reqData)
	if err != nil {
		return
	}
	// verify signature
	if err := ValidSignature(reqTimestamp, reqNonce, reqMsgSign, token, recMsg.Encrypt); err != nil {
		return res, err
	}
	// decrypt message
	_, xmlMsg, _, err := AESDecryptMsg(recMsg.Encrypt, aesKey)
	if err != nil {
		return
	}
	// Parse the content
	res, err = ParseMsgContent(xmlMsg)
	if err != nil {
		return
	}

	return
}

// TruncateRobotMsg Truncate enterprise WeChat robot messages. Divide long messages by line judgment and return message slices.
func TruncateRobotMsg(originalMsg, sep string) (resMsgSegments []string) {
	if len([]byte(originalMsg)) < 4096 {
		resMsgSegments = append(resMsgSegments, originalMsg)
	} else {
		// cut by row
		msgSegments := strings.Split(originalMsg, sep)

		var segment string
		for _, s := range msgSegments {
			countLen := len([]byte(segment + s))
			if countLen > 4096 {
				resMsgSegments = append(resMsgSegments, segment)
				segment = s + sep
			} else {
				segment += s
				segment += sep
			}
		}
		resMsgSegments = append(resMsgSegments, segment) // add the last message
	}
	return
}
