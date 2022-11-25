package token

import (
	"crypto"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Token struct {
	Header  map[string]string
	Payload map[string]any
	Secret  string
	TTL     float64
}

var defHeader = map[string]string{
	"alg": "HS256",
	"typ": "JWT",
}

func encodeBase64(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func decodeBase64(data []byte) ([]byte, error) {
	var res = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	var len int
	var err error

	len, err = base64.URLEncoding.WithPadding('=').Decode(res, data)
	if err != nil {
		return res, err
	}
	if len == 0 {
		return res, errors.New("invali data")
	}
	return []byte(strings.TrimRight(string(res), "\x00")), err
}

func encodeAndTrimPadding(data []byte, padding string) string {
	return strings.TrimRight(encodeBase64(data), "=")
}

func hamcsha256(data string, key []byte) []byte {
	hasher := hmac.New(crypto.SHA256.New, key)
	hasher.Write([]byte(data))
	return []byte(encodeAndTrimPadding(hasher.Sum(nil), "="))
}

func jsonDecode(data string, v any) error {
	var err error

	err = json.Unmarshal([]byte(data), v)
	return err
}

func jsonEncode(v any) ([]byte, error) {
	var err error
	var res []byte

	res, err = json.Marshal(v)
	return res, err
}

func (t *Token) GetJWT() (string, error) {
	var err error
	var header string
	var payload string
	var sign string
	var j []byte

	if j, err = jsonEncode(t.Header); err != nil {
		return "", err
	}
	header = encodeAndTrimPadding(j, "=")
	if j, err = jsonEncode(t.Payload); err != nil {
		return "", err
	}
	payload = encodeAndTrimPadding(j, "=")
	body := header + "." + payload
	sign = string(hamcsha256(body, []byte(t.Secret)))
	return body + "." + sign, nil
}

func VerifyJWT(jwt string, secrete string) (bool, error) {
	var pieces []string
	var sign string
	var body string

	pieces = strings.Split(jwt, ".")
	if len(pieces) != 3 {
		return false, errors.New("invalid token")
	}
	body = pieces[0] + "." + pieces[1]
	sign = string(hamcsha256(body, []byte(secrete)))
	return sign == pieces[2], nil
}

func decodePiece(piece string) ([]byte, error) {
	if l := len(piece) % 4; l > 0 {
		piece += strings.Repeat("=", 4-l)
	}
	return decodeBase64([]byte(piece))
}
func ExtractDataFromToken(token string, t *Token) error {
	var pieces []string
	var header []byte
	var payload []byte
	var err error

	pieces = strings.Split(token, ".")
	if len(pieces) < 3 {
		return errors.New("invalid token")
	}
	if header, err = decodePiece(pieces[0]); err != nil {
		return err
	}
	if err = jsonDecode(string(header), &t.Header); err != nil {
		return err
	}
	if payload, err = decodePiece(pieces[1]); err != nil {
		return err
	}
	if err = jsonDecode(string(payload), &t.Payload); err != nil {
		return err
	}
	return nil
}

func getNow() float64 {
	return float64(time.Now().Unix())
}

func (t *Token) IsValid() bool {
	if t.Payload["exp"] != nil {
		if (t.Payload["exp"].(float64)) > getNow() {
			if t.Payload["exp"].(float64)-getNow() < t.TTL {
				return true
			}
		}
	} else if t.Payload["iat"] != nil {
		if (t.Payload["iat"].(float64)) > getNow()-t.TTL {
			return true
		}
	}
	return false
}

func ParseToken(token string, secret string, ttl float64) (*Token, error) {
	var err error
	var ok bool
	var t = &Token{Secret: secret, TTL: ttl}

	if ok, err = VerifyJWT(token, secret); err != nil {
		return t, err
	}
	if !ok {
		return t, errors.New("ivalid token")
	}
	err = ExtractDataFromToken(token, t)
	return t, err
}

func compare(v1 any, v2 any) bool {
	switch v1.(type) {
	case map[string]string:
		if len(v1.(map[string]string)) != len(v2.(map[string]string)) {
			return false
		}
		for key, val := range v1.(map[string]string) {
			if v2.(map[string]string)[key] != val {
				return false
			}
		}

	case map[string]interface{}:
		if len(v1.(map[string]any)) != len(v2.(map[string]any)) {
			return false
		}
		for key, val := range v1.(map[string]any) {
			if v2.(map[string]any)[key] != val {
				return false
			}
		}

	}
	return true
}

func NewToken(header map[string]string, payload map[string]any, secret string, ttl int64) *Token {
	if header == nil {
		header = defHeader
	}
	ttl = int64(time.Duration(ttl) * time.Minute)
	ttl /= int64(time.Duration(time.Second.Nanoseconds()))
	payload["iat"] = getNow()
	payload["exp"] = (payload["iat"]).(int64) + ttl
	return &Token{header, payload, secret, float64(ttl)}
}
