package token

import (
	"strings"
	"testing"
	"time"
)

func TestTokens_createJWT(t *testing.T) {
	var token *Token
	var tests = []struct {
		data   map[string]any
		secret string
		want   string
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}, secret: "some", want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsIm5hbWUiOiJKb2huIERvZSIsInN1YiI6IjEyMzQ1Njc4OTAifQ.O12uDkFrzFuureZSqyd26utdFdXjwQprI9jXEcau_RQ"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: "", want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkxMjIsIm5hbWUiOiJUb20gQ3J1c2UiLCJzdWIiOiJzdW1faWQifQ.kVE-r-VBKvji80jujSXCwLZC4U-Ow5xJXMyvY4ARZ3I"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: "i2jm34dyuj", want: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkxMjIsIm5hbWUiOiJUb20gQ3J1c2UiLCJzdWIiOiJzdW1faWQifQ.4Ow_dsJ-8g8M3-FEn23vkynMZbPXazGHMtQnqQI_x0w"},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		got, _ := token.GetJWT()
		if got != tt.want {
			t.Errorf("createJWT(%v, %s) = %s; want %s", tt.data, tt.secret, got, tt.want)
		}
	}
}

func TestTokens_verifyJWT(t *testing.T) {
	var token *Token
	var want bool = true
	var tests = []struct {
		data   map[string]any
		secret string
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}, secret: "some"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: ""},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: "i2jm34dyuj"},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		jwt, _ := token.GetJWT()
		got, _ := VerifyJWT(jwt, tt.secret)
		if got != want {
			t.Errorf("varifyJWT(%v, %s) = %v; want %v", tt.data, tt.secret, got, want)
		}
	}
}

func TestTokens_verifyJWT_bad(t *testing.T) {
	var token *Token
	var want bool = false
	var tests = []struct {
		data   map[string]any
		secret string
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}, secret: "some"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: ""},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: "i2jm34dyuj"},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		jwt, _ := token.GetJWT()
		jwt = strings.Replace(jwt, "a", "b", -1)
		got, _ := VerifyJWT(jwt, tt.secret)
		if got != want {
			t.Errorf("verifyJWT(%v, %s) = %v; want %v", tt.data, tt.secret, got, want)
		}
	}
}

func TestTokens_verifyJWT_notValid(t *testing.T) {
	var token *Token
	var want bool = false
	var tests = []struct {
		data   map[string]any
		secret string
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": 1516239022}, secret: "some"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: ""},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": 1516239122}, secret: "i2jm34dyuj"},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		jwt, _ := token.GetJWT()
		jwt = strings.Replace(jwt, ".", "", 1)
		got, err := VerifyJWT(jwt, tt.secret)
		if got != want && err == nil {
			t.Errorf("verifyJWT(%v, %s) = %v; want %v", tt.data, tt.secret, got, err.Error())
		}
	}
}

func TestTokens_NewFromToken(t *testing.T) {
	var token *Token
	var tests = []struct {
		data   map[string]any
		secret string
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": float64(time.Now().Unix())}, secret: "some"},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": float64(time.Now().Unix())}, secret: ""},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": float64(time.Now().Unix())}, secret: "i2jm34dyuj"},
	}

	for _, tt := range tests {
		token = &Token{defHeader, tt.data, tt.secret, float64(time.Duration(15) * time.Minute)}
		jwt, _ := token.GetJWT()
		got, _ := ParseToken(jwt, tt.secret, 0)

		if !compare(got.Header, token.Header) || !compare(got.Payload, token.Payload) {
			t.Errorf("NewFromToken(%v, %s) = %v", jwt, tt.secret, got)
		}
	}
}

func TestTokens_NewFromToken_iat(t *testing.T) {
	var token *Token
	var tests = []struct {
		data   map[string]any
		secret string
		want   bool
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "iat": int64(time.Now().Unix() - int64(time.Duration(20)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "some", want: false},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": int64(time.Now().Unix() - int64(time.Duration(10)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "", want: true},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "iat": int64(time.Now().Unix() - int64(time.Duration(19)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "i2jm34dyuj", want: false},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		jwt, _ := token.GetJWT()
		ttl := time.Duration(15) * time.Minute / time.Duration(time.Second.Nanoseconds())
		tok, _ := ParseToken(jwt, tt.secret, float64(ttl))

		if tok.IsValid() != tt.want {
			t.Errorf("isValid(); %v - %v", tt.data["iat"], int64(getNow()-tok.TTL))
		}
	}
}

func TestTokens_NewFromToken_exp(t *testing.T) {
	var token *Token
	var tests = []struct {
		data   map[string]any
		secret string
		want   bool
	}{
		{data: map[string]any{"sub": "1234567890", "name": "John Doe", "exp": int64(time.Now().Unix() - int64(time.Duration(20)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "some", want: false},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "exp": int64(time.Now().Unix() - int64(time.Duration(10)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "", want: false},
		{data: map[string]any{"sub": "sum_id", "name": "Tom Cruse", "exp": int64(time.Now().Unix() + int64(time.Duration(19)*time.Minute/time.Duration(time.Second.Nanoseconds())))}, secret: "i2jm34dyuj", want: false},
	}

	for _, tt := range tests {
		token = &Token{
			Header:  defHeader,
			Payload: tt.data,
			Secret:  tt.secret,
		}
		jwt, _ := token.GetJWT()
		ttl := time.Duration(15) * time.Minute / time.Duration(time.Second.Nanoseconds())
		tok, _ := ParseToken(jwt, tt.secret, float64(ttl))

		if tok.IsValid() != tt.want {
			t.Errorf("isValid(); %v - %v", tt.data["exp"], int64(getNow()-tok.TTL))
		}
	}
}
