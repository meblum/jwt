package jwt

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

var invalidTokens = []struct {
	token    string
	errorMsg string
}{
	{
		token:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjIzNCIsImVtYWlsIjoiMTIzNEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjEyMzQiLCJuYW1lIjoiRm9vIEJhciIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS0vMTIzNCIsImdpdmVuX25hbWUiOiJGb28iLCJmYW1pbHlfbmFtZSI6IkJhciIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjQ2NjE3MDE0LCJleHAiOjI2NDY2MjA2MTR9.3ibZ72byYD13d9gzn21afOSdnu1WhnIP-308XlzvukDWF0eY_ZfDDPye6TyAqWWgg1YoZpDF8ZXB-lZmCa7JVbqz1-G_fKPaUHLK3H00BXfTPvhQYGBqkghr1oI_PtV8K-z2uUzzlgx264BVaurhe6EWwsiE54TAK8LIGda-cML3nqTBXel5HdExji1dE9Gjq8LmjOse_iaFzmvMfmIrrupuzJMMmQ-NXrQsgbWgO2e2qSmcDzcCT5Y6cP-DCOO7QqweH8niJ_2_LuJG_vTFyzl0TmswU8CbouZh9SS2SQTsqHXinkwID-X6n2bxLiejQ3dYeIZ4bxpGSavNbtDX6w",
		errorMsg: "invalid signature",
	},
	{
		token:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEyMzQiLCJlbWFpbCI6IjEyMzRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIxMjM0IiwibmFtZSI6IkZvbyBCYXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtLzEyMzQiLCJnaXZlbl9uYW1lIjoiRm9vIiwiZmFtaWx5X25hbWUiOiJCYXIiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY0NjYxNzAxNCwiZXhwIjo2NDY2MjA2MTR9.X10Eg5n--I2s2V4ibdNRF-_xk9AcysOK4uYmUOukFP2mRQvFO8pvewANBc4FMeMFxbc4g65CpYRShQCGGS5knRtGreccKMNycGbcOIMdJ_Pq56obByjPVcxLkqHrEQ7_YLI9ZBc-N5P53fQuuJJHEi_eBZNdzQFJk1lN2tYXO4Nfdm0eYTczMUSZgA5cEIZX9D1VpB0jn29CsxXiQJlr-lHNk5k-nShpzvPLxeMpTBCmTXukg6hBb4dvrfD1qlMjfhoBmetQ1_v874WztAyiMABwz9bjh9rb4e5386UPMBIWuQYm39DOvIjcUjcFoKQcrM9cT9Cnain7w_bDLh-nMw",
		errorMsg: "expired token",
	},
	{
		token:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEyMzQiLCJlbWFpbCI6IjEyMzRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIxMjM0IiwibmFtZSI6IkZvbyBCYXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtLzEyMzQiLCJnaXZlbl9uYW1lIjoiRm9vIiwiZmFtaWx5X25hbWUiOiJCYXIiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY0NjYxNzAxNCwiZXhwIjoyNjQ2NjIwNjE0fQ.",
		errorMsg: "malformed token",
	},
	{
		token:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jbyIsImF6cCI6IjEyMzQuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTIzNCIsImVtYWlsIjoiMTIzNEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjEyMzQiLCJuYW1lIjoiRm9vIEJhciIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS0vMTIzNCIsImdpdmVuX25hbWUiOiJGb28iLCJmYW1pbHlfbmFtZSI6IkJhciIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjQ2NjE3MDE0LCJleHAiOjI2NDY2MjA2MTR9.rlTXC534gPFMY5YamBWdpLuLMbC66NPPXtYw6uTbUEExYfBLvc_6nU5WGbtJzkyL8LhfIxwIDxmFqFm12NxfLeyFPLvl_srTt_MQf8YQuJtqI-Sdw8krENgn4V4jSclWSnQMnxaRMXPyao7Rr81Uw4d2EkcjMjB5kS427RzDY54_u4rxRkcPm2llvyZiREAp20iCu_Fr4SudJaIcE0OmZtnPmZyrNVKxycCXIFecPwkRNd6fxe7kpg9MybPb7jKFB_qA5UUWLR7bNfOhIJ_0FC0eq8AGCSnIXUhOiCnA3SQr0px-YqVrtQTZGSAbdeh8UpuCXWqVdFE-zFH3RITIeQ",
		errorMsg: "invalid issuer",
	},
	{
		token:    "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTIzNCIsImVtYWlsIjoiMTIzNEBnbWFpbC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6IjEyMzQiLCJuYW1lIjoiRm9vIEJhciIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS0vMTIzNCIsImdpdmVuX25hbWUiOiJGb28iLCJmYW1pbHlfbmFtZSI6IkJhciIsImxvY2FsZSI6ImVuIiwiaWF0IjoxNjQ2NjE3MDE0LCJleHAiOjI2NDY2MjA2MTR9.EF1YPNuX8xeUMcWqgm15y2bJhb9aG3zUM-K958NnHtO_FJEyw3q0FcP8hwI-dMUcv5eZbeqsZWfmabeLbTT4bvV_rGo5BKqNi--E-9SFmts9GyK30WYMsRPxBEZ3oH9-2XlLDBWpYsbAAc-quYRN7kt3ADAgel7pM2UsIjG023xrxwrXpQhR57gBJ0HzxyiX8vtLg6LxY318Vn53IEFGHKgiaghEUkLm6TL6LeL-phPrftQhgEjEjF6o0t9xlgkW8CTNpbtZuAmvHkb_cdXacsT7g0RpGN6U8pKFOdxBdKtoaUwcPpauIRhd5yA1Bgg3emoMKPY0TBkXE2WWH4h7Dg",
		errorMsg: "invalid audiance",
	},
}

var invalidKeys = []struct {
	key      string
	errorMsg string
}{
	{
		key:      `{"keys": [{"kty":"RSA","e":"","kid":"","n":"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw"}]}`,
		errorMsg: "missing info",
	},
	{
		key:      `{"keys": null}`,
		errorMsg: "keys array null",
	},
	{
		key:      `null`,
		errorMsg: "malformed key",
	},
	{
		key:      `{"keys": []}`,
		errorMsg: "no keys found",
	},
}

const validToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEyMzQiLCJlbWFpbCI6IjEyMzRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIxMjM0IiwibmFtZSI6IkZvbyBCYXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtLzEyMzQiLCJnaXZlbl9uYW1lIjoiRm9vIiwiZmFtaWx5X25hbWUiOiJCYXIiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY0NjYxNzAxNCwiZXhwIjoyNjQ2NjIwNjE0fQ.tgccN6wgxazmstUiL88LKpGkZjfs5kzpl_qT91WDypmyClxVS4sMQng_JS9F2CAtWIS8uDh0r4SXCZLu5lOu7MxIq8q90pv3FgaghC_5zGeYcyRExGJkcy5CdqLQ5M8B5DpFhQA38hhMO5SLAs3r4MNlJYJpetyYLz5oa6PP6ygdrK8R4vsUMiRqJGnOzyaimpPD2st-pLQ2bI-is4W3uE9RVzM1C9yUjTwxovixUkGobtnjefWprZTd9JYxkZp2mzvlQHDjryr8zhJThGXNm50_ClbQGf-76wuTB2GH_iFiC-4QisJtJ1HOutDRmkSSPDaSI8pbc0RUOux0WroKzA"
const validKey = `{"keys": [{"kty":"RSA","e":"AQAB","kid":"f73e9e2b-242e-4842-8809-65ba74800972","n":"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw"}]}`
const testClientID = "1234.apps.googleusercontent.com"

func keyGetterFunc(keySring string) KeyFetcherFunc {
	return func() (r io.ReadCloser, expires time.Time, err error) {
		return io.NopCloser(strings.NewReader(keySring)), time.Now().Add(time.Hour * 24), nil
	}

}

func TestNewVerifier(t *testing.T) {
	_, err := NewVerifier(keyGetterFunc(validKey), testClientID)
	if err != nil {
		t.Errorf("New Verifier failed, %v", err)
	}

	for _, v := range invalidKeys {
		_, err := NewVerifier(keyGetterFunc(v.key), testClientID)
		if err == nil {
			t.Errorf("%v not throwing error", v.errorMsg)
		}
	}

}

func TestParseAndVerify(t *testing.T) {
	ver, _ := NewVerifier(keyGetterFunc(validKey), testClientID)

	_, err := ver.ParseAndVerify(validToken)
	if err != nil {
		t.Errorf("token parse fail, %v", err)
	}

	for _, v := range invalidTokens {
		_, err := ver.ParseAndVerify(v.token)
		if err == nil {
			t.Errorf("%v not throwing error", v.errorMsg)
		}

	}
}

func Example() {
	tokenString := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEyMzQiLCJlbWFpbCI6IjEyMzRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIxMjM0IiwibmFtZSI6IkZvbyBCYXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtLzEyMzQiLCJnaXZlbl9uYW1lIjoiRm9vIiwiZmFtaWx5X25hbWUiOiJCYXIiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY0NjYxNzAxNCwiZXhwIjoyNjQ2NjIwNjE0fQ.tgccN6wgxazmstUiL88LKpGkZjfs5kzpl_qT91WDypmyClxVS4sMQng_JS9F2CAtWIS8uDh0r4SXCZLu5lOu7MxIq8q90pv3FgaghC_5zGeYcyRExGJkcy5CdqLQ5M8B5DpFhQA38hhMO5SLAs3r4MNlJYJpetyYLz5oa6PP6ygdrK8R4vsUMiRqJGnOzyaimpPD2st-pLQ2bI-is4W3uE9RVzM1C9yUjTwxovixUkGobtnjefWprZTd9JYxkZp2mzvlQHDjryr8zhJThGXNm50_ClbQGf-76wuTB2GH_iFiC-4QisJtJ1HOutDRmkSSPDaSI8pbc0RUOux0WroKzA"
	clientID := "1234.apps.googleusercontent.com"

	verifier, err := NewVerifier(DefaultKeyFetcher, clientID)
	if err != nil {
		// handle error
	}

	token, err := verifier.ParseAndVerify(tokenString)

	if err != nil {
		// token invalid, handle error
	}
	fmt.Println(token.Claims.Email)
}

func Example_customKeyGetter() {
	jwk := `{"keys": [{"kty":"RSA","e":"AQAB","kid":"f73e9e2b-242e-4842-8809-65ba74800972","n":"u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw"}]}`
	tokenString := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2U5ZTJiLTI0MmUtNDg0Mi04ODA5LTY1YmE3NDgwMDk3MiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIxMjM0LmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXVkIjoiMTIzNC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsInN1YiI6IjEyMzQiLCJlbWFpbCI6IjEyMzRAZ21haWwuY29tIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsImF0X2hhc2giOiIxMjM0IiwibmFtZSI6IkZvbyBCYXIiLCJwaWN0dXJlIjoiaHR0cHM6Ly9saDMuZ29vZ2xldXNlcmNvbnRlbnQuY29tL2EtLzEyMzQiLCJnaXZlbl9uYW1lIjoiRm9vIiwiZmFtaWx5X25hbWUiOiJCYXIiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY0NjYxNzAxNCwiZXhwIjoyNjQ2NjIwNjE0fQ.tgccN6wgxazmstUiL88LKpGkZjfs5kzpl_qT91WDypmyClxVS4sMQng_JS9F2CAtWIS8uDh0r4SXCZLu5lOu7MxIq8q90pv3FgaghC_5zGeYcyRExGJkcy5CdqLQ5M8B5DpFhQA38hhMO5SLAs3r4MNlJYJpetyYLz5oa6PP6ygdrK8R4vsUMiRqJGnOzyaimpPD2st-pLQ2bI-is4W3uE9RVzM1C9yUjTwxovixUkGobtnjefWprZTd9JYxkZp2mzvlQHDjryr8zhJThGXNm50_ClbQGf-76wuTB2GH_iFiC-4QisJtJ1HOutDRmkSSPDaSI8pbc0RUOux0WroKzA"
	clientID := "1234.apps.googleusercontent.com"

	var keyGetter KeyFetcherFunc = func() (r io.ReadCloser, expires time.Time, err error) {

		return io.NopCloser(strings.NewReader(jwk)), time.Now().Add(time.Hour * 24), nil
	}

	verifier, err := NewVerifier(keyGetter, clientID)
	if err != nil {
		// handle error
	}

	token, err := verifier.ParseAndVerify(tokenString)

	if err != nil {
		// token invalid, handle error
	}
	fmt.Println(token.Claims.Email)
	// Output:
	// 1234@gmail.com
}

func TestExtractMaxAge(t *testing.T) {
	expectedAge := 22572
	cacheCtrlVal := fmt.Sprintf("public, max-age=%v, must-revalidate, no-transform", expectedAge)
	maxAge, err := extractMaxAge(cacheCtrlVal)
	if maxAge != 22572 || err != nil {
		t.Errorf("expected %q for %v, got %v", expectedAge, cacheCtrlVal, maxAge)
	}
}
