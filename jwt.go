package jwt

import (
	"context"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // link into binary
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Verifier struct {
	keys     *keyCache
	clientID string
	issuer   string
}

// NewVerifier returns a Verifier which parses and verifies Google issued tokens.
// Tokens will be verified with keys supplied by keyFetcher and checked that their subject matches clientID.
func NewVerifier(keyFetcher KeyFetcherFunc, clientID string) (*Verifier, error) {

	c, err := newKeyCache(keyFetcher)

	if err != nil {
		err = fmt.Errorf("create key cache - %v", err)
	}

	v := &Verifier{
		keys:     c,
		clientID: clientID,
		issuer:   "https://accounts.google.com",
	}

	return v, err

}

// ParseAndVerify returns a Go representation of a Google issued tokenString.
// A non-nil error implies that the token is invalid.
func (v *Verifier) ParseAndVerify(tokenString string) (*JWT, error) {
	//TODO If you specified a hd parameter value in the request, verify that the ID token has a hd claim that matches an accepted G Suite hosted domain.
	var err error

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 || parts[2] == "" {
		return nil, fmt.Errorf("malformed token %v", tokenString)
	}

	var parsedToken *JWT
	if parsedToken, err = parseJWT(parts); err != nil {
		return parsedToken, fmt.Errorf("decode token %v - %v", parts, err)
	}

	if parsedToken.Header.ALG != "RS256" {
		return parsedToken, fmt.Errorf("expected alg RS256, but token alg is %v", parsedToken.Header.ALG)
	}

	key, err := v.keys.retrieveKey(parsedToken.Header.KID)

	if err != nil {
		return parsedToken, fmt.Errorf("retrieve key - %v", err)
	}

	if key == nil {
		return parsedToken, fmt.Errorf("matching key not found")
	}

	if err = verifySignature(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		return parsedToken, fmt.Errorf("verify signature - %v", err)
	}

	if parsedToken.Claims.ISS != v.issuer {
		return parsedToken, fmt.Errorf("invalid issuer")
	}

	if parsedToken.Claims.AUD != v.clientID {
		return parsedToken, fmt.Errorf("client ID does not match")
	}
	if parsedToken.Claims.EXP <= time.Now().Unix() {
		return parsedToken, fmt.Errorf("token expired")
	}

	return parsedToken, nil
}

func verifySignature(signedString, signature string, key *rsa.PublicKey) error {
	var err error

	var sig []byte
	if sig, err = base64.RawURLEncoding.DecodeString(signature); err != nil {
		return fmt.Errorf("unable to base64 decode signature %v, %v", signature, err)
	}

	if !crypto.SHA256.Available() {
		return fmt.Errorf("SHA256 unavailable")
	}
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(signedString))

	if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hasher.Sum(nil), sig); err != nil {
		err = fmt.Errorf("signature verification failed, %v", err)
	}
	return err
}

type JWT struct {
	Header struct {
		ALG string `json:"alg"`
		KID string `json:"kid"`
		TYP string `json:"typ"`
	}
	Claims struct {
		ISS           string `json:"iss"`
		AZP           string `json:"azp"`
		AUD           string `json:"aud"`
		SUB           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		ATHash        string `json:"at_hash"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Locale        string `json:"locale"`
		Nonce         string `json:"nonce"`
		Profile       string `json:"profile"`
		HD            string `json:"hd"`
		IAT           int64  `json:"iat"`
		EXP           int64  `json:"exp"`
	}
	Signature string
}

func parseJWT(tokenParts []string) (*JWT, error) {

	h, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode %v, %v", tokenParts[0], err)
	}

	var token = JWT{}

	if err = json.Unmarshal(h, &token.Header); err != nil {
		return nil, fmt.Errorf("unable to json decode %v, %v", h, err)
	}

	c, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, fmt.Errorf("unable to base64 decode %v, %v", tokenParts[1], err)
	}

	if err = json.Unmarshal(c, &token.Claims); err != nil {
		return nil, fmt.Errorf("unable to json decode %v, %v", c, err)
	}

	token.Signature = tokenParts[2]

	return &token, nil
}

type KeyFetcherFunc func() (r io.ReadCloser, expires time.Time, err error)

type keyCache struct {
	keyFetcher KeyFetcherFunc
	publicKeys map[string]*rsa.PublicKey
	keyExpire  time.Time
}

func newKeyCache(keyFetcherFunc KeyFetcherFunc) (*keyCache, error) {

	k := &keyCache{
		keyFetcher: keyFetcherFunc,
	}

	if _, err := k.retrieveKey(""); err != nil {
		return k, fmt.Errorf("get key - %v", err)
	}

	return k, nil
}

// UpdatePublicKey sets the verifier public key to the key obtained from jwksReader.
func (v *keyCache) UpdatePublicKey(jwksReader io.Reader, expiration time.Time) error {
	m := make(map[string]*rsa.PublicKey)
	jwks, err := parseJWKS(jwksReader)

	if err != nil {
		return fmt.Errorf("unable to parse JWKS %v", err)
	}

	for _, v := range jwks.Keys {
		if v.E == "" || v.N == "" || v.KID == "" {
			return fmt.Errorf("missing info in JWK %v", v)
		}
		decodedN, err := base64.RawURLEncoding.DecodeString(v.N)
		if err != nil {
			return fmt.Errorf("unable to base64 decode jwk n value %v, %v", v.N, err)
		}
		decodedE, err := base64.RawURLEncoding.DecodeString(v.E)
		if err != nil {
			return fmt.Errorf("unable to base64 decode jwk e value %v, %v", v.E, err)
		}

		n := big.NewInt(0).SetBytes(decodedN)

		e := big.NewInt(0).SetBytes(decodedE).Uint64()

		m[v.KID] = &rsa.PublicKey{
			N: n,
			E: int(e),
		}
	}
	if len(m) == 0 {
		return fmt.Errorf("no public keys %v", jwks)
	}

	v.publicKeys = m
	v.keyExpire = expiration
	return nil
}

// keyFetcher updates the key cache if it's expired and returns the requested key. If key is not in cache, nil is returned.
func (v *keyCache) retrieveKey(kid string) (*rsa.PublicKey, error) {
	if v.keyExpire.Before(time.Now()) {
		reader, expires, err := v.keyFetcher()
		if err != nil {
			return nil, fmt.Errorf("fetch key - %v", err)
		}
		defer reader.Close()
		if err = v.UpdatePublicKey(reader, expires); err != nil {
			return nil, fmt.Errorf("update key cache - %v", err)
		}
	}

	return v.publicKeys[kid], nil
}

// DefaultKeyFetcher does an http request to obtain the google public certificates, the request times out after 10 seconds.
// returns the response body and its max-age.
func DefaultKeyFetcher() (r io.ReadCloser, expires time.Time, err error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelFunc()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.googleapis.com/oauth2/v3/certs", nil)
	if err != nil {
		return nil, time.Now(), fmt.Errorf("create request - %v", err)
	}
	res, err := http.DefaultClient.Do(req)

	if err != nil {
		return nil, time.Now(), fmt.Errorf("request - %v", err)
	}

	age, err := extractMaxAge(res.Header.Get("cache-control"))
	if err != nil {
		return nil, time.Now(), fmt.Errorf("get max-age - %v", err)
	}

	return res.Body, time.Now().Add(time.Second * time.Duration(age)), nil
}

// extractMaxAge returns the max-age value from an cache-control http response header or an error if finding a max-age failed.
func extractMaxAge(cacheCtrlValue string) (int, error) {
	cacheValues := strings.Split(cacheCtrlValue, ", ")
	for _, v := range cacheValues {
		if strings.HasPrefix(v, "max-age") {
			maxAgeStr := strings.Split(v, "=")[1]
			maxAge, err := strconv.Atoi(maxAgeStr)
			if err != nil {
				return 0, fmt.Errorf("convert max-age value %v to number - %v", maxAgeStr, err)
			}
			return maxAge, nil
		}
	}
	return 0, fmt.Errorf("max-age not found in %v", cacheCtrlValue)
}

type jwks struct {
	Keys []struct {
		// alg string
		N   string `json:"n"`
		E   string `json:"e"`
		KID string `json:"kid"`
		// kty string
		// use string
	} `json:"keys"`
}

func parseJWKS(r io.Reader) (*jwks, error) {
	var keys = new(jwks)
	err := json.NewDecoder(r).Decode(keys)
	if err != nil {
		err = fmt.Errorf("decoing json %v - %v", r, err)
	} else if keys.Keys == nil {
		err = fmt.Errorf("empty key list %v", r)
	}

	return keys, err
}
