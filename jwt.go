package jwt

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // link into binary
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

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
		err = fmt.Errorf("error decoing json %v,%v", r, err)
	}
	if keys == nil {
		err = fmt.Errorf("no keys in json %v", r)
	}
	return keys, err
}

type Verifier struct {
	publicKeys map[string]*rsa.PublicKey
	clientID   string
	issuer     string
}

// NewVerifier returns a Verifier which will can parse and verify Google issued tokens.
// Tokens will be verified with keys supplied by jwksReader and checked that their subject matches clientID.
func NewVerifier(jwksReader io.Reader, clientID string) (*Verifier, error) {

	v := &Verifier{
		clientID: clientID,
		issuer:   "https://accounts.google.com",
	}
	err := v.UpdatePublicKey(jwksReader)

	if err != nil {
		return nil, fmt.Errorf("unable to set public key, %v", err)
	}

	return v, nil

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
		return parsedToken, fmt.Errorf("unable to decode token %v, %v", parts, err)
	}

	if parsedToken.Header.ALG != "RS256" {
		return parsedToken, fmt.Errorf("expected alg RS256, but token alg is %v", parsedToken.Header.ALG)
	}

	key, ok := v.publicKeys[parsedToken.Header.KID]

	if !ok {
		return parsedToken, fmt.Errorf("matching key not found")
	}

	if err = verifySignature(strings.Join(parts[0:2], "."), parts[2], key); err != nil {
		return parsedToken, fmt.Errorf("unable to verify signature, %v", err)
	}

	if parsedToken.Claims.ISS != v.issuer {
		return parsedToken, fmt.Errorf("invalid issuer")
	}

	if parsedToken.Claims.AUD != v.clientID {
		return parsedToken, fmt.Errorf("client IDS do not match")
	}
	if parsedToken.Claims.EXP <= time.Now().Unix() {
		return parsedToken, fmt.Errorf("token expired")
	}

	return parsedToken, nil
}

func (v *Verifier) UpdatePublicKey(jwksReader io.Reader) error {
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
	return nil
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
