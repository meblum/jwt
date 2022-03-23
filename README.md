[![Go Reference](https://pkg.go.dev/badge/github.com/meblum/jwt.svg)](https://pkg.go.dev/github.com/meblum/jwt)
# JWT
A tiny and simple Go utility to parse and verify [Google issued](https://developers.google.com/identity/protocols/oauth2/openid-connect) Json Web Tokens.

Please see the [documentation](https://pkg.go.dev/github.com/meblum/jwt).

## Example

```Go
package main

import (
	"fmt"
	"net/http"
	"github.com/meblum/jwt"
)

func main() {
	// errors omitted for brevity

	res, _ := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	verifier, _ := jwt.NewVerifier(res.Body, "your.google.clientID")
	res.Body.Close()

	token, err := verifier.ParseAndVerify("your.jwt.string")

	if err != nil {
		// token invalid, handle error
	}
	fmt.Println(token)
}
```

## Licence

```
MIT License

Copyright (c) 2022 Meir Blumenfeld

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
