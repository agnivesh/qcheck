// Command qcheck reports whether a website's TLS is post-quantum ready: whether
// its TLS 1.3 handshake negotiates a hybrid post-quantum key exchange, which is
// what defends recorded traffic against a future quantum adversary.
package main

import "os"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
