//go:build linux

package main

import (
	"flag"
	"fmt"
	"github.com/123123213weqw/Xandbox/internal/gateway"
	"os"
)

func main() {
	config := flag.String("config", "", "private root-owned gateway configuration")
	child := flag.Bool("child", false, "internal inherited-capability child")
	flag.Parse()
	var e error
	if flag.NArg() != 0 || (*child && *config != "") || (!*child && *config == "") {
		e = fmt.Errorf("invalid gateway launch")
	} else if *child {
		e = gateway.RunChild()
	} else {
		e = gateway.RunRoot(*config)
	}
	if e != nil { // Never echo policy/path/header/certificate/credential/error details.
		fmt.Fprintln(os.Stderr, "gateway unavailable; ingress closed")
		os.Exit(1)
	}
}
