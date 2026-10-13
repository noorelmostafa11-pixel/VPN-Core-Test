//go:build testprobe

package main

import (
	"bufio"
	"fmt"
	"github.com/noorelmostafa11-pixel/VPN-Core-Test/core"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	kind := "crypto"
	name := filepath.Base(os.Args[0])
	if strings.Contains(name, "protocol") {
		kind = "protocol"
	} else if strings.Contains(name, "uri") {
		kind = "uri"
	}
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 10485760)
	for s.Scan() {
		out, e := core.TestProbe(kind, s.Text())
		if e != nil {
			if kind == "uri" {
				fmt.Println(`{"error":"CONFIG_VALIDATION_INVALID"}`)
			} else {
				fmt.Println("ERROR:", e)
			}
		} else {
			fmt.Println(out)
		}
	}
}
