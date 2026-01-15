package main

import (
	"fmt"
	"os"

	"github.com/anhdt/golang-enterprise-repo/services/author-service/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
