package main

import (
	"fmt"
	"os"

	"github.com/theheadmen/goDipl3/client/clientapi"
)

func main() {
	if err := clientapi.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
