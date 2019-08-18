package main

import (
	"fmt"
	"os"

	"github.com/ilyaluk/bastion/internal/server"
)

func main() {
	if err := server.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
