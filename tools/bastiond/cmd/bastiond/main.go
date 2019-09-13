package main

import (
	"fmt"
	"os"

	"github.com/ilyaluk/bastion/tools/bastiond/internal/bastiond"
)

func main() {
	if err := bastiond.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
