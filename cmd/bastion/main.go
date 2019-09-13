package main

import (
	"fmt"
	"os"

	"github.com/ilyaluk/bastion/internal/bastion"
)

func main() {
	if err := bastion.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
