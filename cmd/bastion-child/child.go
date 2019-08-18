package main

import (
	"fmt"
	"os"

	"github.com/ilyaluk/bastion/internal/child"
)

func main() {
	if err := child.Run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
