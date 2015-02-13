package unescape_test

import (
	"fmt"

	"github.com/artyom/unescape"
)

func ExampleNginx() {
	input := []byte(`foo\x22.bar\x5C?baz`)
	out, err := unescape.Nginx(input)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s\n", out)
	// Output:
	// foo".bar\?baz
}
