package unescape

import "testing"

func TestNginx(t *testing.T) {
	if out, err := Nginx(nil); err != nil || len(out) > 0 {
		t.Fatalf("non-empty output from empty input: %v, %v", out, err)
	}
	b := []byte(`foo\x09.bar\x5C?baz`)
	exp := []byte("foo\t.bar\\?baz")
	out, err := Nginx(b)
	if err != nil {
		t.Fatal(err)
	}
	cmp(t, out, exp)
}

func TestNginxMalformed(t *testing.T) {
	type testCase struct {
		in, exp []byte
	}
	table := []testCase{
		testCase{
			in:  []byte(`malformed line \x2, here`),
			exp: []byte("malformed line "),
		},
		testCase{
			in:  []byte(`malformed line \2, here`),
			exp: []byte("malformed line "),
		},
	}
	for _, tc := range table {
		out, err := Nginx(tc.in)
		if err != ErrShortScan {
			t.Errorf("error should be ErrShortScan, got: %v", err)
		}
		cmp(t, out, tc.exp)
	}
}

func TestNginxNoop(t *testing.T) {
	b := []byte("safe string")
	out, err := Nginx(b)
	if err != nil {
		t.Fatal(err)
	}
	cmp(t, out, b)
}

func TestNginxUnsafe(t *testing.T) {
	b := []byte(`foo\x09.bar`)
	b = append(b, 0x0)
	b = append(b, `\x5C?baz`...)
	exp := []byte("foo\t.bar")
	out, err := NginxUnsafe(b)
	if err != ErrNotEscaped {
		t.Errorf("error should be ErrNotEscaped, got: %v", err)
	}
	cmp(t, out, exp)
}

func BenchmarkNginx(b *testing.B) {
	for i := 0; i < b.N; i++ {
		out, err := Nginx(longLineEscaped)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) == 0 {
			b.Fatal("zero length")
		}
	}
}

func BenchmarkNginxNoop(b *testing.B) {
	for i := 0; i < b.N; i++ {
		out, err := Nginx(longLineClean)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) == 0 {
			b.Fatal("zero length")
		}
	}
}

func cmp(t *testing.T, out, exp []byte) {
	if len(out) != len(exp) {
		t.Fatalf("length mismatch, want %d, got %d: '%s'",
			len(exp), len(out), out)
	}
	for i, x := range out {
		if x != exp[i] {
			t.Errorf("invalid byte at pos %d: got %#x, want %#x",
				i, x, exp[i])
		}
	}
}

var (
	longLineClean     = []byte(`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko`)
	longLineEscaped   = []byte(`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like\x5CGecko`)
	longLineUnescaped = []byte(`Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like\Gecko`)
)
