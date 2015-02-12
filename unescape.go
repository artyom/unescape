// Package unescape holds functions to revert nginx escaping, applied to
// variables before putting them to log.
//
// Before using functions of this package you first need to split log line into
// fields and unescape each field separately.
//
// You can safely use quote (", 0x22) character as a field delimiter in custom
// nginx log format.
package unescape

import (
	"bytes"
	"errors"
)

// Nginx unescapes nginx log field value.
//
// This function assumes that input is read from valid log file and does not
// contain any bytes not allowed by ngx_http_log_module.
func Nginx(input []byte) ([]byte, error) { return nginx(input, false) }

// NginxUnsafe unescapes nginx log field value using strict mode.
//
// This function assumes that input is read from untrusted log file and performs
// additional checks to verify each input byte using the same logic as
// ngx_http_log_module.
func NginxUnsafe(input []byte) ([]byte, error) { return nginx(input, true) }

func nginx(input []byte, validate bool) ([]byte, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if !validate {
		if n := bytes.IndexByte(input, '\\'); n < 0 {
			out := make([]byte, len(input))
			copy(out, input)
			return out, nil
		}
	}
	out := make([]byte, 0, len(input))
	var (
		unescape bool // unescape mode flag
		c        byte // intermediate char
		seen     byte // chars seen in unescape mode (max 3, 1st is `x`)
	)
	for _, b := range input {
		if validate {
			if (escape[b>>5] & (1 << (b & 0x1f))) > 0 {
				return out[:len(out):len(out)], ErrNotEscaped
			}
		}
		if !unescape && b == '\\' {
			unescape = true
			seen = 0
			c = 0x0
			continue
		}
		if unescape && seen == 0 {
			if b == 'x' {
				seen++
				continue
			}
			return out[:len(out):len(out)], ErrShortScan
		}
		if unescape && seen > 0 {
			n := bytes.IndexByte(hex, b)
			if n < 0 {
				return out[:len(out):len(out)], ErrShortScan
			}
			if seen == 1 {
				c = byte(n << 4)
				seen++
				continue
			} else if seen == 2 {
				c = c ^ byte(n)
				out = append(out, c)
				unescape = false
				continue
			}
			panic("unreachable")
		}
		out = append(out, b)
	}
	return out[:len(out):len(out)], nil
}

var (
	// ErrShortScan is returned when input has invalid escape sequence
	ErrShortScan = errors.New("unescape: malformed escape sequence")
	// ErrNotEscaped is returned when input has unallowed bytes (i.e. binary
	// garbage in file, etc)
	ErrNotEscaped = errors.New("unescape: input not properly escaped")
)

// vars below taken from ngx_http_log_escape function in
// http/modules/ngx_http_log_module.c

// nginx uses this table to escape chars
var hex = []byte("0123456789ABCDEF")

// nginx table to check whether input byte should be escaped. This table differs
// by allowing \ character in input.
var escape = []uint32{
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	/* 0000 0000 0000 0000  0000 0000 0000 0100 */
	0x00000004,

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	/* 0000 0000 0000 0000  0000 0000 0000 0000 */
	// this was modified against original nginx code to allow \ in input
	0x00000000,

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	/* 1000 0000 0000 0000  0000 0000 0000 0000 */
	0x80000000,

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
}
