package common

func SafeStringForCompressString(id string) string {
	buf := make([]rune, 0, len(id))
	count := 0
	for _, c := range id {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '.', c == '-', c == '_', c == '!':
			buf = append(buf, c)
			count++
		default:
			buf = append(buf, '_')
			count++
		}
	}
	return string(buf)
}

func CompressString(id string) []byte {
	panic(1)
}

func DecompressString(buf []byte) string {
	panic(1)
}
