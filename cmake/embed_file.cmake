# Embed a file as a C byte array header, for the server to serve without any on-disk asset.
#   cmake -DINPUT=<file> -DOUTPUT=<header> -DSYMBOL=<name> -P cmake/embed_file.cmake
# Produces: static const unsigned char <name>[] = {...}; static const unsigned long <name>_len;
file(READ "${INPUT}" _hex HEX)
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," _bytes "${_hex}")
file(WRITE "${OUTPUT}"
	"// Generated from ${INPUT} by cmake/embed_file.cmake; do not edit.\n"
	"// NOLINTBEGIN(readability-identifier-naming)\n"
	"static const unsigned char ${SYMBOL}[] = {${_bytes}};\n"
	"static const unsigned long ${SYMBOL}_len = sizeof(${SYMBOL});\n"
	"// NOLINTEND(readability-identifier-naming)\n")
