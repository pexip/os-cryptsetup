#!/bin/bash

. lib.sh

#
# *** Description ***
#
# generate primary header with wrong segment size field
#
# secondary header is corrupted on purpose as well
#

# $1 full target dir
# $2 full source luks2 image

function generate()
{
	# remove mandatory encryption field
	json_str=$(jq -c '.segments."0".size = "511"' $TMPDIR/json0)
	test ${#json_str} -lt $((LUKS2_JSON_SIZE*512)) || exit 2

	write_luks2_json "$json_str" $TMPDIR/json0

	lib_mangle_json_hdr0_kill_hdr1
}

function check()
{
	lib_hdr1_killed || exit 2

	read_luks2_json0 $TGT_IMG $TMPDIR/json_res0
	jq -c 'if .segments."0".size != "511"
	       then error("Unexpected value in result json") else empty end' $TMPDIR/json_res0 || exit 5
}

lib_prepare $@
generate
check
lib_cleanup
