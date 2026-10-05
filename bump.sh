#!/bin/sh
# Bump the build stamp in index.html and version.txt so open apps reload to the new version.
v=$(date +%Y%m%d%H%M%S)
sed -i "s/const BUILD=\"[0-9]*\";/const BUILD=\"$v\";/" index.html
echo "$v" > version.txt
