#!/bin/sh
set +e
echo "Starting oFonod"
src/ofonod
echo "Starting stktest"
tools/stktest > stktest.log
