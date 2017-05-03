#!/bin/bash

OS=$(uname)

echo "test" > testfile
FAIL=0

if [ $OS == "Darwin" ]; then
	OPT="-E"
fi

for i in $(ls -d */); do
	for j in $(find $OPT $i -type f -regex ".*\.yara?"); do
		echo $j; yara $j testfile
		if [[ $? -ne 0 ]]; then
			FAIL=1
		fi
	done
done

echo
if [[ $FAIL -eq 1 ]] ; then
	echo -e "\e[31mBuild faild\e[0m"
else
	echo -e "\e[32mBuild success\e[0m"
fi

rm -f testfile

