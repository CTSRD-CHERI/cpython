#!/bin/sh

# Find all regret*.xml files, skipping permission denied errors
find ./ -name "regret*.xml" 2>&1 | grep -v "Permission denied" | while read -r file; do
  echo "Processing $file"
  sed -i '' '/<testcase /{
  	/classname=/!s/<testcase /<testcase classname="" /
  }' "$file"

done

