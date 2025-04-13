#!/bin/sh

# Find all regret*.xml files, skipping permission denied errors
find ./ -name "regret*.xml" 2>&1 | grep -v "Permission denied" | while read -r file; do
  echo "Processing $file"
  # perl -pi -e 's/classname="NoClassName"/classname=""/g' "$file"
  perl -pi -e 's{<testcase(?!\s+classname=)}{<testcase classname="NoClassName"}g' "$file"
done

