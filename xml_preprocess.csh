#!/bin/csh

# Use 'find' to get all regret*.xml files, suppress permission denied errors
foreach file (`find ./ -name "regret*.xml" |& grep -v "Permission denied"`)
    echo "Processing $file"
    perl -pi -e 's{<testcase(?!\s+classname=)}{<testcase classname=""}g' "$file"
end
