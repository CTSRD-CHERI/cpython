# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

### Example to print use of lib4sbom to convert an SPDX SBOM in tag value
### format to a SPDX SBOM in JSON format (and printn on console) and
### a CycloneDX file in JSON format (stored in a file)

from lib4sbom.generator import SBOMGenerator
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser
import sys

# Set up SBOM parser
test_parser = SBOMParser()
# Load SBOM - will autodetect SBOM type
test_parser.parse_file(sys.argv[1])
# test_parser.parse_file("test/data/spdx_test.spdx")

# print relationships
# rel = test_parser.get_sbom()['relationships']
# for r in rel:
#     print(r)

pack = [x for x in test_parser.get_sbom()['packages'].values()]
supplier = {}
for p in pack:
    supplier[p['name']] = p['supplier']

node = []
implicit_style = " [shape=box, style=filled, fontcolor=white, fillcolor=darkgreen, label="
# Generate header
print("strict digraph suppliersbom {")
print('\tsize="8,10.5"; ratio=fill;')
# Generate graph
for rel in test_parser.get_relationships():
    source = rel['source']
    target = rel['target']

    if supplier.get(source) is None:
        source = rel['source_id']
    else:
        source = supplier[source]
    if supplier.get(target) is None:
        target = rel['target_id']
    else:
        target = supplier[target]

    if source not in node:
        node.append(source)
        print(f'\t"{source}"{implicit_style}"{source}"];')
    if target not in node:
        node.append(target)
        print(f'\t"{target}"{implicit_style}"{target}"];')

    if target != source:
        print (f'"{source}" -> "{target}"')

print("}")