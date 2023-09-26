#!/usr/bin/python3

import json
import sys

filename = str(sys.argv[1])
with open(filename, 'r') as fichier:
    contenu = json.load(fichier)

print(contenu['version'])
