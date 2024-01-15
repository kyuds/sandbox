#!/bin/bash
LANG="$1"
find . -name "*.$LANG" | xargs wc -l
