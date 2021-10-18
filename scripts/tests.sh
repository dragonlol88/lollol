#!/usr/bin/env bash

set -e
set -x
pytest tests
#test_dir="tests"
#
#test_files=($(ls tests))
#
#for file_name in "${test_files[@]}"; do
#  file="$test_dir/$file_name"
#  if [ -f $file ] && [ $file_name != "__init__.py" ]; then
#    pytest  -W ignore::DeprecationWarning  $file
#  fi
#done


