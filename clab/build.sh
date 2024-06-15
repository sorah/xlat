#!/bin/bash
set -eu

cd "$(dirname "${BASH_SOURCE[0]}")"

docker build -t localhost/xlat/xlat ..
