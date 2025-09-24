#!/bin/bash

parent_dir=$(pwd)
installation_dir=/tmp/bin

mkdir -p $installation_dir
cd $installation_dir || exit

cd "$parent_dir" || exit

# Setup githooks
printf "\nsetting up git hooks\n"
. ./.githooks/prepare-hook.sh

printf "\nsetting up git commit message template\n"
git config commit.template .githooks/.gitmessage
git config commit.cleanup strip
