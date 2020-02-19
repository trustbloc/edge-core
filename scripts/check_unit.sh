#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
echo "" > "$pwd"/coverage.txt

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.txt
     rm profile.out
fi
}

# First argument is the exit code
# Second argument is the command that was run
check_exit_code () {
if [ "$1" -ne 0 ] && [ "$1" -ne 1 ]; then
  echo "error: '${2}' returned ${1}, but either 0 or 1 was expected."

  # There's no easy way to print the error message on the screen without temporary files,
  # so we ask the user to check manually
  echo "Try running '${2}' manually to see the full error message."

  exit 1
fi
}

# docker rm returns 1 if the image isn't found. This is OK and expected, so we suppress it
# Any return status other than 0 or 1 is unusual and so we exit
remove_docker_container () {
DOCKER_KILL_EXIT_CODE=0
docker kill CouchDBStoreTest >/dev/null 2>&1 || DOCKER_KILL_EXIT_CODE=$?

check_exit_code $DOCKER_KILL_EXIT_CODE "docker kill CouchDBStoreTest"

DOCKER_RM_EXIT_CODE=0
docker rm CouchDBStoreTest >/dev/null 2>&1 || DOCKER_RM_EXIT_CODE=$?

check_exit_code $DOCKER_RM_EXIT_CODE "docker rm CouchDBStoreTest"
}

remove_docker_container

PKGS=`go list github.com/trustbloc/edge-core/... 2> /dev/null | \
                                                  grep -v /mocks`

docker run -p 5984:5984 -d --name CouchDBStoreTest couchdb:2.3.1 >/dev/null

GO_TEST_EXIT_CODE=0
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m || GO_TEST_EXIT_CODE=$?
if [ $GO_TEST_EXIT_CODE -ne 0 ]; then
  docker kill CouchDBStoreTest >/dev/null
  remove_docker_container

  exit $GO_TEST_EXIT_CODE
fi

amend_coverage_file

docker kill CouchDBStoreTest >/dev/null
remove_docker_container

cd "$pwd" || exit
