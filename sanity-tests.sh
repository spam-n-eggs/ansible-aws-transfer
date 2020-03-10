#!/usr/bin/env bash
PYTHON_VERSION=$1
shift
pushd ansible_collections/tapp/amazon
ansible-test sanity --venv --python $PYTHON_VERSION "${@}"
RC=$?
popd
exit $RC