#!/usr/bin/env bash
PYTHON_VERSION=$1
pushd ansible_collections/cloud/amazon
ansible-test sanity --venv --python $PYTHON_VERSION
RC=$?
popd
exit $RC