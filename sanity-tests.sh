#!/usr/bin/env bash
PYTHON_VERSION=$1
pushd ansible_collections/cloud/amazon
ansible-test sanity --python $PYTHON_VERSION
RC=$?
popd
exit $RC