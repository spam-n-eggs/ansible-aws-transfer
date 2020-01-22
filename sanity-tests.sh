#!/usr/bin/env bash
pushd ansible_collections/cloud/amazon
ansible-test sanity
popd