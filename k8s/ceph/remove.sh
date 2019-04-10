#!/bin/sh

set -x
filepath=$(dirname $(realpath $0))
cd ${filepath}

# ceph部署
kubectl delete -f storageclass.yaml
kubectl delete -f cluster.yaml
/usr/bin/helm delete --purge rook

# 删除数据目录
rm -rf  /data/rook 