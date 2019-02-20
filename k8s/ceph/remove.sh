#!/bin/sh

set -x
filepath=$(dirname $(realpath $0))
cd ${filepath}

# ceph部署
kubectl delete -f storageclass.yaml
kubectl delete -f cluster.yaml
kubectl delete -f operator.yaml

# 移除数据目录
mv /data/rook /data/rook{,_old}