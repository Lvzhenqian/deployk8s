#!/bin/sh

set -x
filepath=$(dirname $(realpath $0))
cd ${filepath}

function checker(){
    local namespace=$1
    rows=$(kubectl -n ${namespace} get pods|grep -v "NAME"|awk '{print $1"|"$3}')
    while :;do
        if echo ${rows}|egrep "agent|operator|discover|mgr|mon|osd" &> /dev/null;then
            break
        fi
        rows=$(kubectl -n ${namespace} get pods|grep -v "NAME"|awk '{print $1"|"$3}')
        sleep 5
    done
    for line in ${rows};do
        name=$(echo ${line}|awk -F'|' '{print $1}')
        status=$(echo ${line}|awk -F'|' '{print $2}')
        while :;do
            echo "${name} ${status}"
            case ${status} in
            Running)
                break
                ;;
            Completed)
                kubectl -n ${namespace} delete pod ${name}
                ;;
            *)
                sleep 20
                status=$(kubectl -n ${namespace} get pods|awk '/'${name}'/{print $3}') 
                ;;
            esac
        done
    done
}
# ceph部署
kubectl create -f operator.yaml
checker rook-ceph-system
kubectl create -f cluster.yaml
while :;do
    if kubectl -n rook-ceph get pods |grep "osd-[0-9]" &> /dev/null;then
        break
    else
        kubectl -n rook-ceph get pods
    fi
    sleep 20
done
kubectl create -f storageclass.yaml