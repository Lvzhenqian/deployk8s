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

function ready(){
    nodes=($(kubectl get node|awk '/k8s/{print $1}'))
    for name in ${nodes};do
        while :;do 
            status=$(kubectl -n rook-ceph get pods|awk '/'${name}'/{print $3}')
            if [[ "${status}" == "Completed" ]];then
                break
            else
                sleep 20
                status=$(kubectl -n rook-ceph get pods|awk '/'${name}'/{print $3}')
            fi
        done
    done
}
# ceph部署
/usr/bin/helm repo add rook-stable https://charts.rook.io/stable
/usr/bin/helm repo update
/usr/bin/helm install rook rook-stable/rook-ceph --namespace rook-ceph-system
checker rook-ceph-system
kubectl create -f cluster.yaml
ready
kubectl create -f storageclass.yaml