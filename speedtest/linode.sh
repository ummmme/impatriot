#!/usr/bin/env bash
# Vultr 服务器测速脚本
# version: 20190610
# 节点地址：https://www.vultr.com/faq/#downloadspeedtests


printr() {
    echo; echo "## $1"; echo;
}

printr "请注意：本脚本将测试所有Linode节点速度，并输出测试结果表格，预计耗时约1~2分钟";

node_list=(
'newark'
'atlanta'
'dallas'
'fremont'
'toronto1'
'frankfurt'
'london'
'singapore'
'tokyo2'
);

#表头
echo "服务器名称 | 服务器地址 | 平均延时 | 丢包率 | 下载速度" > /tmp/linode_tmp.log

for node in ${node_list[@]}; do
    serverDomain="speedtest.${node}.linode.com"

    echo "正在测试${node}节点, 请稍候..."
    res=$(ping -c 100 -f -n -q ${serverDomain});
    #丢包率
    lostRate=`echo ${res}|awk -F 'received,' '{print $2}' | awk -F 'packet loss,' '{print $1}'`;
    #平均延时
    avgLag=`echo ${res}|awk -F 'min/avg/max/mdev =' '{print $2}' | awk -F '/' '{print $2}' | awk -F '.' '{print $1}'`;
    #平均下载速度(前10秒)
    avgDown=$(curl -H 'Range: bytes=0-' -m 10 -Lo /dev/null -skw "%{speed_download}\n" http://speedtest.${node}.linode.com/100MB-${node}.bin | awk '{print int($0)}');
    let "avgDownSpeed=${avgDown}/1000";
    echo "${node} | ${serverDomain} | ${avgLag}ms | ${lostRate} | ${avgDownSpeed}k" >> /tmp/linode_tmp.log;
done

printr  "节点测试完毕：";
column -t -s "|" /tmp/linode_tmp.log > /tmp/linode_speed.log
cat /tmp/linode_speed.log;