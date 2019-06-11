#!/usr/bin/env bash
# Vultr 服务器测速脚本
# version: 20190610
# 节点地址：https://www.vultr.com/faq/#downloadspeedtests


printr() {
    echo; echo "## $1"; echo;
}

printr "请注意：本脚本将测试所有Vultr节点速度，并输出最终测试结果表格，预计耗时约2~3分钟";

node_list=(
'Frankfurt|fra-de-ping.vultr.com'
'Amsterdam|ams-nl-ping.vultr.com'
'Paris|par-fr-ping.vultr.com'
'London|lon-gb-ping.vultr.com'
'Singapore|sgp-ping.vultr.com'
'Tokyo|hnd-jp-ping.vultr.com'
'NewYork(NJ)|nj-us-ping.vultr.com'
'Toronto|tor-ca-ping.vultr.com'
'Chicago|il-us-ping.vultr.com'
'Atlanta|ga-us-ping.vultr.com'
'Seattle|wa-us-ping.vultr.com'
'Miami|fl-us-ping.vultr.com'
'Dallas|tx-us-ping.vultr.com'
'SiliconValley|sjo-ca-us-ping.vultr.com'
'LosAngeles|lax-ca-us-ping.vultr.com'
'Sydney|syd-au-ping.vultr.com'
);

#表头
echo "服务器名称 | 服务器地址 | 平均延时 | 丢包率 | 下载速度" > /tmp/vultr_tmp.log

for node in ${node_list[@]}; do
    serverName=`echo ${node} | awk -F '|' '{print $1}'`;
    serverDomain=`echo ${node} | awk -F '|' '{print $2}'`;

    echo "正在测试${serverName}节点, 请稍候..."
    res=$(ping -c 100 -f -n -q ${serverDomain});
    #丢包率
    lostRate=`echo ${res}|awk -F 'received,' '{print $2}' | awk -F 'packet loss,' '{print $1}'`;
    #平均延时
    avgLag=`echo ${res}|awk -F 'min/avg/max/mdev =' '{print $2}' | awk -F '/' '{print $2}' | awk -F '.' '{print $1}'`;

    avgDown=$(curl -H 'Range: bytes=0-' -m 10 -Lo /dev/null -skw "%{speed_download}\n" https://${serverDomain}/vultr.com.1000MB.bin | awk '{print int($0)}');
    let "avgDownSpeed=${avgDown}/1000";
    echo "${serverName} | ${serverDomain} | ${avgLag}ms | ${lostRate} | ${avgDownSpeed}k" >> /tmp/vultr_tmp.log;
done

printr  "测试完毕.各节点速度如下：";
column -t -s "|" /tmp/vultr_tmp.log > /tmp/vultr_speed.log
cat /tmp/vultr_speed.log;
