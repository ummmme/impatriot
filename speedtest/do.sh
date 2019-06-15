#!/usr/bin/env bash
# DigitalOcean 服务器测速脚本
# version: 20190613
# 节点地址：http://speedtest-nyc1.digitalocean.com/


printr() {
    echo; echo "## $1"; echo;
}

printr "请注意：本脚本将测试所有DigitalOcean节点速度，并输出最终测试结果表格，预计耗时约2~3分钟";

node_list=(
'NYC1|speedtest-nyc1.digitalocean.com'
'NYC2|speedtest-nyc2.digitalocean.com'
'NYC3|speedtest-nyc3.digitalocean.com'
'AMS2|speedtest-ams2.digitalocean.com'
'AMS3|speedtest-ams2.digitalocean.com'
'SFO1|speedtest-sfo1.digitalocean.com'
'SFO2|speedtest-sfo2.digitalocean.com'
'SGP|speedtest-sgp1.digitalocean.com'
'LON|speedtest-lon1.digitalocean.com'
'FRA|speedtest-fra1.digitalocean.com'
'TOR|speedtest-tor1.digitalocean.com'
'BLR|speedtest-blr1.digitalocean.com'
);

#表头
echo "服务器名称 | 服务器地址 | 平均延时 | 丢包率 | 下载速度" > /tmp/speedtest_tmp.log

for node in ${node_list[@]}; do
    serverName=`echo ${node} | awk -F '|' '{print $1}'`;
    serverDomain=`echo ${node} | awk -F '|' '{print $2}'`;

    echo "正在测试${serverName}节点, 请稍候..."
    res=$(ping -c 100 -f -n -q ${serverDomain});
    #丢包率
    lostRate=`echo ${res}|awk -F 'received,' '{print $2}' | awk -F 'packet loss,' '{print $1}'`;
    #平均延时
    avgLag=`echo ${res}|awk -F 'min/avg/max/mdev =' '{print $2}' | awk -F '/' '{print $2}' | awk -F '.' '{print $1}'`;
    #平均下载速度(10秒内)
    avgDown=$(curl -H 'Range: bytes=0-' -m 10 -Lo /dev/null -skw "%{speed_download}\n" http://${serverDomain}/1gb.test | awk '{print int($0)}');
    let "avgDownSpeed=${avgDown}/1000";
    echo "${serverName} | ${serverDomain} | ${avgLag}ms | ${lostRate} | ${avgDownSpeed}k" >> /tmp/speedtest_tmp.log;
done

printr  "测试完毕.各节点速度如下：";
column -t -s "|" /tmp/speedtest_tmp.log > /tmp/speedtest.log
cat /tmp/speedtest.log;
