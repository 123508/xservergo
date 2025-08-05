#!/bin/bash
# 运行脚本
# 用于启动项目的各个服务

set -e

# 解析 YAML 文件
# parse_yaml <path_to_conf.yaml> <prefix>
function parse_yaml {
    local prefix=$2
    local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
    sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
    awk -F$fs '{
        indent = length($1)/2;
        vname[indent] = $2;
        for (i in vname) {if (i > indent) {delete vname[i]}}
        if (length($3) > 0) {
            vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
            printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
        }
    }'
}

# 项目根目录
PROJECT_ROOT=$(cd "$(dirname "$0")/.." && pwd)
SERVICE_NAME=$1

# 读取配置文件
eval $(parse_yaml "$PROJECT_ROOT/config/conf.yaml" "config_")

if [ -z "$SERVICE_NAME" ]; then
    echo "Usage: $0 <service_name>"
    exit 1
fi

if [ "$SERVICE_NAME" == "user" ]; then
    SERVICE_DIR="$PROJECT_ROOT/apps/user"
    export KITEX_IP_TO_REGISTRY=$config_ip_to_register
    export KITEX_PORT_TO_REGISTRY=$config_user_port
    cd $SERVICE_DIR
    go run .
elif [ "$SERVICE_NAME" == "auth" ]; then
    SERVICE_DIR="$PROJECT_ROOT/apps/auth"
    export KITEX_IP_TO_REGISTRY=$config_ip_to_register
    export KITEX_PORT_TO_REGISTRY=$config_auth_port
    cd $SERVICE_DIR
    go run .
elif [ "$SERVICE_NAME" == "gateway" ]; then
    SERVICE_DIR="$PROJECT_ROOT/apps/gateway"
    cd $SERVICE_DIR
    go run .
else
    echo "Unknown service: $SERVICE_NAME"
    exit 1
fi
