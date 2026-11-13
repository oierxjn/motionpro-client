# MotionPro 代理服务端容器镜像（Linux, 容器 netns 内跑 TUN+隧道+代理）
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# 运行时依赖: cryptography(隧道) + fastapi/uvicorn(Web 面板) + iproute2(tun_dev 用 ip 命令)
ARG PIP_INDEX_URL=https://pypi.org/simple
RUN pip install --no-cache-dir -i ${PIP_INDEX_URL} \
        "cryptography>=50.0.1" "fastapi" "uvicorn" \
    && apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY mp_client.py proto_client.py vpn_service.py forwarder.py \
     tun_dev.py routes.py local_proxy.py proxy_serve.py \
     config.example.py ./

# config.py 由运行时挂载（含凭据，不入镜像）
CMD ["python", "proxy_serve.py"]
