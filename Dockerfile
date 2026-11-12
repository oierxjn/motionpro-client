# MotionPro 代理服务端容器镜像（Linux, 容器 netns 内跑 TUN+隧道+代理）
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# 仅 cryptography 一个运行时依赖
RUN pip install --no-cache-dir "cryptography>=50.0.1"

COPY mp_client.py proto_client.py vpn_service.py forwarder.py \
     tun_dev.py routes.py local_proxy.py proxy_serve.py \
     config.example.py ./

# config.py 由运行时挂载（含凭据，不入镜像）
CMD ["python", "proxy_serve.py"]
