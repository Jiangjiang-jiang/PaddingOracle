FROM ubuntu:20.04

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
  && sed '/security\.ubuntu\.com/d' /etc/apt/sources.list \
  && apt-get clean \
  && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
  && echo "Asia/Shanghai" > /etc/timezone \
  && apt-get -y update && apt-get -y install \
  libmbedtls-dev \
  cmake \
  build-essential

COPY ./build.sh /

ENV DOCKER=on

CMD ["bash", "/build.sh"]
