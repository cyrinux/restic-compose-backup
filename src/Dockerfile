FROM restic/restic:0.17.3

RUN apk update && apk add python3 \ 
    dcron \
    mariadb-client \
    postgresql-client \
    mariadb-connector-c-dev \
    py3-setuptools \
    py3-wheel \
    py3-pip \
    py3-docker-py

ADD . /restic-compose-backup
WORKDIR /restic-compose-backup
RUN pip3 install -e . --break-system-packages
ENV XDG_CACHE_HOME=/cache

ENTRYPOINT []
CMD ["./entrypoint.sh"]
