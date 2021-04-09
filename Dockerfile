FROM alpine:3.6
LABEL maintainer "Edward Bjarte Fjellskål <edward.fjellskaal@gmail.com>"

RUN addgroup -S passivedns && adduser -S -g passivedns passivedns  
RUN apk add --no-cache -t .build-deps build-base automake autoconf git \
 && apk add --no-cache tini ldns-dev libpcap-dev \
 && git clone -b '1.2.0' --single-branch --depth 1 https://github.com/gamelinux/passivedns /tmp/src \
 && cd /tmp/src \
 && autoreconf --install \
 && ./configure \
 && make \
 && make install \
 && /bin/rm -r /tmp/src \
 && apk del .build-deps \
 && mkdir /var/log/passivedns \
 && chown passivedns:passivedns /var/log/passivedns \
 && chmod +s /usr/local/bin/passivedns

USER passivedns
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/passivedns", "-l", "-", "-L", "-", "-C", "0", "-P", "0", "-X", "46CDNOLFIPRSTMndHfsxoryetaz"]
