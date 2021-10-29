ARG NGX_VER=stable
ARG NGX_WAF_VER=current
FROM --platform=$TARGETPLATFORM addsp/ngx_waf-prebuild:ngx-${NGX_VER}-module-${NGX_WAF_VER}-musl as ngx_waf_prebuild

ARG NGX_VER=stable
FROM --platform=$TARGETPLATFORM nginx:${NGX_VER}-alpine as runtime

FROM --platform=$TARGETPLATFORM alpine:3.14 as prepare
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG MAXMIND_LICENSE_KEY
ARG MODSECURITY_VERSION
ARG CHANGE_SOURCE=false

# MODSECURITY version

ENV MODSECURITY_VERSION=3.0.4


# GeoIP
RUN mkdir /GeoLite2/
WORKDIR /GeoLite2/

ENV MAXMIND_BASE_URL "https://download.maxmind.com/app/geoip_download?license_key=$MAXMIND_LICENSE_KEY&"

RUN set -eux; \
  \
  if [ ${CHANGE_SOURCE} = true ]; then \
    sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/' /etc/apk/repositories ; \
  fi; \
  \
  wget "${MAXMIND_BASE_URL}edition_id=GeoLite2-ASN&suffix=tar.gz" -O GeoLite2-ASN.tar.gz; \
  wget "${MAXMIND_BASE_URL}edition_id=GeoLite2-ASN&suffix=tar.gz.sha256" -O GeoLite2-ASN.tar.gz.sha256; \
  sed 's/GeoLite2-ASN_[0-9]*.tar.gz/GeoLite2-ASN.tar.gz/g' -i GeoLite2-ASN.tar.gz.sha256; \
  sha256sum -c GeoLite2-ASN.tar.gz.sha256; \
  tar xvf GeoLite2-ASN.tar.gz --strip 1; \
  \
  wget "${MAXMIND_BASE_URL}edition_id=GeoLite2-Country&suffix=tar.gz" -O GeoLite2-Country.tar.gz; \
  wget "${MAXMIND_BASE_URL}edition_id=GeoLite2-Country&suffix=tar.gz.sha256" -O GeoLite2-Country.tar.gz.sha256; \
  sed 's/GeoLite2-Country_[0-9]*.tar.gz/GeoLite2-Country.tar.gz/g' -i GeoLite2-Country.tar.gz.sha256; \
  sha256sum -c GeoLite2-Country.tar.gz.sha256; \
  tar xvf GeoLite2-Country.tar.gz --strip 1;


WORKDIR /src
ENV WORKING_DIR="/src"


# Download dependencies
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    libc-dev \
    make \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    linux-headers \
    libxslt-dev \
    gd-dev \
    geoip-dev \
    perl-dev \
    libedit-dev \
    mercurial \
    bash \
    alpine-sdk \
    findutils \
    patch \
    curl \
  # modsecurity dependencies
    autoconf \
    automake \
    curl-dev \
    libmaxminddb-dev \
    libtool \
    lmdb-dev \
    yajl-dev

# Download ModSecurity files
RUN set -eux; \
  \
  echo "Downloading sources..."; \
  cd ${WORKING_DIR}; \
  git clone --depth 1 -b v${MODSECURITY_VERSION} --single-branch https://github.com/SpiderLabs/ModSecurity

# Starting build process
## Build libmodsecurity
RUN set -eux; \
  echo "building modsecurity..."; \
  cd ModSecurity; \
  git submodule init; \
  git submodule update; \
  wget https://gist.githubusercontent.com/crsgists/0e1f6f7f1bd1f239ded64cecee46a11d/raw/181bc852065e9782367f1dc67c96d4d250e73a46/cve-2020-15598.patch; \
  patch -p1 < cve-2020-15598.patch; \
  ./build.sh; \
  ./configure --prefix=/usr; \
  make -o 3 -j$(nproc); \
  make install


# Build nginx modules
## https://github.com/nginxinc/docker-nginx/blob/1.20.1/modules/Dockerfile.alpine
FROM runtime as builder
ARG ENABLED_MODULES="geoip2"
ARG CHANGE_SOURCE=false
ENV PKG_RELEASE   1

RUN set -ex \
    && if [ "$ENABLED_MODULES" = "" ]; then \
        echo "No additional modules enabled, exiting"; \
        exit 1; \
    fi

COPY ./ /modules/

RUN set -ex \
    \
    &&  if [ ${CHANGE_SOURCE} = true ]; then \
            sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/' /etc/apk/repositories ; \
            fi \
    && apk update \
    && apk add linux-headers openssl-dev pcre-dev zlib-dev openssl abuild \
               musl-dev libxslt libxml2-utils make mercurial gcc unzip git \
               xz g++
RUN set -ex \
    \
    # allow abuild as a root user \
    && printf "#!/bin/sh\\n/usr/bin/abuild -F \"\$@\"\\n" > /usr/local/bin/abuild \
    && chmod +x /usr/local/bin/abuild \
    && nginxVersion=$(nginx -v 2>&1 | grep -o '[0-9.]*$') \
    && export NGINX_VERSION=$nginxVersion \
    && hg clone -r ${NGINX_VERSION}-${PKG_RELEASE} https://hg.nginx.org/pkg-oss/ \
    && cd pkg-oss \
    && mkdir /tmp/packages \
    && for module in $ENABLED_MODULES; do \
        echo "Building $module for nginx-$NGINX_VERSION"; \
        if [ -d /modules/$module ]; then \
            echo "Building $module from user-supplied sources"; \
            # check if module sources file is there and not empty
            if [ ! -s /modules/$module/source ]; then \
                echo "No source file for $module in modules/$module/source, exiting"; \
                exit 1; \
            fi; \
            # some modules require build dependencies
            if [ -f /modules/$module/build-deps ]; then \
                echo "Installing $module build dependencies"; \
                apk update && apk add $(cat /modules/$module/build-deps | xargs); \
            fi; \
            # if a module has a build dependency that is not in a distro, provide a
            # shell script to fetch/build/install those
            # note that shared libraries produced as a result of this script will
            # not be copied from the builder image to the main one so build static
            if [ -x /modules/$module/prebuild ]; then \
                echo "Running prebuild script for $module"; \
                /modules/$module/prebuild; \
            fi; \
            /pkg-oss/build_module.sh -v $NGINX_VERSION -f -y -o /tmp/packages -n $module $(cat /modules/$module/source); \
        elif make -C /pkg-oss/alpine list | grep -E "^$module\s+\d+" > /dev/null; then \
            echo "Building $module from pkg-oss sources"; \
            cd /pkg-oss/alpine; \
            make abuild-module-$module BASE_VERSION=$NGINX_VERSION NGINX_VERSION=$NGINX_VERSION; \
            apk add $(. ./abuild-module-$module/APKBUILD; echo $makedepends;); \
            make module-$module BASE_VERSION=$NGINX_VERSION NGINX_VERSION=$NGINX_VERSION; \
            find ~/packages -type f -name "*.apk" -exec mv -v {} /tmp/packages/ \;; \
        else \
            echo "Don't know how to build $module module, exiting"; \
            exit 1; \
        fi; \
    done


FROM runtime
ARG ENABLED_MODULES="geoip2"
ARG CHANGE_SOURCE=false

COPY --from=prepare /GeoLite2/*.mmdb /usr/share/GeoIP/
COPY --from=prepare /usr/lib/libmodsecurity* /usr/lib/

RUN set -eux; \
  \
  if [ ${CHANGE_SOURCE} = true ]; then sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories; fi; \
  apk add --no-cache \
     \
    yajl \
    libstdc++	\
    libmaxminddb \
  ; \
  \
  mkdir -p /run/nginx/; \
  rm -f /etc/nginx/conf.d/default.conf; \
# forward request and error logs to docker log collector
  ln -sf /dev/stdout /var/log/nginx/access.log; \
  ln -sf /dev/stderr /var/log/nginx/error.log;

COPY --from=builder /tmp/packages /tmp/packages
RUN set -ex \
    && nginxVersion=$(nginx -v 2>&1 | grep -o '[0-9.]*$') \
    && export NGINX_VERSION=$nginxVersion \
    && for module in $ENABLED_MODULES; do \
           apk add --no-cache --allow-untrusted /tmp/packages/nginx-module-${module}-${NGINX_VERSION}*.apk; \
       done \
    && rm -rf /tmp/packages

COPY --from=ngx_waf_prebuild /modules/ngx_http_waf_module.so /etc/nginx/modules/ngx_http_waf_module.so
COPY --from=ngx_waf_prebuild /assets /usr/local/src/ngx_waf/assets
COPY nginx/nginx.conf         /etc/nginx/
COPY nginx/conf.d/*           /etc/nginx/conf.d/

RUN touch /var/run/nginx/nginx.pid && \
        chown -R nginx:nginx /var/run/nginx/nginx.pid

# GoogleContainerTools/kaniko#1278 workaround
# RUN test -e /var/run || ln -s /run /var/run

USER nginx

RUN nginx -t 1>&2

HEALTHCHECK --timeout=10s --start-period=5s CMD wget -O /dev/null http://127.0.0.1:8080 || exit 1

EXPOSE 8080
VOLUME [ "/usr/local/src/ngx_waf/assets" ]

ENTRYPOINT [ "/usr/sbin/nginx", "-g", "daemon off;" ]