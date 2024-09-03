ARG RUBY_DEV=public.ecr.aws/sorah/ruby:3.3-dev-noble

FROM $RUBY_DEV AS build

WORKDIR /src
COPY . .

ENV BUNDLE_USER_CACHE=/cache/bundler
ENV BUNDLE_GLOBAL_GEM_CACHE=true
RUN --mount=type=cache,target=/cache/bundler bundle install

RUN bundle exec rake build


###

FROM $RUBY_DEV AS build-pf2

WORKDIR /tmp/libbacktrace
RUN git clone --depth=1 https://github.com/ianlancetaylor/libbacktrace .
RUN git archive -o /tmp/libbacktrace.tar.gz HEAD

WORKDIR /src
RUN git clone --depth=1 -b v0.6.0 https://github.com/osyoyu/pf2 .

RUN rm -rf crates/backtrace-sys2/src/libbacktrace/*
RUN tar xf /tmp/libbacktrace.tar.gz -C crates/backtrace-sys2/src/libbacktrace
RUN git config --global user.email "pui@test.invalid" && git config --global user.name pui
RUN git add crates/backtrace-sys2/src/libbacktrace && git commit -m 'Patch libbacktrace'

ENV BUNDLE_USER_CACHE=/cache/bundler
ENV BUNDLE_GLOBAL_GEM_CACHE=true
RUN --mount=type=cache,target=/cache/bundler bundle install

RUN bundle exec rake build


###

FROM $RUBY_DEV

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y ubuntu-dbgsym-keyring

RUN <<NUR
. /etc/os-release
cat <<EOF > /etc/apt/sources.list.d/ddebs.sources
Types: deb
URIs: http://ddebs.ubuntu.com
Suites: ${VERSION_CODENAME} ${VERSION_CODENAME}-updates ${VERSION_CODENAME}-proposed
Components: main restricted universe multiverse
EOF
NUR

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y iproute2 nftables clang cargo debian-goodies elfutils dctrl-tools && \
    find-dbgsym-packages --install /usr/bin/ruby

RUN --mount=type=bind,from=build-pf2,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

RUN --mount=type=bind,from=build,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

ENTRYPOINT ["/usr/local/bin/xlat-siit"]
