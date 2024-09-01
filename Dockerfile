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

RUN apt-get update && apt-get install -y iproute2 nftables clang cargo ruby3.3-dbgsym libruby3.3-dbgsym && \
    rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,from=build-pf2,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

RUN --mount=type=bind,from=build,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

ENTRYPOINT ["/usr/local/bin/xlat-siit"]
