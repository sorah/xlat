ARG RUBY_DEV=public.ecr.aws/sorah/ruby:3.3-dev-noble

FROM $RUBY_DEV AS build

WORKDIR /src
COPY . .

ENV BUNDLE_USER_CACHE=/cache/bundler
ENV BUNDLE_GLOBAL_GEM_CACHE=true
RUN --mount=type=cache,target=/cache/bundler bundle install

RUN bundle exec rake build

###

FROM $RUBY_DEV

RUN apt-get update && apt-get install -y iproute2 nftables clang cargo && \
    rm -rf /var/lib/apt/lists/*

RUN gem install pf2 -v 0.6.0

RUN --mount=type=bind,from=build,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

ENTRYPOINT ["/usr/local/bin/xlat-siit"]
