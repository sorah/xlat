ARG RUBY=3.3

FROM public.ecr.aws/sorah/ruby:$RUBY-dev as build

WORKDIR /src
COPY . .

ENV BUNDLE_USER_CACHE=/cache/bundler
ENV BUNDLE_GLOBAL_GEM_CACHE=true
RUN --mount=type=cache,target=/cache/bundler bundle install

RUN bundle exec rake build

###

FROM public.ecr.aws/sorah/ruby:$RUBY

RUN apt-get update && apt-get install -y iproute2 nftables && \
    rm -rf /var/lib/apt/lists/*

RUN --mount=type=bind,from=build,source=/src/pkg,destination=/pkg gem install /pkg/*.gem

ENTRYPOINT ["/usr/local/bin/xlat-siit"]
