ARG RUBY=public.ecr.aws/sorah/ruby:3.4-dev
ARG RUBY_DEV=public.ecr.aws/sorah/ruby:3.4-dev-noble

FROM $RUBY_DEV AS build

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y clang cargo

WORKDIR /app
COPY . .

RUN bundle config set --local deployment true
RUN bundle install

RUN bundle exec rake compile


###

FROM $RUBY

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
    apt-get install -y iproute2 nftables debian-goodies elfutils dctrl-tools && \
    find-dbgsym-packages --install /usr/bin/ruby

COPY --from=build /app /app
COPY --from=build /app/.bundle /app/.bundle

ENV BUNDLE_GEMFILE=/app/Gemfile
ENTRYPOINT ["bundle", "exec", "ruby", "/app/exe/xlat-siit"]
