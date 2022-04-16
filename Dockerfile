FROM node:alpine AS base
VOLUME /root/.mako
CMD "makod"

RUN apk upgrade --no-cache

# Install build dependencies and compile
FROM base AS build
RUN apk add --no-cache gcc make cmake musl-dev
RUN mkdir -p /code
WORKDIR /code
COPY . /code/
RUN cmake . && make

FROM base
COPY --from=build /code/mako /usr/bin/mako
COPY --from=build /code/makod /usr/bin/makod
