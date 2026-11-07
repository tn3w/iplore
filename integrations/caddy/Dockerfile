FROM caddy:2.11.9-builder@sha256:3fddbec729442a56b942d4c9eaef1df80893dbf2cf5b86701bfae6aad1408eeb AS build
ENV XCADDY_SETCAP=0
WORKDIR /src
COPY . .
RUN xcaddy build \
    --with github.com/tn3w/iplore/integrations/caddy=./caddy \
    --with github.com/tn3w/iplore/integrations=. \
    --output /caddy

FROM caddy:2.11.9@sha256:0c2243efcf437ab7f7a978f1027fcf0d4f9be8a75df27b1b3fbc5dbe0ffa8cf0
COPY --from=build /caddy /usr/bin/caddy
