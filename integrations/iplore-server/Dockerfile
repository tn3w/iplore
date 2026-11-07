FROM golang:1.27.2-alpine3.23@sha256:9e45f0eb4a63ed37ad6e604950407558b7c738e34e015ae77a5d4ad369cde079 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /iplore-server ./iplore-server

FROM scratch
COPY --from=build /iplore-server /iplore-server
USER 65532:65532
ENTRYPOINT ["/iplore-server"]
