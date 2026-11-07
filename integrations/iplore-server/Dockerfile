FROM golang:1.24.13-alpine3.23@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /iplore-server ./iplore-server

FROM scratch
COPY --from=build /iplore-server /iplore-server
USER 65532:65532
ENTRYPOINT ["/iplore-server"]
