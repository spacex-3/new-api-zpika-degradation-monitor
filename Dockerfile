FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src
COPY go.mod go.sum ./
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/manxue-monitor .

FROM --platform=$BUILDPLATFORM alpine:3.22 AS runtime-files

RUN apk add --no-cache ca-certificates tzdata

FROM alpine:3.22

COPY --from=runtime-files /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=runtime-files /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /out/manxue-monitor /usr/local/bin/manxue-monitor
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/manxue-monitor"]
