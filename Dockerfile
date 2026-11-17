FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
COPY *.go ./
COPY web ./web
RUN CGO_ENABLED=0 go test ./... && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/manxue-monitor .

FROM alpine:3.22

RUN addgroup -S -g 10001 monitor && \
    adduser -S -D -H -u 10001 -G monitor monitor && \
    apk add --no-cache ca-certificates tzdata
COPY --from=build /out/manxue-monitor /usr/local/bin/manxue-monitor
USER monitor
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/manxue-monitor"]
