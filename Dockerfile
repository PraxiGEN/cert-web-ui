# 构建阶段：编译 Go 单二进制
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY config ./config
COPY store ./store
COPY ca ./ca
COPY api ./api
COPY main.go ./main.go
COPY scheduler ./scheduler
ARG APP_VERSION
RUN set -eux; \
    if [ -n "${APP_VERSION:-}" ]; then \
      CGO_ENABLED=0 GOOS=linux go build -ldflags "-X cert-web-ui/config.Version=${APP_VERSION:-}" -o /out/cert-web-ui .; \
    else \
      CGO_ENABLED=0 GOOS=linux go build -o /out/cert-web-ui .; \
    fi

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/cert-web-ui /app/cert-web-ui
COPY web ./web

EXPOSE 9280
CMD ["/app/cert-web-ui"]
