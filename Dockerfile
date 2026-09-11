# 构建阶段：编译 Go 单二进制
# 版本号经 -ldflags 编译期烙进二进制，不走运行时环境变量
# （部署模板残留的 APP_VERSION 环境变量不会再遮蔽镜像真实版本）。
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY config ./config
COPY store ./store
COPY ca ./ca
COPY api ./api
COPY main.go ./main.go
COPY scheduler ./scheduler
# CI 发版经 --build-arg APP_VERSION 传入；本地构建留空时使用 config.go 里 var Version 的默认值
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
