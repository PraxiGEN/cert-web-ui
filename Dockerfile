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
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/cert-web-ui .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
# 版本号唯一权威 = config/config.go 的 APP_VERSION 默认值；
# 此处不设默认，CI 发版经 build-arg 显式传入，本地构建留空时回落 config.go
ARG APP_VERSION
ENV APP_VERSION=${APP_VERSION}
WORKDIR /app
COPY --from=build /out/cert-web-ui /app/cert-web-ui
COPY web ./web

EXPOSE 9280
CMD ["/app/cert-web-ui"]
