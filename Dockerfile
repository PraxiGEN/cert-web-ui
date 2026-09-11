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

# 运行阶段：仅需二进制与前端页面，无任何外部 CA 依赖
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
# 由 CI 传入 git tag（如 v1.2.3），成为运行时版本号的默认值；
# 容器仍可用 -e APP_VERSION 覆盖。
ARG APP_VERSION=v1.0.0
ENV APP_VERSION=${APP_VERSION}
WORKDIR /app
COPY --from=build /out/cert-web-ui /app/cert-web-ui
COPY web ./web

EXPOSE 8080
CMD ["/app/cert-web-ui"]
