FROM golang:1.25-alpine AS builder

RUN apk add --no-cache --update go gcc g++

WORKDIR /app

COPY . .
RUN go mod tidy && go mod download

RUN go run cmd/minify/minify.go frontend dist
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags "-s -w" -a -installsuffix cgo -o /app/joustlm cmd/joustlm/joustlm.go

RUN wget https://github.com/upx/upx/releases/download/v5.0.0/upx-5.0.0-amd64_linux.tar.xz
RUN tar -xvf upx-5.0.0-amd64_linux.tar.xz
RUN mv upx-5.0.0-amd64_linux/upx /usr/local/bin/
RUN upx -9 -o/app/joustlm-compressed /app/joustlm && mv /app/joustlm-compressed /app/joustlm

FROM alpine

LABEL org.opencontainers.image.source=https://github.com/shashank-priyadarshi/joustlm
LABEL org.opencontainers.image.description="This repository contains source code for InfraCloud assessment."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.authors="Shashank Priyadarshi <email@ssnk.in>"

WORKDIR /app

ARG CONFIG_PATH
ARG PORT

ENV CONFIG_PATH=${CONFIG_PATH:-/app/config.yml}
ENV PORT=${PORT:-8080}

RUN mkdir -p /app/data && chown -R 65532:65532 /app/data

COPY --from=builder /app/joustlm /app/joustlm

USER 65532:65532

ENTRYPOINT ["/app/joustlm"]
