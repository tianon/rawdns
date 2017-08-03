FROM golang:1.8-alpine as builder

ENV GB_VERSION 0.4.2
RUN apk add --no-cache openssl
RUN set -x \
	&& mkdir -p /go/src/github.com/constabulary \
	&& cd /go/src/github.com/constabulary \
	&& wget -qO- "https://github.com/constabulary/gb/archive/v${GB_VERSION}.tar.gz" \
		| tar -xz \
	&& mv gb-* gb \
	&& cd gb \
	&& go install -v ./...

WORKDIR /usr/src/rawdns
COPY . .
RUN ls && gb build -ldflags '-s -w'


FROM alpine:3.6
RUN apk add --no-cache ca-certificates
WORKDIR /
COPY --from=builder /usr/src/rawdns/bin/rawdns /usr/local/bin/
COPY example-config.json .
CMD ["rawdns"]
