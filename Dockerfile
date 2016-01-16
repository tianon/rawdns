FROM golang:1.5-alpine

RUN apk add --no-cache ca-certificates openssl

ENV GB_VERSION 0.3.5
RUN set -x \
	&& mkdir -p /go/src/github.com/constabulary \
	&& cd /go/src/github.com/constabulary \
	&& wget -qO- "https://github.com/constabulary/gb/archive/v${GB_VERSION}.tar.gz" \
		| tar -xz \
	&& mv gb-* gb \
	&& cd gb \
	&& go install -v ./...

WORKDIR /usr/src/rawdns
ENV PATH $PATH:/usr/src/rawdns/bin

COPY . /usr/src/rawdns
RUN gb build

CMD ["rawdns"]
