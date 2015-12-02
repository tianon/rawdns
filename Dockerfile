FROM golang:1.5

ENV GB_VERSION 0.3.3
RUN set -x \
	&& mkdir -p /go/src/github.com/constabulary/gb \
	&& cd /go/src/github.com/constabulary/gb \
	&& curl -fsSL "https://github.com/constabulary/gb/archive/v${GB_VERSION}.tar.gz" \
		| tar -xz --strip-components=1 \
	&& go install -v ./...

WORKDIR /usr/src/rawdns
ENV PATH $PATH:/usr/src/rawdns/bin

COPY . /usr/src/rawdns
RUN gb build

CMD ["rawdns"]
