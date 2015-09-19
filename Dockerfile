FROM golang:1.5

ENV GB_VERSION v0.1.2
RUN set -x \
	&& mkdir -p /go/src/github.com/constabulary/gb \
	&& cd /go/src/github.com/constabulary/gb \
	&& curl -fsSL 'https://github.com/constabulary/gb/archive/v0.1.2.tar.gz' \
		| tar -xz --strip-components=1 \
	&& go install -v ./...

WORKDIR /usr/src/rawdns
ENV PATH $PATH:/usr/src/rawdns/bin

COPY . /usr/src/rawdns
RUN gb build

CMD ["rawdns"]
