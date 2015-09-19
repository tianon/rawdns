FROM golang:1.5

# get a specific commit of "gb" for repeatability
ENV GB_COMMIT e677e206028e1d4e3a8ec2e6e4ca5caa0c94f8fd
RUN set -x \
	&& git clone https://github.com/constabulary/gb.git /go/src/github.com/constabulary/gb \
	&& ( \
		cd /go/src/github.com/constabulary/gb \
		&& git checkout --quiet $GB_COMMIT \
		&& go install -v ./... \
	) \
	&& rm -rf /go/src/github.com/constabulary/gb

WORKDIR /usr/src/rawdns
ENV PATH $PATH:/usr/src/rawdns/bin

COPY . /usr/src/rawdns
RUN gb build

CMD ["rawdns"]
