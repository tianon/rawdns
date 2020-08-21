FROM golang:1.14-alpine3.12

RUN apk add --no-cache ca-certificates openssl

WORKDIR /usr/local/src/rawdns
COPY . .
RUN go build -v -mod vendor -o /usr/local/bin/rawdns ./cmd/rawdns

CMD ["rawdns"]
