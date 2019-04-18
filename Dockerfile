FROM golang:1.12-alpine3.9

RUN apk add --no-cache ca-certificates openssl

WORKDIR /usr/local/src/rawdns
COPY . .
RUN go build -v -mod vendor -o /usr/local/bin/rawdns ./cmd/rawdns

CMD ["rawdns"]
