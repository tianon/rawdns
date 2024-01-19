FROM golang:1.21-alpine3.19

RUN apk add --no-cache ca-certificates

WORKDIR /usr/local/src/rawdns

COPY go.mod go.sum ./
RUN set -eux; \
	go mod download; \
	go mod verify

COPY . .

RUN go build -v -trimpath -o /usr/local/bin/rawdns ./cmd/rawdns

CMD ["rawdns"]
