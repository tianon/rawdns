FROM golang:1.25-alpine3.22

RUN apk add --no-cache ca-certificates

WORKDIR /usr/local/src/rawdns

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -v -trimpath -o /usr/local/bin/rawdns ./cmd/rawdns

CMD ["rawdns"]
