FROM golang:1.25-alpine3.23

RUN apk add --no-cache ca-certificates

ENV GOCACHE /go/cache

WORKDIR /usr/local/src/rawdns

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN --mount=type=cache,target=$GOCACHE \
	go build -v -trimpath -o /usr/local/bin/rawdns ./cmd/rawdns

CMD ["rawdns"]
