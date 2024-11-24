FROM golang:1.22.7-alpine3.19 AS builder

EXPOSE 8080

WORKDIR /go

COPY . /go

RUN go build -o mock-server server.go

FROM alpine:3.19

COPY --from=builder /go .

CMD ["/mock-server"]
