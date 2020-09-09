FROM golang:1.15-alpine AS builder
WORKDIR /go/src/github.com/kantipov/hlf-cert-exporter
COPY . .
RUN go build

FROM alpine:latest  
WORKDIR /app
COPY --from=builder /go/src/github.com/kantipov/hlf-cert-exporter/hlf-cert-exporter .
CMD ["./hlf-cert-exporter"]
