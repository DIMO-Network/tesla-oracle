FROM golang:1.24 AS build

RUN useradd -u 10001 dimo

WORKDIR /go/src/github.com/DIMO-Network/tesla-oracle/
COPY . /go/src/github.com/DIMO-Network/tesla-oracle/

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOFLAGS=-mod=vendor

RUN ls
RUN go mod tidy
RUN go mod vendor
RUN make install

FROM busybox AS package

LABEL maintainer="DIMO <hello@dimo.zone>"

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /go/src/github.com/DIMO-Network/tesla-oracle/target/bin/tesla-oracle .

USER dimo

EXPOSE 8888

CMD /tesla-oracle