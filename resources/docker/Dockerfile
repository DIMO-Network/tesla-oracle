FROM golang:1.24 AS build

RUN useradd -u 10001 dimo

WORKDIR /go/src/github.com/DIMO-Network/tesla-oracle/
COPY . /go/src/github.com/DIMO-Network/tesla-oracle/

ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOFLAGS=-mod=vendor

RUN apt-get clean && apt-get update
RUN curl -fsSL https://deb.nodesource.com/setup_21.x | bash -
RUN apt-get install -y nodejs
RUN ls
RUN go mod tidy
RUN go mod vendor
RUN make install
RUN cd web && npm install && npm run build

FROM gcr.io/distroless/static-debian12 AS package

LABEL maintainer="DIMO <hello@dimo.zone>"

WORKDIR /

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /go/src/github.com/DIMO-Network/tesla-oracle/target/bin/tesla-oracle .
COPY --from=build /go/src/github.com/DIMO-Network/tesla-oracle/migrations /migrations
COPY --from=build /go/src/github.com/DIMO-Network/tesla-oracle/web/dist /dist

USER dimo

EXPOSE 8080
EXPOSE 8888

CMD ["/tesla-oracle"]