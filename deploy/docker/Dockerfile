# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
LABEL org.opencontainers.image.source="https://github.com/trip-nine/flowtrim" org.opencontainers.image.licenses="MIT"
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN mkdir -p /out/state && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/trip-nine/flowtrim/internal/app.Version=${VERSION}" -o /out/flowtrim ./cmd/flowtrim \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/flowgen ./cmd/flowgen \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/mockhec ./cmd/mockhec

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/flowtrim /usr/local/bin/flowtrim
COPY --from=build /out/flowgen /usr/local/bin/flowgen
COPY --from=build /out/mockhec /usr/local/bin/mockhec
COPY examples/flowtrim.yaml /etc/flowtrim/flowtrim.yaml
COPY examples/intel.txt /etc/flowtrim/intel.txt
COPY --from=build --chown=65532:65532 /out/state /var/lib/flowtrim
USER nonroot:nonroot
EXPOSE 2055/udp 4739/udp 6343/udp 8443/tcp 9109/tcp
VOLUME ["/var/lib/flowtrim"]
ENTRYPOINT ["/usr/local/bin/flowtrim"]
CMD ["run", "-config", "/etc/flowtrim/flowtrim.yaml"]
