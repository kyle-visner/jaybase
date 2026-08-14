# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27rc2-alpine@sha256:dcbb18cc5fa1082364dc6aa95224b6b55429d09cbb9631a053d8064c1c367300 AS build

ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath -ldflags="-s -w" -o /out/jaybase-server ./cmd/jaybase-server
RUN mkdir -p /out/data /out/backups

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/data /var/lib/jaybase
COPY --from=build --chown=65532:65532 /out/backups /var/backups/jaybase
COPY --from=build /out/jaybase-server /jaybase-server
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/jaybase-server"]
CMD ["serve"]
