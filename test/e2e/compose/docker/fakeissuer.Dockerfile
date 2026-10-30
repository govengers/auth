# The fake OpenID Connect provider of the compose end-to-end stack. Build context: the repository root.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags e2e -trimpath -ldflags="-s -w" -o /out/fakeissuer ./test/e2e/compose/fakeissuer

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/fakeissuer /fakeissuer
USER nonroot:nonroot
ENTRYPOINT ["/fakeissuer"]
