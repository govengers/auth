# Build context is the repository root: docker build -f docker/forwardauth.Dockerfile .
# Base images are pinned by digest (the tag stays readable); Dependabot proposes the bumps.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:670bb5aa5349ae03b8516764718486f4f16399134bdc9acd0c46a23f043ab05c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/forwardauth ./cmd/forwardauth

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/forwardauth /forwardauth
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/forwardauth"]
