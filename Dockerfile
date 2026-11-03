# syntax=docker/dockerfile:1

FROM golang:1.24 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/gatelint ./cmd/gatelint

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/gatelint /usr/local/bin/gatelint
WORKDIR /work
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gatelint"]
CMD ["scan", "."]
