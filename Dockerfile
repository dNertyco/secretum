# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/secretum ./cmd/secretum

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/secretum /secretum
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/secretum"]
