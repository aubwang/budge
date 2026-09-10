FROM golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir -m 0700 /data
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /budge ./cmd/budge
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /budge /budge
COPY --from=build --chown=65532:65532 /data /data
WORKDIR /data
ENTRYPOINT ["/budge"]
CMD ["server", "--container", "--db", "/data/budge.db", "--owner-listen", "0.0.0.0:18780", "--owner-host", "127.0.0.1:18780", "--device-listen", "0.0.0.0:18781", "--url", "https://localhost:18781"]
