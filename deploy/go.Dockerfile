# Builds one Go binary: APP=api | merchant-demo | telegraph-probe
FROM docker.io/library/golang:1.25-alpine AS build
ARG APP=api
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./apps/${APP}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
