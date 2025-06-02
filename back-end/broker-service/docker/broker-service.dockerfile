# Use a Golang image to build the binary
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy Go module files first for caching dependencies
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the Go source code
COPY src /app/src

# Build the Go application as a static binary (Make sure the binary is generated in the bin folder)
RUN go build -o /app/bin/broker-serviceBinary ./src/cmd/

# Final lightweight image
FROM alpine:latest

# Set working directory for the final image
WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/bin/broker-serviceBinary .

# Run the binary
CMD ["/app/broker-serviceBinary"]