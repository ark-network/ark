# Use official Go image as base
FROM golang:1.21-alpine

# Install git (needed for go install)
RUN apk add --no-cache git

# Install nak
RUN go install github.com/fiatjaf/nak@latest

# Expose default nak port
EXPOSE 10547

# Run nak relay
CMD ["nak", "serve"]

