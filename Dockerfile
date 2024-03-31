# Use the official Go image as the base image
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files into the container
COPY go.mod .
COPY go.sum .

# Download and install module dependencies
RUN go mod download

# Copy the entire project into the container
COPY . .

# Debugging: Print the contents of the ui/static directory

# Build the Go application
RUN go build -o main .

# Expose the port the application will run on
EXPOSE 8080

# Command to run the application
CMD ["./main"]
