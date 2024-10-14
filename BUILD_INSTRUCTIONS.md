
# How to Build HMAC File Server

Follow these steps to build HMAC File Server from the source:

## Prerequisites

1. **Go**: Ensure that Go is installed on your system. You can download and install it from [the official Go website](https://golang.org/dl/).
   - To verify Go is installed, run:
     ```bash
     go version
     ```

2. **Git**: Ensure Git is installed. You can check this by running:
   ```bash
   git --version
   ```

## Build Steps

1. **Clone the Repository**:
   First, clone the repository to your local machine if you haven't already:
   ```bash
   git clone git@github.com:yourusername/hmac-file-server.git
   cd hmac-file-server
   ```

2. **Build the Project**:
   Run the following command to build the Go project:
   ```bash
   go build -o hmac-file-server
   ```
   This will compile the project and generate an executable file named `hmac-file-server`.

3. **Run the Application**:
   After the build completes, you can run the application using:
   ```bash
   ./hmac-file-server --config=config.toml
   ```
   Ensure you have a `config.toml` file in the same directory or specify the path to the file.

## (Optional) Installing the Application:

If you'd like to install the binary globally on your system, you can move the built binary to a directory in your system's `PATH`, such as `/usr/local/bin`:

```bash
sudo mv hmac-file-server /usr/local/bin/
```

Now you can run `hmac-file-server` from anywhere in your terminal.

## Rebuilding after Changes:

Whenever you make changes to the source code, you can rebuild the application by simply running `go build` again.
