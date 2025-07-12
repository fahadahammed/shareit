[![Test with PyTest and Other Tools](https://github.com/fahadahammed/shareit/actions/workflows/testing_pipeline.yml/badge.svg?branch=main)](https://github.com/fahadahammed/shareit/actions/workflows/testing_pipeline.yml)
[![Build and Publish Python Package to PYPI](https://github.com/fahadahammed/shareit/actions/workflows/pypi.yaml/badge.svg?branch=main)](https://github.com/fahadahammed/shareit/actions/workflows/pypi.yaml)


# shareit

A simple Python CLI tool to share files over your local network easily.



## Features
- Share files or directories from your machine over HTTP
- Discoverable on your local network
- Customizable host, port, and directory
- Beautiful CLI output with rich formatting

## Installation

Install via pip (recommended):

```bash
pip install shareit
```

Or, if using [Poetry](https://python-poetry.org/):

```bash
poetry add shareit
```

## Usage

Share a directory (default: current directory):

```bash
shareit --dir <directory> --host <host> --port <port>
```

Share a specific file:

```bash
shareit --file <file_path> --host <host> --port <port>
```

All arguments are optional:
- `--dir` defaults to current directory
- `--file` is for sharing a single file
- `--host` defaults to `0.0.0.0`
- `--port` defaults to `18338`

Example:

```bash
shareit --file mydoc.pdf --host 192.168.1.10 --port 9000
```

The tool will display a formatted link to access the shared file or directory from other devices on your network.

## Getting Local IP Addresses

The tool will display all local network interfaces and their assigned IP addresses for easy access.

## Development

Clone the repo and install dependencies:

```bash
git clone https://github.com/yourusername/shareit.git
cd shareit
poetry install
```

## Testing

Run tests with:

```bash
pytest
```

## Distribution

To build and publish:

```bash
poetry build
poetry publish
```

## TODO
- [x] Add support for individual file sharing
- [x] Implement authentication for shared directories
- [ ] Check some sensitive file sharing mode, like .env, .git, etc.
- [ ] Add more CLI options for customization
- [ ] Improve error handling and logging
- [ ] Add support for HTTPS sharing
- [ ] Implement a web interface for browsing shared files
- [ ] Add support for file uploads to the shared directory

## License

MIT License
