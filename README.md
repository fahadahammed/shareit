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

```bash
shareit --dir <directory> --host <host> --port <port>
```

All arguments are optional:
- `--dir`   : Directory to share (default: current directory)
- `--host`  : Host to bind (default: 0.0.0.0)
- `--port`  : Port to use (default: 18338)

Example:

```bash
shareit --dir . --host 0.0.0.0 --port 18338
```

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

## License

MIT License
