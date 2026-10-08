[![Test with PyTest and Other Tools](https://github.com/fahadahammed/shareit/actions/workflows/testing_pipeline.yml/badge.svg?branch=main)](https://github.com/fahadahammed/shareit/actions/workflows/testing_pipeline.yml)
[![Build and Publish Python Package to PYPI](https://github.com/fahadahammed/shareit/actions/workflows/pypi.yaml/badge.svg?branch=main)](https://github.com/fahadahammed/shareit/actions/workflows/pypi.yaml)


# shareit

A simple Python CLI tool to share files over your local network easily.



## Features
- Share files or directories from your machine over HTTP or HTTPS
- Let other devices upload files into a directory on your machine
- Create, inspect, and remove self-signed HTTPS certificates
- Browse shared files in a web page with breadcrumbs, search, and file details
- Hide sensitive files such as `.env` and `.git` unless you opt in
- Protect a share or upload page with a username and password
- Discoverable on your local network
- Customizable host, port, directory, page title, and log file
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

`share` serves files for download. `upload` does the same and also accepts files from the browser. Both print a URL for every local network address.

### Share files for download

Share a directory:

```bash
shareit share --dir ~/files
```

Share one file. It is copied into a temporary directory and served from there:

```bash
shareit share --file ~/Documents/mydoc.pdf --host 192.168.1.10 --port 9000
```

`share` requires `--dir` or `--file`. The page has no upload form.

### Let others upload files

```bash
shareit upload --dir ~/inbox --host 192.168.1.10 --port 9000
```

`upload` requires `--dir`. Open the printed URL on another device and use the upload form. Files are saved into the folder you are browsing, including subfolders. An existing file is kept; a second file with the same name is saved as `name (1).ext`. `--max-upload-mb` defaults to 512.

### Password protection

`--protected` makes the browser ask for a username and password before the page loads. Set them yourself, or leave either value out and shareit generates it for this run and prints it:

```bash
shareit share --dir ~/files --protected --username ada --password 'your-password'
shareit upload --dir ~/inbox --protected --username ada --password 'your-password'
```

Generate both:

```bash
shareit share --dir ~/files --protected
shareit upload --dir ~/inbox --protected
```

You can also set only `--username` or only `--password`. The missing value is generated. The credentials last until you stop the server. `--username` or `--password` without `--protected` is rejected.

### HTTPS

`--https` serves the page over TLS. With no certificate files, shareit writes a self-signed certificate to `~/.shareit/certs/` and reuses it until it expires:

```bash
shareit share --dir ~/files --https
shareit upload --dir ~/inbox --https --cert ~/certs/shareit.crt --key ~/certs/shareit.key
```

`--cert` and `--key` must be given together, and the key must match the certificate. Password-protected keys are not accepted. Browsers warn about a self-signed certificate until you trust it.

Manage certificates:

```bash
shareit cert generate
shareit cert info
shareit cert remove
```

`cert generate` writes `~/.shareit/certs/shareit.crt` and `shareit.key` unless you pass `--cert` and `--key`. The certificate includes `localhost`, `127.0.0.1`, `::1`, and this machine's local IP addresses.

| Option | Default | Purpose |
| --- | --- | --- |
| `--name` | `shareit` | Common name |
| `--days` | `365` | Lifetime, from 1 to 3650 days |
| `--dns` | | Extra DNS name. Repeat the flag to add more |
| `--ip` | | Extra IP address. Repeat the flag to add more |
| `--skip-lan` | off | Leave out this machine's local IP addresses |
| `--force` | off | Replace an existing certificate and key |

`cert info` prints the subject, issuer, validity, names, fingerprint, and whether the key matches. `cert remove` deletes the certificate and its private key after checking that both files are a real certificate and key.

### Browse page

The page shows the directory you opened, with breadcrumbs, a parent-directory link inside subfolders, a filter box, and columns for name, type, size, and modified time. `--title` changes the heading. The default title is `ShareIt`.

### Sensitive files

These names are hidden, and direct requests to download or upload them are refused:

- `.env` and names that start with `.env`
- `.git`, `.svn`, `.hg`, `.ssh`, `.aws`, `.gnupg`
- `.htpasswd`, `.netrc`, `.npmrc`, `.pypirc`
- `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`
- `credentials.json`, `secrets.json`

`--allow-sensitive` shares them. Sharing a sensitive file or directory by itself also requires that flag.

### Logs

Startup, requests, failed logins, blocked files, and rejected uploads are printed in the terminal. `--log-file` writes the same log to a file:

```bash
shareit upload --dir ~/inbox --log-file ~/shareit.log
```

A busy port and a permissions failure are reported as those errors.

### Options for share and upload

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `0.0.0.0` | Address to bind |
| `--port` | `18338` | Port to bind |
| `--title` | `ShareIt` | Heading in the browser |
| `--protected` | off | Require a username and password |
| `--username` | generated when protected | Basic auth username |
| `--password` | generated when protected | Basic auth password |
| `--https` | off | Serve over HTTPS |
| `--cert` | `~/.shareit/certs/shareit.crt` when `--https` is set | PEM certificate |
| `--key` | `~/.shareit/certs/shareit.key` when `--https` is set | PEM private key |
| `--allow-sensitive` | off | Share hidden files such as `.env` and `.git` |
| `--log-file` | | Also write logs to this file |
| `--max-upload-mb` | `512` | Upload size limit. `upload` only |

When `--host` is `0.0.0.0`, shareit prints every local interface and a URL for it.

## Getting local IP addresses

The tool lists each local network interface, its IP address, and the URL to open.

## Development

Clone the repo and install dependencies:

```bash
git clone https://github.com/fahadahammed/shareit.git
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
- [x] Check some sensitive file sharing mode, like .env, .git, etc.
- [x] Add more CLI options for customization
- [x] Improve error handling and logging
- [x] Add support for HTTPS sharing
- [x] Implement a web interface for browsing shared files
- [x] Add support for file uploads to the shared directory

## License

MIT License
