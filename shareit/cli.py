import argparse
import psutil
import ipaddress
import os
from rich import print as rprint
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

import uuid
import shutil

import http.server as http_server
import socketserver

# Function to read the version from pyproject.toml
def read_pyproject_toml():
    the_pyproject_toml_file = os.path.dirname(os.path.realpath(__file__)) \
                              + os.sep + "pyproject.toml"
    if not os.path.exists(the_pyproject_toml_file):
        the_pyproject_toml_file = the_pyproject_toml_file.replace("/shareit", "", 1)
    with open(file=the_pyproject_toml_file, mode='r', encoding='utf-8') as tomlfile:
        lines = tomlfile.readlines()
        for line in lines:
            if "version" in line:
                return line.split('"')[-2]
        return ""


def generate_temporary_dir(the_path):
    """Generate a unique identifier for the file sharing session."""
    dir_name = f".tmp_dir_{uuid.uuid4()}"
    temp_dir = os.path.join(the_path, dir_name)
    os.makedirs(temp_dir, exist_ok=True)
    return dir_name

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_all_ip_addresses():
    """Return a dict of interface: [ip addresses] using psutil for cross-platform support."""
    ip_dict = {}
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # AF_INET
                ip_dict.setdefault(iface, []).append(addr.address)
    return ip_dict

def file_share(directory=None, file=None, host="0.0.0.0", port=18338):
    """Function to share files over the network."""
    if not directory and not file:
        rprint("[bold red]Error:[/] You must specify either a directory or a file to share.")
        exit(1)

    rprint(Panel.fit(f"[bold green]Sharing directory:[/] [yellow]{directory}[/] on [cyan]{host}:{port}[/]", title="[bold blue]shareit File Server"))
    if not os.path.isdir(directory):
        rprint(f"[bold red]Error:[/] The directory [yellow]{directory}[/] does not exist or is not a directory.")
        return
    rprint(f"[bold green]Directory [yellow]{directory}[/] is valid. Ready to share files.[/]")

    # If a file is specified, copy it to the directory to share
    if file:
        if not os.path.isfile(file):
            rprint(f"[bold red]Error:[/] The file [yellow]{file}[/] does not exist or is not a file.")
            return
        try:
            # Copy the file to the directory to share
            shutil.copy(file, directory)
            rprint(f"[bold green]File [yellow]{file}[/] copied to [yellow]{directory}[/] for sharing.[/]")
        except Exception as e:
            rprint(f"[bold red]Error:[/] Failed to copy file: {e}")
            return

    os.chdir(directory)  # Change to the directory to share

    handler = http_server.SimpleHTTPRequestHandler
    with socketserver.TCPServer((host, port), handler) as httpd:
        rprint(Panel.fit("[bold green]File sharing service started successfully![/]", title="[bold blue]Server Status"))
        if host == "0.0.0.0":
            rprint("[bold yellow]Files are available on the following IP addresses:[/]")
            table = Table(title="Access URLs", show_header=True, header_style="bold magenta")
            table.add_column("Interface", style="dim")
            table.add_column("IP Address")
            table.add_column("URL")
            for iface, ips in get_all_ip_addresses().items():
                for ip in ips:
                    if ip != "0.0.0.0":
                        url = f"http://{ip}:{port}"
                        if file:
                            url += f"/{os.path.basename(file)}"
                        table.add_row(iface, ip, url)
            rprint(table)
        else:
            url = f"http://{host}:{port}"
            rprint(f"[bold green]Serving HTTP on [yellow]{host}:{port}[/] ([cyan]{url}[/])")
            rprint(f"[bold blue]Access your files at [underline]{url}[/]")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()

            # Change the working directory to parent
            parent_path = os.path.dirname(os.getcwd())  # Move to parent directory
            os.chdir(parent_path)

            # Remove the temporary directory if it was created and is inside the current working directory
            if os.path.exists(directory) and os.path.basename(directory).startswith(".tmp_dir_"):
                shutil.rmtree(directory, ignore_errors=True)

            rprint("\n[bold red]Server stopped by user.[/]")


def main():
    parser = argparse.ArgumentParser(description="Share files over the network.")
    parser.add_argument('--version', action='version', version="shareit, " + read_pyproject_toml())
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dir', type=str, help='Directory to share')
    group.add_argument('--file', type=str, help='File to share')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=18338, help='Port to bind (default: 18338)')
    args = parser.parse_args()
    rprint("[bold white]Welcome to shareit CLI File Sharing Tool[/]")
    rprint("[bold white]───────────────────────────────────────────")
    ip_addresses = ["0.0.0.0"]

    the_host = args.host
    if not is_valid_ip(args.host):
        rprint(f"[bold white]Provided host {args.host} is not a valid IP address. Using default host: 0.0.0.0")
        the_host = "0.0.0.0"

    for iface, ips in get_all_ip_addresses().items():
        for ip in ips:
            ip_addresses.append(ip)
    ip_addresses.remove("127.0.0.1") # Exclude loopback address
    if the_host not in ip_addresses:
        rprint("[bold white]Provided host is not a valid local IP address. Select appropriate host from the following:")

        table = Table(title="Available IP Addresses", show_header=True, header_style="bold magenta")
        table.add_column("Index", style="dim")
        table.add_column("IP Address")
        for idx, ip in enumerate(ip_addresses):
            table.add_row(str(idx), ip)
        rprint(table)

        ip_choice = Prompt.ask("[bold green]Enter the index of the IP address you want to use[/]")

        try:
            ip_choice = int(ip_choice)
            if 0 <= ip_choice < len(ip_addresses):
                the_host = ip_addresses[ip_choice]
            else:
                rprint("[bold white]Invalid index. Using default host.")
        except ValueError:
            rprint("[bold orange]Invalid input. Using default host.")
            rprint(f"Using host: {the_host}")
    rprint(f"Using host: {the_host}")
    try:
        if args.dir:
            rprint(f"[bold white]Sharing directory: {args.dir}[/]")
            file_share(directory=args.dir, host=the_host, port=args.port)
        else:
            rprint(f"[bold white]Sharing file: {args.file}[/]")
            if not os.path.isfile(args.file):
                rprint(f"[bold red]Error:[/] The file [yellow]{args.file}[/] does not exist or is not a file.")
                exit(1)
            dir_path = generate_temporary_dir(the_path=".")
            file_share(directory=dir_path,file=args.file, host=the_host, port=args.port)
    except Exception as e:
        rprint(f"[bold red]Error:[/] {e}")
        rprint("[bold red]Failed to start file sharing service.[/]")
        rprint("[bold yellow]Make sure the directory exists and you have permission to access it.[/]")
        rprint("[bold yellow]You can also try running the script with elevated privileges if necessary.[/]")
        rprint("[bold red]Exiting...[/]")
        exit(1)




if __name__ == "__main__":
    main()
