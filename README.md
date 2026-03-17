# sni-probe

A lightweight Go tool for probing and analyzing TLS SNI (Server Name Indication) across network connections.

## Features
- Probe TLS endpoints and extract SNI information
- Useful for network diagnostics, censorship research, and infrastructure debugging
- Written in Go with zero external dependencies

## Usage
```bash
go build -o sni-probe
./sni-probe <target>
```

## Built With
- Go
- Standard library net/tls