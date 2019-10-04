# bastion

Simple, yet reasonably secure SSH bastion with full logging support

## Usage
```bash
# You can use any inetd-like service
# TODO: systemd unit config
socat TCP-LISTEN:2022,reuseaddr,fork,range=127.0.0.1/32 EXEC:"go run cmd/bastion-child/child.go config.yaml"
# Or, simple server:
go run tools/bastiond/cmd/bastiond/main.go tools/bastiond/config/config.yaml
```