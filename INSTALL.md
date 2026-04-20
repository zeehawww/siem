# Aegis SIEM — Terminal Install Guide

## One-line install (recommended)

```bash
python3 -m pip install --upgrade "git+https://github.com/zeehawww/siem.git"
```

## Verify install

```bash
aegis help
```

## First run

```bash
aegis analyze
aegis status
aegis serve
```

Open: `http://127.0.0.1:5001`

## Optional: real-time network syslog

In the dashboard open **Live Data** and start the UDP listener.
Then send a test event from another machine:

```bash
logger -n <SIEM_HOST_IP> -P 5140 "Failed password for testuser from 1.2.3.4 port 22"
```

## Troubleshooting

- If `aegis` not found:
  - reinstall with `--user`:
    ```bash
    python3 -m pip install --user --upgrade "git+https://github.com/zeehawww/siem.git"
    ```
  - add user Python bin to your shell PATH.

- If dashboard port busy:
  - stop old process or run only one `aegis serve` instance.
