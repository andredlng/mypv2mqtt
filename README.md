# mypv2mqtt - A my-PV ELWA to MQTT bridge

Polls the JSON status endpoint of a my-PV ELWA and publishes selected values to MQTT.

## Installation

### Native install with Python venv

Requires Python 3.12.

```bash
cd /usr/local/lib
git clone https://c0d3.sh/andre/mypv2mqtt.git
cd mypv2mqtt
./install
```

The `install` script provisions a local virtual environment via `uv` and tries an
editable install. If that fails (e.g. offline builds), the run script still
works against the `src/` layout.

## Configuration

Configuration lives in `/etc/mypv2mqtt.conf` by default (JSON). Each option can
also be set via CLI arguments.

| option            | default                                            | arguments                   | comment                                                      |
|-------------------|----------------------------------------------------|-----------------------------|--------------------------------------------------------------|
| `mqtt_host`       | `localhost`                                        | `-m`, `--mqtt_host`         | MQTT broker hostname                                         |
| `mqtt_port`       | `1883`                                             | `--mqtt_port`               | MQTT broker port                                             |
| `mqtt_keepalive`  | `30`                                               | `--mqtt_keepalive`          | MQTT keep-alive interval (seconds)                           |
| `mqtt_clientid`   | `mypv2mqtt`                                        | `--mqtt_clientid`           | MQTT client id                                               |
| `mqtt_user`       | -                                                  | `-u`, `--mqtt_user`         | MQTT username                                                |
| `mqtt_password`   | -                                                  | `-p`, `--mqtt_password`     | MQTT password                                                |
| `mqtt_topic`      | `bus/devices/MYDEVICE`                             | `-t`, `--mqtt_topic`        | Base topic used for publishing                               |
| `mqtt_tls`        | `false`                                            | `--mqtt_tls`                | Enable TLS                                                   |
| `mqtt_tls_version`| `TLSv1.2`                                          | `--mqtt_tls_version`        | TLS version (TLSv1, TLSv1.1, TLSv1.2)                        |
| `mqtt_verify_mode`| `CERT_REQUIRED`                                    | `--mqtt_verify_mode`        | TLS verify mode (CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED)    |
| `mqtt_ssl_ca_path`| -                                                  | `--mqtt_ssl_ca_path`        | CA file for TLS                                              |
| `mqtt_tls_no_verify`| `false`                                          | `--mqtt_tls_no_verify`      | Disable TLS hostname verification                            |
| `api_url`         | `http://elwa.home-server-01/data.jsn?ip=10.88.1.91` | `--api_url`                 | Full URL to query the ELWA JSON endpoint                     |
| `poll_interval`   | `30`                                               | `--poll_interval`           | Polling interval in seconds                                  |
| `timestamp`       | `false`                                            | `-z`, `--timestamp`         | Publish a timestamp per topic                                |
| `verbose`         | `false`                                            | `-v`, `--verbose`           | Enable DEBUG logging                                         |
| `log_level`       | `INFO`                                             | `--log-level`               | Logging level (CRITICAL, ERROR, WARNING, INFO, DEBUG)        |
| -                 | `/etc/mypv2mqtt.conf`                              | `-c`, `--config`            | Config file path                                             |

### Data points

The bridge currently publishes the following keys from `/data.jsn`:

- `device`
- `fwversion`
- `psversion`
- `coversion`
- `temp1`

### Running

Use the provided run script or invoke via the venv:

```bash
./run -c mypv2mqtt.conf
# or
./venv/bin/python -m mypv2mqtt -c mypv2mqtt.conf --log-level INFO
# or
./venv/bin/mypv2mqtt -c mypv2mqtt.conf --log-level INFO
```

For service management, drop the unit in `systemd/` or use the Supervisor
snippet in `supervisor/`.

## Support

Best-effort only. Please open issues/PRs if you extend it.

## License

BSD-3-Clause, see `LICENSE.md`.
