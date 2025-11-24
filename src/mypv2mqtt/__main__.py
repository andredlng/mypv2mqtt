#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import signal
import sys
import time
from typing import Any, Dict, Optional

import aiohttp
import paho.mqtt.client as mqtt


mqtt_client: Optional[mqtt.Client] = None
daemon_args = None
running = True


verify_mode = {
    'CERT_NONE': __import__('ssl').CERT_NONE,
    'CERT_OPTIONAL': __import__('ssl').CERT_OPTIONAL,
    'CERT_REQUIRED': __import__('ssl').CERT_REQUIRED,
}

tls_versions = {
    'TLSv1': __import__('ssl').PROTOCOL_TLSv1,
    'TLSv1.1': __import__('ssl').PROTOCOL_TLSv1_1,
    'TLSv1.2': __import__('ssl').PROTOCOL_TLSv1_2,
}


def parse_args():
    parser = argparse.ArgumentParser(
        prog='mypv2mqtt',
        description='A my-PV ELWA to MQTT bridge',
        epilog='Have a lot of fun!',
    )
    # MQTT options
    parser.add_argument('-m', '--mqtt_host', type=str, default='localhost', help='MQTT server hostname.')
    parser.add_argument('--mqtt_port', type=int, default=1883, help='MQTT server port.')
    parser.add_argument('--mqtt_keepalive', type=int, default=30, help='MQTT keep alive (seconds).')
    parser.add_argument('--mqtt_clientid', type=str, default='mypv2mqtt', help='MQTT client id.')
    parser.add_argument('-u', '--mqtt_user', type=str, help='MQTT username.')
    parser.add_argument('-p', '--mqtt_password', type=str, help='MQTT password.')
    parser.add_argument('-t', '--mqtt_topic', type=str, default='bus/devices/MYDEVICE', help='Base topic to publish messages.')
    parser.add_argument('--mqtt_tls', default=False, action='store_true', help='Enable MQTT TLS.')
    parser.add_argument('--mqtt_tls_version', type=str, default='TLSv1.2', help='TLS version (TLSv1, TLSv1.1, TLSv1.2).')
    parser.add_argument('--mqtt_verify_mode', type=str, default='CERT_REQUIRED', help='TLS verify mode (CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED).')
    parser.add_argument('--mqtt_ssl_ca_path', type=str, help='CA file path for MQTT TLS.')
    parser.add_argument('--mqtt_tls_no_verify', default=False, action='store_true', help='Disable TLS hostname verification.')

    # App options
    parser.add_argument('--api_url', type=str, default='URL_REQUIRED', help='Full URL to fetch ELWA JSON data from.')
    parser.add_argument('--poll_interval', type=int, default=10, help='Polling interval in seconds.')

    # General
    parser.add_argument('-c', '--config', type=str, default='/etc/mypv2mqtt.conf', help='Path to config file.')
    parser.add_argument('--log-level', type=str, default='INFO', help='Logging level (CRITICAL, ERROR, WARNING, INFO, DEBUG).')
    parser.add_argument('-z', '--timestamp', default=False, action='store_true', help='Publish timestamps for all topics.')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose logging.')
    return parser.parse_args()


def os_path_isfile(path: str) -> bool:
    try:
        import os
        return os.path.isfile(path)
    except Exception:
        return False


def parse_config():
    global daemon_args
    if daemon_args.config and not os_path_isfile(daemon_args.config):
        return
    if not daemon_args.config:
        return
    with open(daemon_args.config, 'r') as f:
        data = json.load(f)
        for k in (
            'mqtt_host',
            'mqtt_port',
            'mqtt_keepalive',
            'mqtt_clientid',
            'mqtt_user',
            'mqtt_password',
            'mqtt_topic',
            'mqtt_tls',
            'mqtt_tls_version',
            'mqtt_verify_mode',
            'mqtt_ssl_ca_path',
            'mqtt_tls_no_verify',
            'api_url',
            'poll_interval',
            'timestamp',
            'verbose',
            'log_level',
        ):
            if k in data:
                v = data[k]
                current = getattr(daemon_args, k, None)
                try:
                    if isinstance(current, bool) and isinstance(v, str):
                        v = v.lower() == 'true'
                    elif isinstance(current, int) and isinstance(v, str):
                        v = int(v)
                    elif isinstance(current, float) and isinstance(v, str):
                        v = float(v)
                except Exception:
                    pass
                setattr(daemon_args, k, v)


def init_mqtt():
    logging.debug('Starting MQTT')
    global daemon_args
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, daemon_args.mqtt_clientid)
    if daemon_args.mqtt_tls:
        cert_reqs = verify_mode.get(daemon_args.mqtt_verify_mode)
        tls_version = tls_versions.get(daemon_args.mqtt_tls_version)
        ca_certs = daemon_args.mqtt_ssl_ca_path if daemon_args.mqtt_ssl_ca_path else None
        client.tls_set(ca_certs=ca_certs, cert_reqs=cert_reqs, tls_version=tls_version)
        client.tls_insecure_set(daemon_args.mqtt_tls_no_verify)
    if daemon_args.verbose:
        client.enable_logger()
    if daemon_args.mqtt_user and daemon_args.mqtt_password:
        client.username_pw_set(daemon_args.mqtt_user, daemon_args.mqtt_password)
    try:
        client.connect_async(daemon_args.mqtt_host, daemon_args.mqtt_port, daemon_args.mqtt_keepalive)
        if hasattr(client, 'reconnect_delay_set'):
            client.reconnect_delay_set(min_delay=1, max_delay=30)
    except Exception as e:
        logging.warning(f"Failed to start MQTT connection: {e}")
    return client


def publish_mqtt(topic: str, value: Any):
    global mqtt_client, daemon_args
    logging.info(f"Topic: {topic}, Payload: {value}")
    mqtt_client.publish(topic, str(value))
    if daemon_args.timestamp:
        mqtt_client.publish(f"{topic}/timestamp", time.time(), retain=True)


def publish_payloads(data: Dict[str, Any]):
    base_topic = daemon_args.mqtt_topic.rstrip('/')
    for key in ('device', 'fwversion', 'psversion', 'coversion', 'temp1'):
        if key not in data:
            continue
        topic = f"{base_topic}/{key}" if base_topic else key
        publish_mqtt(topic, data[key])


async def poll_once(session: aiohttp.ClientSession):
    try:
        logging.debug("Requesting %s", daemon_args.api_url)
        async with session.get(daemon_args.api_url) as resp:
            resp.raise_for_status()
            payload = await resp.json(content_type=None)
            if isinstance(payload, dict):
                publish_payloads(payload)
            else:
                logging.warning("Unexpected payload type: %s", type(payload))
    except asyncio.CancelledError:
        raise
    except Exception as e:
        logging.warning("Failed to fetch data from %s: %s", daemon_args.api_url, e)


async def poll_loop():
    interval = max(1, int(daemon_args.poll_interval))
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while running:
            await poll_once(session)
            await asyncio.sleep(interval)


def shutdown(signum, frame):
    global running
    logging.info('Shutdown...')
    running = False
    try:
        if mqtt_client is not None:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()
    except Exception:
        pass
    logging.info('Bye!')
    sys.exit(0)


async def main_async():
    global mqtt_client

    mqtt_client = init_mqtt()
    mqtt_client.loop_start()

    try:
        await poll_loop()
    finally:
        if mqtt_client is not None:
            mqtt_client.loop_stop()
            mqtt_client.disconnect()


def main():
    global daemon_args
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    daemon_args = parse_args()
    parse_config()

    log_level = logging.INFO
    try:
        log_level = getattr(logging, str(daemon_args.log_level).upper())
    except Exception:
        log_level = logging.INFO
    if daemon_args.verbose:
        log_level = logging.DEBUG
    logging.basicConfig(level=log_level)

    asyncio.run(main_async())


if __name__ == '__main__':
    main()
