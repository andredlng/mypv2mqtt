#!/usr/bin/env python

import asyncio
import logging
import os
import traceback

import aiohttp

import iot_daemonize
import iot_daemonize.configuration as configuration

config = None


def publish_payloads(data):
    base_topic = config.mqtt_topic.rstrip('/')
    for key in ('device', 'fwversion', 'psversion', 'coversion', 'temp1'):
        if key not in data:
            continue
        try:
            topic = f"{base_topic}/{key}" if base_topic else key
            logging.info("Topic: {}, Payload: {}".format(topic, data[key]))
            iot_daemonize.mqtt_client.publish(topic, data[key])
        except Exception:
            logging.error(traceback.format_exc())


async def poll_once(session):
    try:
        async with session.get(config.api_url) as resp:
            resp.raise_for_status()
            payload = await resp.json(content_type=None)
            logging.info("URL: {}, Payload: {}".format(config.api_url, payload))
            if isinstance(payload, dict):
                publish_payloads(payload)
    except asyncio.CancelledError:
        raise
    except Exception:
        logging.error(traceback.format_exc())


async def poll_loop_async(stop):
    interval = max(1, int(config.poll_interval))
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop():
            await poll_once(session)
            await asyncio.sleep(interval)


def poll_loop(stop):
    loop = asyncio.new_event_loop()
    loop.run_until_complete(poll_loop_async(stop))


def main():
    global config

    config = configuration.MqttDaemonConfiguration(
        program='mypv2mqtt',
        description='A my-PV ELWA to MQTT bridge'
    )
    config.add_config_arg('mqtt_clientid', flags='--mqtt_clientid', default='mypv2mqtt',
                     help='The clientid to send to the MQTT server. Default is mypv2mqtt.')
    config.add_config_arg('mqtt_topic', flags='--mqtt_topic', default='bus/devices/MYDEVICE',
                     help='The base topic to publish MQTT messages. Default is bus/devices/MYDEVICE.')
    config.add_config_arg('api_url', flags='--api_url', default='URL_REQUIRED',
                     help='Full URL to fetch ELWA JSON data from.')
    config.add_config_arg('poll_interval', flags='--poll_interval', default=10,
                     help='Polling interval in seconds. Default is 10.')
    config.add_config_arg('config', flags=['-c', '--config'], default='/etc/mypv2mqtt.conf',
                     help='The path to the config file. Default is /etc/mypv2mqtt.conf.')
    config.parse_args()

    if config.config and os.path.isfile(config.config):
        config.parse_config(config.config)

    iot_daemonize.init(config, mqtt=True, daemonize=True)

    iot_daemonize.daemon.add_task(poll_loop)

    iot_daemonize.run()


if __name__ == '__main__':
    main()
