"""
Support for scanning a network with arp-scan.

For more details about this platform, please refer to the documentation at
https://home-assistant.io/components/device_tracker.arpscan_tracker/
sudo arp-scan --interface=eth0 -l -g --retry=2 -b 2 -T '58:e2:8f:20:b0:45' | grep 192.168.1.75 | wc -l
"""
import logging
import re
import subprocess
from collections import namedtuple
import voluptuous as vol
import homeassistant.util.dt as dt_util
import homeassistant.helpers.config_validation as cv
from homeassistant.components.device_tracker import (
    DOMAIN,
    PLATFORM_SCHEMA,
    DeviceScanner,
)

_LOGGER = logging.getLogger(__name__)

CONF_IP = "ip"
CONF_MAC = "mac"
CONF_DEVICE_NAME = "device_name"
CONF_OPTIONS = "scan_options"
DEFAULT_OPTIONS = "-l -g -t1 -q"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_IP): cv.string,
        vol.Required(CONF_MAC): cv.string,
        vol.Required(CONF_DEVICE_NAME): cv.string,
        vol.Optional(CONF_OPTIONS, default=DEFAULT_OPTIONS): cv.string,
    }
)


def get_scanner(hass, config):
    """Validate the configuration and return a Aruba scanner."""
    return ArpScanDeviceScanner(config[DOMAIN])


Device = namedtuple("Device", ["mac", "name", "ip", "last_update"])


class ArpScanDeviceScanner(DeviceScanner):
    """This class scans for devices connected to the raspberry pi box."""

    def __init__(self, config):
        """Initialize the scanner."""
        self.last_results = []
        self.ip = config[CONF_IP]
        self.mac = config[CONF_MAC]
        self.device_name = config[CONF_DEVICE_NAME]
        self.__options = config[CONF_OPTIONS]
        self.hosts_scanned = []

        _LOGGER.info("Scanner initialized")

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self.__update_info()

        _LOGGER.debug("arp-scan last results %s", self.last_results)

        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        filter_named = [
            result.name for result in self.last_results if result.mac == device
        ]
        if filter_named:
            return filter_named[0]
        return None

    def __update_info(self):
        _LOGGER.debug("Scanning...")

        last_results = []
        now = dt_util.now()
        try:
            result = subprocess.getoutput(
                "arp-scan %s -T %s | grep %s" % (self.__options, self.mac, self.ip)
            ).strip()
            if len(result) == 0:
                _LOGGER.info(
                    "No MAC address found for %s=%s", self.device_name, self.mac
                )
                self.last_results = []
                return False

            data = re.split("\\s+", result)
            last_results.append(Device(data[1].upper(), self.device_name, data[0], now))
        except subprocess.SubprocessError as err:
            print(err)
            _LOGGER.error("arp-scan subprocess error %s", err)
            return False

        self.last_results = last_results

        _LOGGER.debug("arp-scan scan successful")
        return True
