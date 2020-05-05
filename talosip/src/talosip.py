import yaml
import os
import requests
import json
import wget

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Indicator, IPv4Address, Bundle, FileSystemStore


class Talosip:
    def __init__(self):
        config_file_path = os.path.dirname(
            os.path.abspath(__file__))+"/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.talosip_interval = get_config_variable(
            "TALOSIP_INTERVAL", ["talosip", "interval"], config, True
        )
        self.talosip_url = get_config_variable(
            "TALOSIP_URL", ["talosip", "url"], config
        )
        self.helper = OpenCTIConnectorHelper(config)

    def get_interval(self):
        return int(self.amitt_interval) * 60 * 60 * 24

    def _process_file(self):
        ip_lists = open("ip_blacklist.txt", "r")
        print("File downloaded. Processing data...")
        for ip in ip_lists:
            ip = ip.strip("\n")
            print(ip)
            indicator = self.helper.api.stix_indicator.create(
                type="ipv4-addr",
                observable_value=ip,
                markingDefinitions='TLP:WHITE',
                description="from talos via OPENCTI",

            )
        print(indicator)

    def _send_bundle(self, bundle: Bundle):
        serialized_bundle = bundle.serialize()
        self.helper.send_stix2_bundle(
            serialized_bundle, None, self.update_existing_data, False
        )

    def _create_indicator(self, data):
        # create stix indicator
        _ip = IPv4Address(value=data)
        _indicator = Indicator(
            description="from Talos IP blacklist via Opencti",
            pattern="["+_ip.type+":value = '"+_ip.value+"']",
            labels="ipv4-blacklist"
        )
        return _indicator

    def start(self):
        self._process_file()


if __name__ == "__main__":
    talosipInstance = Talosip()
    talosipInstance.start()
