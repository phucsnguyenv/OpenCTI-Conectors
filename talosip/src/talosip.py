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

        self.identity = self.helper.api.identity.create(
            type="identiry",
            name="Cisco Talos"
        )
        self.marker_definition = self.helper.api.marking_definition.create(
            type="marking-definition",
            name="Ipv4-blacklist",
            definition_type="statement",
            definition="Cisco"
        )

    def get_interval(self):
        return int(self.amitt_interval) * 60 * 60 * 24

    def _process_file(self):
        ip_lists = open("ip_blacklist.txt", "r")
        print("File downloaded. Processing data...")
        for ip in ip_lists:
            ip = ip.strip("\n")
            observable = self.helper.api.stix_observable.create(
                type="ipv4-addr",
                observable_value=ip,
                description="from talos via OPENCTI",
                createdByRef=self.identity,
                createIndicator="True",
                markingDefinitions=self.marker_definition
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
