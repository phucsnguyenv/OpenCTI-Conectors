import yaml
import os
import time
import wget
from datetime import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Indicator, IPv4Address, Bundle, ExternalReference, Report, TLP_WHITE


class Talosip:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
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
            type="identity",
            name="Cisco Talos",
            description="Talosintilligence  IP Blacklist"
        )
        

    def get_interval(self):
        return int(self.talosip_interval) * 60 * 60 * 24

    def _process_file(self):
        stix_bundle = []
        stix_indicators = []

        while True:
            black_list_file = os.path.dirname(os.path.abspath(__file__))+"/ip_blacklist.txt"
            if os.path.isfile(black_list_file):
                print("[31] File IP blacklist existing, deleting file...")
                # deleting file....
                os.remove(black_list_file)
                print("[] File deleted.")
            elif not os.path.isfile(black_list_file):
                print("[33] File not exist or deleted. Downloading new file...")
                ip_blacklist = wget.download(
                    self.talosip_url, out="ip_blacklist.txt")
                # processing message...
                ip_lists = open("ip_blacklist.txt", "r")
                print("File downloaded. Processing data...")
                for ip in ip_lists:
                    ip = ip.strip("\n")
                    _indicator = self._create_indicator(ip)
                    stix_indicators.append(_indicator["id"])
                    stix_bundle.append(_indicator)
         # create a report
                _report_uuid = "report--1620352a-00ff-4ab8-97cb-eeaed0779a90"
                _report_external_reference = ExternalReference(
                    source_name="Talos Intelligence",
                    url="https://talosintelligence.com/",
                    external_id="ip-blacklist"
                )

                _report = Report(
                    id=_report_uuid,
                    name="Talos Intelligence IP Blacklist",
                    type="report",
                    description="This report represents the blacklist provided by Cisco Talos",
                    published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    created_by_ref=self.identity["stix_id_key"],
                    object_marking_refs=TLP_WHITE,
                    labels=["threat-report"],
                    object_refs=stix_indicators,
                )
                stix_bundle.append(_report)

                sending_bundle = Bundle(objects=stix_bundle)
                self.helper.send_stix2_bundle(
                    bundle=sending_bundle.serialize(),update=True
                )
                break
            else:
                raise ValueError(
                    "[] Error unknown."
                )

       

    def _create_indicator(self, data):
        # create stix indicator
        _ip = IPv4Address(value=data)
        _indicator = Indicator(
            name=data,
            description="from Talos IP blacklist via Opencti",
            pattern="[" + _ip.type + ":value = '" + _ip.value + "']",
            labels="malicious-activity",
            created_by_ref=self.identity["stix_id_key"],
            object_marking_refs=TLP_WHITE
        )
        return _indicator

    def start(self):
        self._process_file()


if __name__ == "__main__":
    talosipInstance = Talosip()
    talosipInstance.start()
