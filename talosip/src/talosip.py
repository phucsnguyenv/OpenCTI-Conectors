import yaml
import os
import time
import wget
from datetime import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import (
    Indicator,
    IPv4Address,
    Bundle,
    ExternalReference,
    Report,
    TLP_WHITE,
    Identity,
)
from pycti.utils.constants import CustomProperties


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
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.helper.log_info("Creating an Identity...")
        self.identity = Identity(
            type="identity",
            name="Cisco Talos",
            description="Talosintilligence  IP Blacklist",
            identity_class="organization",
        )
        self.tags = [
            {"tag_type": "Event", "value": "TalosIntelligence", "color": "#fc036b"},
            {"tag_type": "Event", "value": "ipv4-blacklist", "color": "#1c100b"},
        ]
        # get tag
        self.talos_tag = self.helper.api.tag.create(
            tag_type="Event", value="TalosIntelligence", color="#fc036b"
        )
        self.ipv4_tag = self.helper.api.tag.create(
            tag_type="Event", value="ipv4-blacklist", color="#1c100b"
        )
        self.entity_identity = self.helper.api.identity.create(
            name="Cisco Talos",
            type="Organization",
            description="Talosintilligence  IP Blacklist",
        )
        self.tlp_white_marking_definition = self.helper.api.marking_definition.read(
            filters={"key": "definition", "values": ["TLP:WHITE"]}
        )

    def get_interval(self):
        return int(self.talosip_interval) * 60 * 60 * 24

    def _create_observable(self, ip):
        # creating observable
        created_observable = self.helper.api.stix_observable.create(
            type="IPv4-Addr",
            observable_value=ip,
            createdByRef=self.entity_identity["id"],
            description="from talos via OpenCTI",
            markingDefinitions=self.tlp_white_marking_definition["id"],
        )
        # adding tag to created observable
        self.helper.api.stix_entity.add_tag(
            id=created_observable["id"], tag_id=self.talos_tag["id"]
        )
        self.helper.api.stix_entity.add_tag(
            id=created_observable["id"], tag_id=self.ipv4_tag["id"]
        )
        # create external references
        virus_ref = self.helper.api.external_reference.create(
            source_name="Virustotal " + ip,
            url="https://www.virustotal.com/gui/search/" + ip,
        )
        thre_ref = self.helper.api.external_reference.create(
            source_name="Threatcrowd " + ip,
            url="https://www.threatcrowd.org/pivot.php?data=" + ip,
        )
        # adding external references
        self.helper.api.stix_entity.add_external_reference(
            id=created_observable["id"], external_reference_id=virus_ref["id"]
        )
        self.helper.api.stix_entity.add_external_reference(
            id=created_observable["id"], external_reference_id=thre_ref["id"]
        )

    def _process_file(self):
        stix_bundle = []
        stix_indicators = []
        stix_bundle.append(self.identity)
        while True:
            black_list_file = (
                os.path.dirname(os.path.abspath(__file__)) + "/ip_blacklist.txt"
            )
            if os.path.isfile(black_list_file):
                self.helper.log_info(
                    "[48] File IP blacklist existing, deleting file..."
                )
                # deleting file....
                os.remove(black_list_file)
                self.helper.log_info("[50] File deleted.")
            elif not os.path.isfile(black_list_file):
                self.helper.log_info(
                    "[54] File not exist or deleted. Downloading new file..."
                )
                self.helper.log_info(
                    "Downloading file from {}".format(self.talosip_url)
                )
                wget.download(self.talosip_url, out="ip_blacklist.txt")
                # processing message...
                ip_lists = open("ip_blacklist.txt", "r")
                self.helper.log_info("[59] File downloaded. Processing data...")
                for ip in ip_lists:
                    ip = ip.strip("\n")
                    _indicator = self._create_indicator(ip)
                    self._create_observable(ip)
                    stix_indicators.append(_indicator["id"])
                    stix_bundle.append(_indicator)
                # create a report
                _report_uuid = "report--1620352a-00ff-4ab8-97cb-eeaed0779a90"
                _report_external_reference = ExternalReference(
                    source_name="Talos Intelligence",
                    url="https://talosintelligence.com/",
                    external_id="ip-blacklist",
                )
                self.helper.log_info("Creating report...")
                _report = Report(
                    id=_report_uuid,
                    name="Talos Intelligence IP Blacklist",
                    type="report",
                    description="This report represents the blacklist provided by Cisco Talos",
                    published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                    created_by_ref=self.identity,
                    object_marking_refs=TLP_WHITE,
                    labels=["threat-report"],
                    external_references=_report_external_reference,
                    object_refs=stix_indicators,
                    custom_properties={CustomProperties.TAG_TYPE: self.tags},
                )
                stix_bundle.append(_report)
                # sending bundle
                self.helper.log_info("Sending bundle....")
                sending_bundle = Bundle(objects=stix_bundle)
                self.helper.send_stix2_bundle(
                    bundle=sending_bundle.serialize(), update=self.update_existing_data
                )
                self.helper.log_info("STIX Bundle has been sent.")
                break
            else:
                raise ValueError("[] Error unknown.")

    def _create_indicator(self, data):
        # create stix indicator
        _ip = IPv4Address(value=data)
        _indicator = Indicator(
            name=data,
            description="from Talos IP blacklist via Opencti",
            pattern="[" + _ip.type + ":value = '" + _ip.value + "']",
            labels="malicious-activity",
            created_by_ref=self.identity,
            object_marking_refs=TLP_WHITE,
            custom_properties={CustomProperties.TAG_TYPE: self.tags},
        )
        return _indicator

    def start(self):
        self.helper.log_info("[111] Fetching Talos IP database...")
        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    self.helper.log_info(
                        "[119] Connector last run: "
                        + datetime.utcfromtimestamp(last_run).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        )
                    )
                else:
                    last_run = None
                    self.helper.log_info("[126] Connector has never run")
                if last_run is None or (
                    (timestamp - last_run)
                    > ((int(self.talosip_interval)) * 60 * 60 * 24)
                ):
                    self.helper.log_info("[131] Connector will run!")
                    self._process_file()
                    self.helper.log_info(
                        "[134] Connector successfully run, storing last_run as "
                        + str(timestamp)
                    )
                    self.helper.set_state({"last_run": timestamp})
                    self.helper.log_info(
                        "[137] Last_run stored, next run in: "
                        + str(round(self.get_interval() / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(60)
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "[145] Connector will not run, next run in: "
                        + str(round(new_interval / 60 / 60 / 24, 2))
                        + " days"
                    )
                    time.sleep(3600)
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("[151] Connector stop")
                exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
                time.sleep(60)


if __name__ == "__main__":
    try:
        talosipInstance = Talosip()
        talosipInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
