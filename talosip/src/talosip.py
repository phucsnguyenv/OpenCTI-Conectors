import yaml
import os
import time
import wget
from datetime import datetime
import shutil

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import TLP_WHITE
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
        # get tag
        self.talos_tag = self.helper.api.tag.create(
            tag_type="Event", value="TalosIntelligence", color="#fc036b"
        )
        self.ipv4_tag = self.helper.api.tag.create(
            tag_type="Event", value="ipv4-blacklist", color="#1c100b"
        )
        # create identity
        self.helper.log_info("Creating an Identity...")
        self.entity_identity = self.helper.api.identity.create(
            name="Cisco Talos",
            type="Organization",
            description="Talosintilligence IP Blacklist",
        )
        # create marking definition
        self.tlp_white_marking_definition = self.helper.api.marking_definition.read(
            filters={"key": "definition", "values": ["TLP:WHITE"]}
        )
        # report published time
        self.published_report = None
        self.being_added = []
        self.being_deleted = []

    def delete_old_entity(self):
        if len(self.being_deleted) > 0:
            self.helper.log_info("Deleting old entity")
            for ip in self.being_deleted:
                object_result = self.helper.api.stix_observable.read(
                    filters=[{"key": "observable_value", "values": [ip]}],
                )
                self.helper.api.stix_observable.delete(id=object_result["id"])
                for indicator_id in object_result["indicatorsIds"]:
                    self.helper.api.stix_domain_entity.delete(id=indicator_id)
                for external_ref_id in object_result["externalReferencesIds"]:
                    self.helper.api.stix_domain_entity.delete(id=external_ref_id)
        else:
            self.helper.log_info("Nothing to delete")

    def _get_published_report(self):
        published_time = (
            os.path.dirname(os.path.abspath(__file__)) + "/published_time.txt"
        )
        # Set and store published time to file. If file exists, get published time from file --> Avoid create new report
        if os.path.isfile(published_time):
            self.helper.log_info("Getting published time from file")
            read = open("published_time.txt", "r")
            published = read.read()
        else:
            self.helper.log_info("Setting new time")
            published = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            write = open("published_time.txt", "w")
            write.write(published)
        return published

    def check_diff(self, newfile, oldfile):
        # should use try except
        try:
            old_iplist = open(oldfile, "r")
        except:
            old_iplist = []
        new_iplist = open(newfile, "r")
        parsed_old_list = []
        parsed_new_list = []
        for ip in old_iplist:
            ip = ip.strip("\n")
            parsed_old_list.append(ip)
        for ip in new_iplist:
            ip = ip.strip("\n")
            parsed_new_list.append(ip)
        self.being_added = [ip for ip in parsed_new_list if ip not in parsed_old_list]
        self.being_deleted = [ip for ip in parsed_old_list if ip not in parsed_new_list]
        self.helper.log_info(
            "{}/{} IOCs that are new will be added.".format(
                len(self.being_added), len(parsed_new_list)
            )
        )
        self.helper.log_info(
            "{} IOCs that are no longer in the list will be deleted.".format(
                len(self.being_deleted)
            )
        )

    def get_interval(self):
        return int(self.talosip_interval) * 60 * 60 * 24

    def _create_observable(self, ip):
        # creating observable
        created_observable = self.helper.api.stix_observable.create(
            type="IPv4-Addr",
            observable_value=ip,
            createdByRef=self.entity_identity["id"],
            description="from talosip",
            markingDefinitions=self.tlp_white_marking_definition["id"],
            createIndicator=False,
            update=self.update_existing_data,
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
        return created_observable

    def _create_indicator(self, ip, observable_id):
        # create indicator
        created_indicator = self.helper.api.indicator.create(
            name=ip,
            indicator_pattern="[ipv4-addr:value = '" + ip + "']",
            markingDefinitions=self.tlp_white_marking_definition["id"],
            update=self.update_existing_data,
            main_observable_type="ipv4-addr",
            description="from talosip",
        )
        # add tags
        self.helper.api.stix_entity.add_tag(
            id=created_indicator["id"], tag_id=self.ipv4_tag["id"]
        )
        self.helper.api.stix_entity.add_tag(
            id=created_indicator["id"], tag_id=self.talos_tag["id"]
        )
        # link to observable
        self.helper.log_info("Adding observable...")
        self.helper.api.indicator.add_stix_observable(
            id=created_indicator["id"], stix_observable_id=observable_id
        )

        return created_indicator

    def _process_file(self):
        created_observable_id = []
        created_indicator_id = []
        new_black_list_file = (
            os.path.dirname(os.path.abspath(__file__)) + "/ip_blacklist.txt"
        )
        old_black_list_file = (
            os.path.dirname(os.path.abspath(__file__)) + "/old_ip_blacklist.txt"
        )

        # always fetch new file
        if os.path.isfile(new_black_list_file):
            self.helper.log_info(
                "[48] File IP blacklist existing, changing name to old file"
            )
            # deleting file....
            shutil.move(new_black_list_file, old_black_list_file)
            self.helper.log_info("[50] File name changed.")

        self.helper.log_info("Downloading file from {}".format(self.talosip_url))
        wget.download(self.talosip_url, out="ip_blacklist.txt")
        # processing message...
        self.helper.log_info("[59] File downloaded. Processing data...")
        self.check_diff(new_black_list_file, old_black_list_file)
        for ip in self.being_added:
            created_observable = self._create_observable(ip)
            created_indicator = self._create_indicator(ip, created_observable["id"])
            created_observable_id.append(created_observable["id"])
            created_indicator_id.append(created_indicator["id"])
            # create a report
            # create external reference
        self.helper.log_info("Creating external reference...")
        _report_external_reference = self.helper.api.external_reference.create(
            source_name="Talos Intelligence", url="https://talosintelligence.com/",
        )
        self.helper.log_info("Creating report...")
        # create report
        created_report = self.helper.api.report.create(
            name="Talos Intelligence IP Blacklist",
            published=self._get_published_report(),
            markingDefinitions=self.tlp_white_marking_definition["id"],
            description="This report represents the blacklist provided by Cisco Talos",
            report_class="Threat Report",
            createdByRef=self.entity_identity["id"],
            external_reference_id=_report_external_reference["id"],
            update=self.update_existing_data,
            modified=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        # add tag to report
        self.helper.api.stix_entity.add_tag(
            id=created_report["id"], tag_id=self.talos_tag["id"]
        )
        # add observables to report from id list
        self.helper.log_info("Adding observables to report...")
        for observable_id in created_observable_id:
            self.helper.api.report.add_stix_observable(
                id=created_report["id"], stix_observable_id=observable_id
            )
            # add indicators to report from id list
        self.helper.log_info("Adding entity...")
        for indicator_id in created_indicator_id:
            self.helper.api.report.add_stix_entity(
                id=created_report["id"], entity_id=indicator_id
            )
        self.delete_old_entity()

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
