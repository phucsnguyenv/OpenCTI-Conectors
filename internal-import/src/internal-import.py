import yaml
import os
import shutil
import time
import csv
from datetime import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Report, TLP_WHITE, Identity, Indicator
from pycti.utils.constants import CustomProperties


class InternalImport:
    def __init__(self):
        # get config variable
        config_file_path = os.path.dirname(
            os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, Loader=yaml.FullLoader))
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

        self.update_existing_data = get_config_variable(
            "UPDATE_EXISTING_DATA", ["connector",
                                     "update_existing_data"], config
        )
        self._data_path = os.path.dirname(os.path.abspath(__file__)) + "/data"
        self.identity = self.helper.api.identity.create(
            name="Internal Collector",
            type="User",
            description="Importing internal data from CSV file"
        )
        self.markingDefinitions = self.helper.api.marking_definition.create(
            definition_type="tlp",
            definition="TLP:WHITE"
        )
        self.tag = self.helper.api.tag.create(
            tag_type="Internal-Import",
            value="internal-importer",
            color="#2e99db"
        )
        self.stix_tag = [
            {"tag_type":"Internal-Import", "value":"internal-importer", "color":"#2e99db"}
        ]
        self.filename = ""

    def _read_file(self, data):
        """reading data from a file"""
        with open(data, newline="") as csvfile:
            reader = csv.reader(csvfile, delimiter=",")
            self._process_message(reader)

    def _open_files(self):
        """Listing all files in the folder"""
        _list_files = os.listdir(self._data_path + "/files")
        if _list_files.__len__() > 1:
            self.helper.log_info("Reading all files in folder")
            for _file in _list_files:
                if _file != "sample.csv":
                    self.filename = _file
                    _file = self._data_path + "/files/" + _file
                    self._read_file(_file)
        else:
            self.helper.log_info("No files. Sleeping...")

    def _get_type(self, data):
        _dict = {
            "md5": "File-MD5",
            "ip": "IPv4-Addr",
            "url": "URL",
            "sha1": "File-SHA1",
            "sha256": "File-SHA256",
            "domain": "Domain"
        }
        _type = _dict.get(data)
        return _type

    def _process_message(self, data):
        """doing things with data here"""
        list_observale = []
        self.helper.log_info("Creating Indicators data")
        for row in data:
            if row[0] == "_report":
                _report = row
            else:
                # creating observable
                _observable_type = self._get_type(row[1])
                self.helper.log_info("Creating Observale...")
                _observable = self.helper.api.stix_observable.create(
                    type=_observable_type,
                    observable_value=row[0],
                    createByRef=self.identity["id"],
                    markingDefinitions=self.markingDefinitions["id"],
                    createIndicator=True
                )

                # create external references
                virus_ref = self.helper.api.external_reference.create(
                    source_name="Virustotal " + row[0],
                    url="https://www.virustotal.com/gui/search/" + row[0],
                )
                thre_ref = self.helper.api.external_reference.create(
                    source_name="Threatcrowd " + row[0],
                    url="https://www.threatcrowd.org/pivot.php?data=" + row[0],
                )
                # attach external references to observable
                self.helper.api.stix_entity.add_external_reference(
                    id=_observable["id"],
                    external_reference_id=virus_ref["id"]
                )
                self.helper.api.stix_entity.add_external_reference(
                    id=_observable["id"],
                    external_reference_id=thre_ref["id"]
                )
                # adding tag
                self.helper.api.stix_entity.add_tag(
                    id=_observable["id"],
                    tag_id=self.tag["id"]
                )
                list_observale.append(_observable["id"])
                # create indicator
                # _indicator = self.helper.api.indicator.create(
                #     name=row[0],
                #     pattern_type="stix",
                #     main_observable_type=_observable_type,
                #     indicator_pattern="[" +
                #     _observable_type+":value='"+row[0]+"']",
                #     createByRef=self.identity["id"],
                #     markingDefinitions=self.markingDefinitions["id"]
                # )
                # stix_indicator = Indicator(
                #     name=row[0],
                #     labels="malware-activity",
                #     description="IOC imported from "+self.filename,
                #     pattern="[" +
                #     _observable_type+":value='"+row[0]+"']",
                #     created_by_ref=self.identity["stix_id_key"],
                #     object_marking_refs=self.markingDefinitions["stix_id_key"],
                #     custom_properties={CustomProperties.TAG_TYPE: self.stix_tag}
                # )
                # bundle.append(stix_indicator)
        # Creating report
        self.helper.log_info("Generating report...")
        report = self.helper.api.report.create(
            report_class= "Internal Report",
            description=_report[1],
            name="Import data from file: {}".format(self.filename),
            published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            createByRef=self.identity["id"],
        )
        for obser_id in list_observale:
            self.helper.api.report.contains_stix_observable(
                id=report["id"],
                stix_observable_id=obser_id
            )
        # stix_report = Report(
        #     name="Import data locally from file {}".format(self.filename),
        #     published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        #     type="report",
        #     description=report[1],
        #     object_marking_refs=self.markingDefinitions["stix_id_key"],
        #     created_by_ref=self.identity["stix_id_key"],
        #     labels=["threat-report"],
        #     object_refs=indicator_id_list
        # )
        # bundle.append(stix_report)
        # sending_stix_bundle = Bundle(objects=bundle)
        # self.helper.send_stix2_bundle(
        #     bundle=sending_stix_bundle.serialize(), update=self.update_existing_data
        # )
        self.helper.log_info("Bundle sent.")
        self.helper.log_info("Archiving file...")
        # archiving files
        _src = self._data_path + "/files/" + self.filename
        _dest = self._data_path + "/archive"
        shutil.move(_src, _dest)
        self.helper.log_info("Sleeping...")

    def start(self):
        while True:
            self._open_files()
            time.sleep(60)


if __name__ == "__main__":
    try:
        importInstance = InternalImport()
        importInstance.start()
    except Exception as e:
        print(e)
        time.sleep(2)
        exit(0)
