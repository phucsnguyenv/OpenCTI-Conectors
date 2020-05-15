import yaml
import os
import shutil
import time
import csv
from datetime import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable
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
            description="Importing internal data from CSV file",
        )
        self.markingDefinitions = self.helper.api.marking_definition.create(
            definition_type="tlp", definition="TLP:WHITE"
        )
        self.tag = self.helper.api.tag.create(
            tag_type="Internal-Import", value="internal-importer", color="#2e99db"
        )
        self.filename = ""

        self.helper.log_info("Identity id: {}".format(self.identity["id"]))

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
            "domain": "Domain",
        }
        _type = _dict.get(data.lower())
        return _type

    def _process_message(self, data):
        """doing things with data here"""
        created_observable_id_list = []
        created_indicator_id_list = []
        self.helper.log_info("Creating Indicators data")
        for row in data:
            if row[0] == "_report":
                _report = row
            else:
                # creating observable
                observable_type = self._get_type(row[1])
                self.helper.log_info("Creating Observale...")
                created_observable = self.helper.api.stix_observable.create(
                    type=observable_type,
                    observable_value=row[0],
                    createByRef=self.identity["id"],
                    markingDefinitions=self.markingDefinitions["id"],
                    createIndicator=True,
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
                    id=created_observable["id"], external_reference_id=virus_ref["id"]
                )
                self.helper.api.stix_entity.add_external_reference(
                    id=created_observable["id"], external_reference_id=thre_ref["id"]
                )
                # adding tag
                self.helper.api.stix_entity.add_tag(
                    id=created_observable["id"], tag_id=self.tag["id"]
                )
                # this should be stix_id_key
                created_observable_id_list.append(
                    created_observable["stix_id_key"])
                created_indicator_id_list.append(
                    created_observable["indicatorsIds"])
        # Creating report
        self.helper.log_info("Generating report...")
        created_report = self.helper.api.report.create(
            report_class="Internal Report",
            description=_report[1],
            name="Import data from file {}".format(self.filename),
            published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            createByRef=self.identity["id"],
        )
        self.helper.api.stix_entity.add_tag(
            id=created_report["id"], tag_id=self.tag["id"]
        )
        # Adding observale to report
        # self.helper.log_info(created_observable_id_list)
        for created_observable_stix_id in created_observable_id_list:
            self.helper.log_info("Attaching {} to report -- {}".format(created_observable_stix_id, type(created_observable_stix_id)))
            self.helper.api.report.add_stix_observable(
                id=created_report["id"], stix_observable_id=created_observable_stix_id,report=created_report
            )

        self.helper.log_info("Archiving file...")
        # archiving files
        _src = self._data_path + "/files/" + self.filename
        _dest = self._data_path + "/archive"
        shutil.move(_src, _dest)
        self.helper.log_info("Sleeping...")

    def start(self):
        while True:
            self._open_files()
            time.sleep(50)


if __name__ == "__main__":
    try:
        importInstance = InternalImport()
        importInstance.start()
    except Exception as e:
        print(e)
        time.sleep(5)
        exit(0)
