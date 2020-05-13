import yaml
import os
import json
import shutil
import time
import csv

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Report, TLP_WHITE
from pycti.utils.constants import CustomProperties


class ExRefAdd():
    def __init__(self):
        # get config variable
        config_file_path = os.path.dirname(
            os.path.abspath(__file__))+"/config.yml"
        config = (yaml.load(open(config_file_path, Loader=yaml.FullLoader)) if os.path.isfile(config_file_path)
                  else {}
                  )
        self.helper = OpenCTIConnectorHelper(config)

        self.update_existing_data = get_config_variable(
            "UPDATE_EXISTING_DATA", ["connector",
                                     "update_existing_data"], config
        )
        self._data_path = os.path.dirname(os.path.abspath(__file__))+"/data"
        self.marking_definition = self.helper.api.marking_definition.create(
            definition_type="tlp",
            definition="white"
        )
        self.identity = self.helper.api.identity.create(
            name="Internal Collector",
            Description="Internal",
            markingDefinitions=self.marking_definition["id"],
            identity_class="organization"
        )
        self.tag1 = self.helper.api.tag.create(
            value="internal-import",
            color="#2e99db"
        )
        self.filename = ''

    def _read_file(self, data):
        """reading data from a file"""
        with open(data, newline='') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            self._process_message(reader)

    def _open_files(self):
        """Listing all files in the folder"""
        _list_files = os.listdir(self._data_path+"/files")
        if (_list_files.__len__() > 1):
            self.helper.log_info("Reading all files in folder")
            for _file in _list_files:
                if(_file != "sample.csv"):
                    self.filename = _file
                    _file = self._data_path+"/files/"+_file
                    self._read_file(_file)
        else:
            self.helper.log_info("No files. Sleeping...")

    def _process_message(self, data):
        _isvalid = 0
        observable_id_list = []
        observable_list = []
        bundle = []
        """doing things with data here"""
        self.helper.log_info("Creating Observable data")
        for row in data:
            if(row[0] == "_report"):
                report = row
            else:
                ex_ref = []
                ex_virustotal = self.helper.api.external_reference.create(
                    source_name="Virustotal "+row[0],
                    url="https://www.virustotal.com/gui/seach/"+row[0]
                )
                ex_threatcrow = self.helper.api.external_reference.create(
                    source_name="Threatcrowd "+row[0],
                    url="https://www.threatcrowd.org/pivot.php?data="+row[0]
                )
                ex_ref.append()
                _observable = self.helper.api.stix_observable.create(
                    name=row[0],
                    observable_value=row[0],
                    type=row[1],
                    description=row[2],
                    createIndicator=True,
                    markingDefinitions=self.marking_definition["id"],
                    createdByRef=self.identity["id"],
                    custom_properties={
                        CustomProperties.TAG_TYPE: self.tag1}
                )
                observable_id_list = _observable["stix_id_key"]

        # Creating report
        self.helper.log_info("Generating report...")
        _report = Report(
            name="Import data locally from file {}".format(self.filename),
            type="report",
            description=report[1],
            object_marking_refs=TLP_WHITE,
            labels=["threat-report"],
            object_refs=observable_id_list
        )
        bundle.append(_report)
        self.helper.log_info("Sending bundle...")
        sending_bundle = Bundle(objects=bundle)
        self.helper.send_stix2_bundle(
            bundle=sending_bundle.serialize(), update=self.update_existing_data
        )
        self.helper.log_info("Bundle sent.")

    def start(self):
        while True:
            self._open_files()
            time.sleep(6*3600)


if __name__ == "__main__":
    try:
        exrefaddInstance = ExRefAdd()
        exrefaddInstance.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
