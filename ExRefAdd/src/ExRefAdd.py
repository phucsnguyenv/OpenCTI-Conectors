import yaml
import os
import json
import shutil
import time
import csv
from datetime import datetime

from pycti import OpenCTIConnectorHelper, get_config_variable
from stix2 import Bundle, Report, TLP_WHITE, Identity, Indicator
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
        self.identity = Identity(
            name="Internal Collector",
            identity_class="individual",
            description="Import internal data from CSV file"
        )
        self.tag1 = self.helper.api.tag.create(
            tag_type="Event",
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

    def _create_indicator(self, row):
        _dict = {
            "ipv4": "ipv4-addr",
            "url": "url"
        }
        indicator_type = _dict[row[1]]
        indicator_value = row[0]
        _indicator = Indicator(
            type="indicator"
            name=indicator_value,
            description="IOC import from "+self.filename,
            pattern="["+indicator_type+":value = '"+indicator_value+"']",
            labels="malicious-activity",
            created_by_ref=self.identity,
            object_marking_refs=TLP_WHITE,
            custom_properties={CustomProperties.TAG_TYPE: self.tag1}
        )
        return _indicator

    def _process_message(self, data):
        indicator_id_list = []
        bundle = []
        bundle.append(self.identity)
        """doing things with data here"""
        self.helper.log_info("Creating Indicators data")
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
                ex_ref.append(ex_threatcrow["stix_id_key"])
                ex_ref.append(ex_virustotal["stix_id_key"])

                # create indicator
                self.helper.log_info("Creating Indicator...")
                _indicator = self._create_indicator(row)
                bundle.append(_indicator)
                indicator_id_list.append(_indicator["id"])
        # Creating report
        self.helper.log_info("Generating report...")
        _report = Report(
            name="Import data locally from file {}".format(self.filename),
            type="report",
            published=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            description=report[1],
            object_marking_refs=TLP_WHITE,
            created_by_ref=self.identity,
            labels=["threat-report"],
            object_refs=indicator_id_list
        )
        bundle.append(_report)
        self.helper.log_info("Sending bundle...")
        print(bundle)
        sending_bundle = Bundle(objects=bundle)
        self.helper.send_stix2_bundle(
            bundle=sending_bundle.serialize(), update=self.update_existing_data
        )
        self.helper.log_info("Bundle sent.")
        self.helper.log_info("Sleeping...")

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
