import yaml
import json
import os 

from pycti import OpenCTIConnectorHelper, get_config_variable

class VirustotalReference:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)

    def create_reference(self, data):
        virus_ref = self.helper.api.external_reference.create(
            source_name="Virustotal " + data,
            url="https://www.virustotal.com/gui/search/" + data
        )
        return virus_ref

    def _process_message(self, data):
        entity_id = data["entity_id"]
        observable = self.helper.api.stix_observable.read(id=entity_id)
        observable_value = observable["observable_value"]
        self.helper.log_info("Creating virustotal reference for {}".format(observable_value))
        created_reference = self.create_reference(observable_value)
        self.helper.log_info("External reference created with id {}".format(created_reference["id"]))
        self.helper.log_info("Attaching the reference to {}".format(entity_id))
        self.helper.api.stix_entity.add_external_reference(
            id=entity_id,
            external_reference_id=created_reference["id"]
        )
        

    def start(self):
        self.helper.listen(self._process_message)

if __name__ == "__main__":
    virustotalInstance = VirustotalReference()
    virustotalInstance.start()