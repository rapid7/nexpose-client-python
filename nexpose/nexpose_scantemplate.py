from json_utils import JSON

class ScanTemplateSummary(JSON):

    @staticmethod
    def CreateFromJSON(json_dict):
        id = json_dict["id"]
        name = json_dict["name"]

        scanTemplateSummary = ScanTemplateSummary(id, name)
        return scanTemplateSummary

    def __init__(self, id, name):
        self.id = id
        self.name = name

    def as_json(self):
        json_dict = {}
        json_dict["id"] = self.id
        json_dict["name"] = self.name
        return json_dict
