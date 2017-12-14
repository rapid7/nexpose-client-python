import copy


class Configuration(object):

    @classmethod
    def CreateFromJSON(cls, json_dict):
        services = {
            'amazon-web-services': AWSConfiguration,
        }
        service_name = json_dict['serviceName']
        if service_name in services:
            cls = services[service_name]
        config = cls(
            service_name=json_dict['serviceName'],
            name=json_dict['configName'],
            properties=json_dict['configurationAttributes']['properties'],
            id=json_dict['configID'],
        )
        return config

    def __init__(self, service_name, name, properties, id=None):
        self.id = id
        self.properties = copy.deepcopy(properties)
        self.service_name = service_name
        self.name = name

    def as_json(self):
        json_dict = {
            'serviceName': self.service_name,
            'configName': self.name,
            'configurationAttributes': {
                'valueClass': 'Object',
                'objectType': 'service_configuration',
                'properties': self.properties,
            },
        }
        json_dict['configID'] = self.id

        return json_dict


class AWSConfiguration(Configuration):

    @property
    def region(self):
        items = self.properties['region']['items']
        regions = [i['value'] for i in items]
        return regions

    @region.setter
    def region(self, regions):
        items = [{'valueClass': 'String', 'value': r} for r in regions]
        self.properties['region']['items'] = items

    def add_region(self, region):
        if region in self.region:
            raise RuntimeError("Region {} already in configuration".format(region))
        self.properties['region']['items'].append(
            {'valueClass': 'String', 'value': region})

    @property
    def engine_inside_aws(self):
        return self.properties['engineInsideAWS']['value']

    @engine_inside_aws.setter
    def engine_inside_aws(self, value):
        self.properties['engineInsideAWS']['value'] = value

    @property
    def import_tags(self):
        return self.properties['importTags']['value']

    @import_tags.setter
    def import_tags(self, value):
        self.properties['importTags']['value'] = value

    @property
    def console_inside_aws(self):
        return self.properties['consoleInsideAWS']['value']

    @console_inside_aws.setter
    def console_inside_aws(self, value):
        self.properties['consoleInsideAWS']['value'] = value

    @property
    def session_name(self):
        return self.properties['sessionName']['value']

    @session_name.setter
    def session_name(self, value):
        self.properties['sessionName']['value'] = value

    @property
    def site_id(self):
        return self.properties['siteID']['value']

    @site_id.setter
    def site_id(self, value):
        self.properties['siteID']['value'] = str(value)

    @property
    def use_proxy(self):
        return self.properties['useProxy']['value']

    @use_proxy.setter
    def use_proxy(self, value):
        self.properties['useProxy']['value'] = value

    @property
    def arn(self):
        return self.properties['arn']['value']

    @arn.setter
    def arn(self, value):
        self.properties['arn']['value'] = value
