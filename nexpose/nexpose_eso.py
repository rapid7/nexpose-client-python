import copy
from .nexpose_integration_options import IntegrationOption, Step, StepConfiguration, ServiceNames


class Configuration(object):

    @classmethod
    def CreateFromJSON(cls, json_dict, integration_options=None):
        services = {
            'amazon-web-services': AWSConfiguration,
        }
        service_name = json_dict['serviceName']
        if integration_options is not None:
            integration_options = [
                IntegrationOption.CreateFromJSON(i) for i in integration_options]
        if service_name in services:
            cls = services[service_name]
            config = cls(
                name=json_dict['configName'],
                properties=json_dict['configurationAttributes']['properties'],
                id=json_dict['configID'],
                integration_options=integration_options,
            )
        else:
            config = cls(
                service_name=json_dict['serviceName'],
                name=json_dict['configName'],
                properties=json_dict['configurationAttributes']['properties'],
                id=json_dict['configID'],
                integration_options=integration_options,
            )
        return config

    def __init__(self, service_name, name, properties, steps, id=None):
        self._id = id
        self.properties = copy.deepcopy(properties)
        self.service_name = service_name
        self.name = name

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = id

    def add_property(self, name, prop, type_=None):
        if type_ is None:
            if isinstance(prop, bool):
                type_ = 'Boolean'
            elif isinstance(prop, int):
                type_ = 'Integer'
            elif isinstance(prop, str):
                type_ = 'String'
            elif isinstance(prop, list):
                type_ = 'Array'
            else:
                raise TypeError("Invalid type {} for prop '{}'".format(type(prop), name))
        data = {
            'valueClass': type_,
        }
        if type_ == 'Array':
            data['items'] = [{'value': v, 'valueClass': 'String'} for v in prop]
        else:
            data['value'] = prop
        self.properties[name] = data

    def get_property(self, name, default=None):
        try:
            prop = self.properties[name]
        except KeyError:
            if default is None:
                raise
            else:
                self.add_property(name, default)
                prop = self.properties[name]
        if self.properties[name]['valueClass'] == 'Array':
            prop = [p['value'] for p in prop['items']]
        else:
            prop = prop['value']
        return prop

    def add_property_item(self, name, item):
        if item in self.get_property(name, []):
            raise ValueError("{} '{}' already in configuration".format(name, item))
        self.properties[name]['items'].append({'value': item, 'valueClass': 'String'})

    def _get_step(self, option_name, service_name, type_name=None):
        for opt in self._integration_options:
            if option_name not in opt.name:
                continue
            try:
                return opt.get_step(service_name, type_name)
            except KeyError:
                msg = "Unable to find step for option '{}', serviceName '{}'".format(
                    option_name, service_name)
                if type_name is not None:
                    msg += " and typeName '{}'".format(type_name)
                raise KeyError(msg)
        else:
            raise KeyError("Unknown option_name '{}'".format(option_name))

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
        if self._id:
            json_dict['configID'] = self.id
        return json_dict



def _AWS_get_default_verify_opts():
    return IntegrationOption(
        name='aws-verify',
        steps=[Step(
           service_name=ServiceNames.AWS,
           config=StepConfiguration(type_name='verify-aws-targets'),
        ), Step(
            service_name=ServiceNames.NEXPOSE,
            config=StepConfiguration(
                type_name='verify-external-targets',
                previous_type_name='verify-aws-targets',
            ),
        ), Step(
            service_name=ServiceNames.AWS,
            config=StepConfiguration(
                type_name='verify-aws-targets',
                previous_type_name='verify-external-targets',
            ),
        )],
    )


def _AWS_get_default_sync_opts():
    return IntegrationOption(
        name='aws-sync',
        steps=[Step(
            service_name=ServiceNames.AWS,
            config=StepConfiguration(
                type_name='discover-aws-assets',
            ),
        ), Step(
            service_name=ServiceNames.NEXPOSE,
            config=StepConfiguration(
                type_name='sync-external-assets',
                previous_type_name='discover-aws-assets',
            ),
        )],
    )


class AWSConfiguration(Configuration):
    service_name = ServiceNames.AWS

    def __init__(self, name, properties=None, integration_options=None, id=None):
        if properties is None:
            properties = {}
        if integration_options is None:
            integration_options = []
        self._id = None

        self.name = name
        self._integration_options = integration_options
        self.properties = properties
        if id is not None:
            self.id = id

    def enable_default_integrations(self, site_id, import_tags=False):
        self._integration_options += [
            _AWS_get_default_sync_opts(),
            _AWS_get_default_verify_opts(),
        ]
        self.site_id = site_id
        self.import_tags = import_tags

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = value
        for opt in self._integration_options:
            if 'Config ID' not in opt.name:
                opt.name = "Config ID:{} - {}".format(value, opt.name)
            for step in opt.steps:
                if step.service_name != ServiceNames.AWS:
                    continue
                step.config.add_property('discoveryConfigID', value)

    #
    # Properties stored directly on AWSConfiguration
    #

    @property
    def regions(self):
        return self.get_property('region')

    @regions.setter
    def regions(self, regions):
        self.add_property('region', list(regions))

    def add_region(self, region):
        self.add_property_item('region', region)

    @property
    def engine_inside_aws(self):
        return self.get_property('engineInsideAWS')

    @engine_inside_aws.setter
    def engine_inside_aws(self, value):
        self.add_property('engineInsideAWS', bool(value))

    @property
    def console_inside_aws(self):
        return self.get_property('consoleInsideAWS')

    @console_inside_aws.setter
    def console_inside_aws(self, value):
        self.add_property('consoleInsideAWS', bool(value))

    @property
    def session_name(self):
        return self.get_property('sessionName')

    @session_name.setter
    def session_name(self, value):
        self.add_property('sessionName', str(value))

    @property
    def use_proxy(self):
        return self.get_property('useProxy')

    @use_proxy.setter
    def use_proxy(self, value):
        self.add_property('useProxy', bool(value))

    @property
    def arn(self):
        return self.get_property('arn')

    @arn.setter
    def arn(self, value):
        self.add_property('arn', str(value))


    #
    # Properties stored on some steps
    #

    @property
    def import_tags(self):
        step = self._get_step(
            'aws-sync',
            'amazon-web-services',
            'discover-aws-assets',
        )
        return step.config.get_property('importTags')

    @import_tags.setter
    def import_tags(self, value):
        step = self._get_step(
            'aws-sync',
            'amazon-web-services',
            'discover-aws-assets',
        )
        step.config.add_property('importTags', bool(value))

    @property
    def site_id(self):
        step = self._get_step(
            'aws-sync',
            'nexpose',
            'sync-external-assets',
        )
        return step.config.get_property('siteID')

    @site_id.setter
    def site_id(self, value):
        step = self._get_step(
            'aws-sync',
            'nexpose',
            'sync-external-assets',
        )
        return step.config.add_property('siteID', int(value))

    @property
    def integration_options(self):
        return self._integration_options
