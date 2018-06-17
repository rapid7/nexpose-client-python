class ServiceNames(object):
    AWS = 'amazon-web-services'
    NEXPOSE = 'nexpose'


class Step(object):
    
    @classmethod
    def CreateFromJSON(cls, json_dict):
        uuid = json_dict.get('uuid')
        service_name = json_dict['serviceName']
        config = StepConfiguration.CreateFromJSON(
            json_dict['stepConfiguration'])
        return cls(
            service_name=service_name,
            config=config,
            uuid=uuid,
        )

    def __init__(self, service_name, config, uuid=None):
        self.uuid = uuid
        self.service_name = service_name
        self.config = config

    def as_json(self):
        data = {
            "serviceName": self.service_name,
            "stepConfiguration": self.config.as_json(),
        }
        if self.uuid is not None:
            data['uuid'] = self.uuid,
        return data


class StepConfiguration(object):

    @classmethod
    def CreateFromJSON(cls, json_dict):
        type_name = json_dict['typeName']
        previous_type_name = json_dict.get('previousTypeName', "")
        props = json_dict.get('configurationParams', {}).get('properties', {})
        integration_option_id = json_dict.get('integrationOptionID')
        step_config = cls(
            type_name, previous_type_name,
            set_defaults=False,
            integration_option_id=integration_option_id)
        step_config.configuration_params['properties'] = props
        return step_config

    def __init__(
            self, type_name, previous_type_name="",
            set_defaults=True,
            workflow_id=None, integration_option_id=None, **properties):
        self.type_name = type_name
        self.previous_type_name = previous_type_name
        if properties is None:
            properties = {}
        self.configuration_params = {
            "valueClass": "Object",
            "objectType": "params",
            "properties": {},
        }
        for prop_name, prop_value in properties.items():
            self.add_property(prop_name, prop_value)
        self.workflow_id = workflow_id
        self.integration_option_id = integration_option_id
        if set_defaults:
            self.set_defaults()

    def set_defaults(self):
        defaults = {}
        if self.type_name == 'discover-aws-assets':
            defaults = {
                'excludeAssetsWithTags': '',
                'importTags': False,
                'onlyImportTheseTags': '',
            }
        for prop_name, default_value in defaults.items():
            if prop_name not in self.configuration_params['properties']:
                self.add_property(prop_name, default_value)

    def add_property(self, name, prop, type_=None):
        if type_ is None:
            if isinstance(prop, bool):
                type_ = 'Boolean'
            elif isinstance(prop, int):
                type_ = 'Integer'
            elif isinstance(prop, str):
                type_ = 'String'
            else:
                raise TypeError("Invalid type {} for prop '{}'".format(type(prop), name))
        self.configuration_params['properties'][name] = {
            'valueClass': type_,
            'value': prop,
        }

    def get_property(self, name):
        return self.configuration_params['properties'][name]['value']

    def as_json(self):
        data = {
            "typeName": self.type_name,
            "previousTypeName": self.previous_type_name,
            "configurationParams": self.configuration_params,
        }
        if self.workflow_id:
            data['workflowID'] = self.workflow_id
        if self.integration_option_id:
            data['integrationOptionID'] = self.integration_option_id
        return data


class IntegrationOption(object):

    @classmethod
    def CreateFromJSON(cls, json_dict):
        name = json_dict.get('name', "")
        id_ = json_dict.get('id')
        steps = [Step.CreateFromJSON(s) for s in json_dict['steps']]
        return cls(name, id_, steps)

    def __init__(self, name="", id=None, steps=None):
        if steps is None:
            steps = []
        self.name = name
        self.id = id
        self.steps = steps

    def get_step(self, service_name, type_name=None):
        for step in self.steps:
            if step.service_name != service_name:
                continue
            if type_name is not None and step.config.type_name != type_name:
                continue
            return step
        else:
            msg = "Unable to find step for serviceName '{}'".format(
                service_name)
            if type_name is not None:
                msg += " and typeName '{}'".format(type_name)
            raise KeyError(msg)

    def as_json(self):
        data = {
            'name': self.name,
            'steps': [s.as_json() for s in self.steps]
        }
        if self.id is not None:
            data['id'] = self.id
        return data

    def update(self, data):
        self.id = data['id']
        self.steps = [Step.CreateFromJSON(s) for s in data['steps']]
