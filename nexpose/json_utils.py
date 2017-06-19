class JSON:
	@staticmethod
	def CreateFromJSON(json_dict):
		raise NotImplementedError

	def as_json(self):
		raise NotImplementedError	

class HasID:
	pass

def get_id(data, id_field_name):
	if isinstance(data, HasID):
		return data.id
	if isinstance(data, dict):
		return data.get(id_field_name, 0)
	return data # assume the data is the id

def load_urls(json_dict, url_loader):
	assert isinstance(json_dict, dict)
	for key in json_dict.keys():
		if isinstance(json_dict[key], dict):
			if json_dict[key].get('json', None) is not None:
				raise ValueError('json_dict[' + key + '] already contains a json-element')
			url = json_dict[key].get('url', None)
			if url is not None:
				json_dict[key]['json'] = url_loader(url)
