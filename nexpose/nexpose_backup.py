class Backup:
	@staticmethod
	def CreateFromJSON(json_dict):
		backup = Backup()
		backup.name = json_dict["Download"]
		backup.date = json_dict["Date"] # Time ... / 1000 ? Timezone ?
		backup.description = json_dict["Description"]
		backup.nexpose_version = json_dict["Version"]
		backup.platform_independent = json_dict["Platform-Independent"]
		backup.size = int(json_dict["Size"])
		return backup
	
	def __init__(self):
		self.name = ''
		self.date = ''
		self.description = ''
		self.nexpose_version = ''
		self.platform_independent = False
		self.size = 0
