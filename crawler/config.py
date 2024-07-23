import os
import json

class Config:

    def __init__(self, config_file='config.json'):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        prev_path = os.getcwd()
        os.chdir(dir_path)
        self.config_file = config_file
        self.config_data = self.load_config()
        os.chdir(prev_path)

        # Update the project_folder from environment variable if set
        self.update_project_folder()
        
    def load_config(self):
        with open(self.config_file, 'r') as file:
            return json.load(file)
        
    def update_project_folder(self):
        # Read the project_folder environment variable
        project_folder_env = os.getenv('PROJECT_FOLDER')

        if project_folder_env:
            self.config_data['project_folder'] = project_folder_env
        else:
            print("\n!!! ERROR !!! Environment variable PROJECT_FOLDER not set.\n")

    def get(self, key, default=None):
        keys = key.split('.')
        value = self.config_data
        for k in keys:
            value = value.get(k, default)
            if value is None:
                return default
        return value

    def get_folder(self, key, default=None):
        keys = key.split('.')
        value = self.config_data
        for k in keys:
            value = value.get(k, default)
            if value is None:
                return default
        folder = value
        
        if key != "project_folder":
            project = self.get("project_folder")
            to_return = os.path.join(project, folder)
            return to_return
        
        return folder




config = Config()

