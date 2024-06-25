import binwalk.core.plugin

# Each plugin must be subclassed from binwalk.core.plugin.Plugin
class MyPlugin(binwalk.core.plugin.Plugin):
    '''
    A sample binwalk plugin module.
    '''

    # A list of module names that this plugin should be enabled for (see self.module.name).
    # If not specified, the plugin will be enabled for all modules.
    MODULES = ['Signature']

    nordic_zip = {'manifest': False, 'dat': 0, 'bin': 0}
    # The init method is invoked once, during module initialization. 
    # At this point the module has been initialized, so plugins have access to the self.module object.
    # The self.module object is the currently running module instance; data from it can be read, but
    # should not be modified.
    def init(self):
        return 
    # The pre_scan method is invoked once, after the module has been loaded, but before any files
    # have been processed.
    def pre_scan(self):
        return 
    # The new_file method is invoked once per file, after the file has been opened, but before
    # the module has processed the file. It is passed an instance of binwalk.core.common.BlockFile.
    def new_file(self, fp):
        return 
    # The scan method is invoked each time the module registers a result during the file scan.
    # The plugin has full read/write access to the result data.
    def scan(self, result):
        if result.valid:
            if result.description[:3] != 'Zip':
                return
            last_word = result.description[-3:]
            if last_word == 'dat':
                self.nordic_zip['dat'] += 1
            elif last_word == 'bin':
                self.nordic_zip['bin'] += 1
            elif last_word == 'son' and result.description[-13:] == 'manifest.json':
                self.nordic_zip['manifest'] = True


    # The post_scan method is invoked once, after the module has finished scanning a file
    def post_scan(self):
        if self.nordic_zip['manifest'] and self.nordic_zip['dat'] > 0 and self.nordic_zip['dat'] == self.nordic_zip['bin']:
            print()
            print("\033[31mNordicSemi Zip File Detected\033[0m")
