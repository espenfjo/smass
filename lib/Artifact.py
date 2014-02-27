import os
import re
import magic
import logging
from datetime import datetime
from moduleloader import classloader
from lib.modules.Hash import Hash

class Artifact(object):
    def __init__(self, config, name, size, data):
        self.config = config
        self.size = size
        self.name = name
        self.data = data
        self.database = classloader("database", self.config.database, self)
        self.magic = classloader("modules", "filemagic", self)
        self.set_type()
        print self.config.modules
        print type(self.config.modules)
        self.modules = []
        if "modules" in self.config:
            for module in list(self.config.modules):
                self.modules.append(classloader("modules", module, self))


    def set_type(self):
        if re.match("PE", str(self.magic.magic)):
            self.type = "pe"

    def analyse(self):
        self.report = {}
        self.report['name'] = self.name
        self.get_hashes()
        self.report["file_type"] = self.magic.magic
        self.report["file_size"] = self.size
        self.report["analysis_date"] = datetime.now()
        self.report["modules"] = []
        for module in self.modules:
            if module.type in self.type or module.type is "generic":
                module.init()
                self.report['modules'].append(module.data)


    def get_hashes(self):
        hashes = Hash(self)
        for hash_type in hashes.hashes:
            self.report[hash_type] = hashes.hashes[hash_type]
