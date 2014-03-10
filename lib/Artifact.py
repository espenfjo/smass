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
        if "type" in self.config:
            if self.config.type:
                self.type = self.config.type
            else:
                self.set_type()
        else:
            self.set_type()

        self.modules = []
        if "modules" in self.config:
            for module in list(self.config.modules):
                self.modules.append(classloader("modules", module, self))


    def set_type(self):
        if re.match("PE", str(self.magic.magic)):
            self.type = "pe"
        elif re.match("(Node.js|javascript)", str(self.magic.magic)):
            self.type = "javascript"
        else:
            self.type = "generic"

    def analyse(self):
        self.report = {}
        self.report['name'] = self.name
        self.get_hashes()
        self.report["file_type"] = self.magic.magic
        self.report["file_size"] = self.size
        self.report["analysis_date"] = datetime.now()
        self.report["modules"] = []
        self.store_file()
        for module in self.modules:
            if module.type in self.type or module.type is "generic":
                module.init()
                self.report['modules'].append(module.data)


    def store_file(self):
        if not self.database.fs.exists({"md5":self.report['md5']}):
            self.report["fs_id"] = self.database.fs.put(self.data)
        else:
            grid_file = self.database.fs.get_version(md5=self.report['md5'])
            self.report["fs_id"] = grid_file._id

    def get_hashes(self):
        hashes = Hash(self)
        for hash_type in hashes.hashes:
            self.report[hash_type] = hashes.hashes[hash_type]
