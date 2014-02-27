import httplib, mimetypes
import urlparse
import urllib
import urllib2
import urllib3
import hashlib
import json
import time
import re
import logging
import threading

FILE_SIZE_LIMIT = 30 * 1024 * 1024   # 30MB

class virustotal(object):
    def __init__(self, artifact):
        self.type = "generic"
        self.artifact = artifact
        self.data = {}
        self.scan_id = None
        self.data["name"] = "VirusTotal"
        self.data["_model"] = self.data["name"]
        self.data["_module"] = "analysis.models"

    def init(self):
        self.get()
        if not self.data:
            self.scan()
            while not self.data and self.scan_id:
                self.get()
                time.sleep(30)


    def get(self):
        logging.info("Getting report of {}".format(self.artifact.name))
        resource = ''
        if self.scan_id:
            resource = self.scan_id
        else:
            resource = self.artifact.report['md5']

        data = urllib.urlencode({
            "apikey": self.artifact.config.virustotal_api_key,
            "resource": resource
        })

        req = urllib2.urlopen(urllib2.Request(
            "http://www.virustotal.com/vtapi/v2/file/report",
            data,
        )).read()
        logging.debug("Get response: {}".format(req))
        if req:
            req_data = json.loads(req)
            if req_data and req_data['response_code'] != 0 and req_data['response_code'] != -2:
                z = req_data.copy()
                self.data.update(z)



    def scan(self):
        http = urllib3.PoolManager()
        url = "https://www.virustotal.com/vtapi/v2/file/scan"
        artifact_data = self.artifact.data
        params = {
            "apikey": self.artifact.config.virustotal_api_key,
            "file": (self.artifact.artifact_name, artifact_data)
        }
        logging.info("Scanning {}".format(self.artifact.artifact_name))
        response_json = http.request('POST', url, params)
        logging.debug("Scan response: {}".format(response_json.data))
        response = json.loads(response_json.data)
        self.scan_id = response['scan_id']
