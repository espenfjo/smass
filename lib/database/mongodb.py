from pymongo import MongoClient
import gridfs

class mongodb(object):
    def __init__(self, artifact):
        self.artifact = artifact
        self.config = artifact.config
        client = MongoClient(self.config.mongo_host)
        db = client.ass
        self.collection = db.ass
        self.fs = gridfs.GridFS(db)
