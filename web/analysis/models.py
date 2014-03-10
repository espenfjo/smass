from django_mongodb_engine.contrib import MongoDBManager
from django_mongodb_engine.storage import GridFSStorage

from django.db import models
from djangotoolbox.fields import EmbeddedModelField, ListField, DictField
from datetime import datetime


class Analysis(models.Model):
    name = models.TextField()
    md5 = models.TextField()
    sha1 = models.TextField()
    sha256 = models.TextField()
    sha512 = models.TextField()
    ssdeep = models.TextField()
    crc = models.TextField()
    file_type = models.TextField()
    analysis_date = models.DateField()
    fs_id = models.TextField()
    meta = EmbeddedModelField('Meta')
    modules = ListField(EmbeddedModelField())

    objects = MongoDBManager()
    class MongoMeta:
        db_table="ass"

class Meta(models.Model):
    tags = ListField()
    comment = models.TextField()
    source = models.URLField()

class JavaScript(models.Model):
    name = models.TextField()


class PE(models.Model):
    name = models.TextField()
    compile_time = models.DateField()
    imphash = models.TextField()
    imports = ListField(EmbeddedModelField('PE_Ports'))
    exports = ListField(EmbeddedModelField('PE_Ports'))
    sections = ListField()
    machine = models.TextField()
    entrypoint = models.TextField()
    is_dll = models.BooleanField(default=False)
    subsystem = models.TextField()
    sub = ListField(EmbeddedModelField('PE_Sub'))

class PE_Sub(models.Model):
    name = models.TextField()
    language = models.TextField()
    filetype = models.TextField()
    sublanguage = models.TextField()
    offset = models.TextField()
    md5 = models.TextField()
    size = models.TextField()
    objects = MongoDBManager()
    fs_id = models.TextField()

class PE_Ports(models.Model):
    name = models.TextField()
    jquery_proof_name = models.TextField()
    imports = ListField()

class VirusTotal(models.Model):
    name = models.TextField()
    scan_id = models.TextField()
    scan_date = models.TextField()
    permalink = models.TextField()
    positives = models.IntegerField()
    total = models.IntegerField()
    scans = DictField()


class VirusTotal_Scans(models.Model):
        pass
