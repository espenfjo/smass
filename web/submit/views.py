import argparse
import gridfs
import sys


from bson.objectid import ObjectId
from django.conf import settings
from django.http import HttpResponse,HttpResponseRedirect,HttpResponseBadRequest,Http404
from django.shortcuts import render, render_to_response
from django.views.decorators.http import require_safe
from django.views.generic.detail import DetailView
from django.template import RequestContext
from django.db import connections


from analysis.models import Analysis,PE,PE_Sub
from .forms import UploadFileForm


sys.path.append(settings.SMASS_PATH)
from lib.Artifact import Artifact
from lib.configreader import parse_config


def submit(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            submit_file(request.FILES['file'], request.POST)
            return HttpResponseRedirect("/")
    else:
        form = UploadFileForm()
        return render(request, 'upload.html', {'form': form})


    return HttpResponse()


def submit_file(stuff, post):
    configfile = "{}/smass.conf".format(settings.SMASS_PATH)
    configobj = parse_config(configfile)
    data = stuff.read()
    name = stuff.name
    size = stuff.size

    class Config(dict):
        def __init__(self, *args, **kwargs):
            super(Config, self).__init__(*args, **kwargs)
            self.__dict__ = self

    config = Config()

    config.database = configobj['database']
    config.modules = list(configobj['modules'])
    config.mongo_host = configobj['mongo_host']
    config.virustotal_api_key = configobj['virustotal_api_key']

    if post.get('type') and post.get('type') != "":
        config.type = post.get('type')

    artifact = Artifact( config, name, size, data)
    artifact.analyse()

    meta = {
        'source': post.get('source'),
        'tags': post.getlist('tags'),
        'comment': post.get('comments'),
        }
    artifact.report['meta'] = meta
    artifact.database.collection.insert(artifact.report)
