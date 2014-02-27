import sys
import argparse

from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
from django.views.generic.detail import DetailView
from .forms import UploadFileForm
from django.conf import settings

from analysis.models import Analysis,PE,PE_Sub

sys.path.append(settings.ASS_PATH)
from lib.Artifact import Artifact
from lib.configreader import parse_config



class AnalysisDetailView(DetailView):
    model = Analysis
    def get_context_data(self, **kwargs):
        context = super(AnalysisDetailView, self).get_context_data(**kwargs)
        context['relationships'] = Analysis.objects.filter(md5=context['analysis'].md5)
        for module in context['analysis'].modules:
            if isinstance(module, PE):
                context['sub_relations'] = find_sub_pe_relations(module)

        return context


def find_sub_pe_relations(pe):
    matches = {}
    for sub in pe.sub:
        md5 = sub.md5
        for match in Analysis.objects.raw_query({"modules.sub.md5":md5}):
            for module in match.modules:
                if isinstance(module, PE):
                    for match_sub in module.sub:
                        if not match_sub.md5 in matches:
                            matches[match_sub.md5] = {}
                            matches[match_sub.md5]['aid'] = {}

                        matches[match_sub.md5]['aid'][match.id] = match.name
                        matches[match_sub.md5]["data"] = match_sub

    return matches.values()

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
    configfile = "{}/ass.conf".format(settings.ASS_PATH)
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

    artifact = Artifact( config, name, size, data)
    artifact.analyse()

    meta = {
        'source': post.get('source'),
        'tags': [post.get('tags'),],
        'comment': post.get('comments'),

        }
    artifact.report['meta'] = meta
    artifact.database.collection.insert(artifact.report)
