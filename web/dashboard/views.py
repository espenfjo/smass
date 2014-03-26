from django.shortcuts import render,  render_to_response
from django.template import RequestContext
from django.db import connections


from analysis.models import Analysis,PE,PE_Sub,Meta


def dashboard(request):
    tags = {}
    analyses = Analysis.objects.all()
    for analysis in analyses:
        if analysis.meta.tags:
            for tag in analysis.meta.tags:
                if tag in tags:
                    tags[tag] = tags[tag] +1
                else:
                    tags[tag] = 1

    report = {
        "artifacts":Analysis.objects.count(),
        "tags":tags

    }


    return render_to_response("dashboard/index.html",
                              {"report" : report},
                              context_instance=RequestContext(request))
