from django.conf.urls import patterns, url
from django.views.generic import ListView, DetailView

from models import Analysis
from analysis.views import AnalysisDetailView, submit, search

analysis_list = ListView.as_view(model=Analysis)

urlpatterns = patterns('',
                    url(r'^analysis/(?P<pk>[a-z\d]+)/$', AnalysisDetailView.as_view(), name='analysis_detail'),
                    url(r'^$', analysis_list, name='analysis_list'),
                    url(r'^submit$', submit, name='submit'),
                    url(r'^search$', search, name='search')
)
