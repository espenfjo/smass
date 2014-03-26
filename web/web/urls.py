from django.conf.urls import patterns, include, url
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
                       url(r"^$", "dashboard.views.dashboard"),
                       url(r"^analyses/", include('analysis.urls')),
                       url(r"^submit/", include('submit.urls')),
)
