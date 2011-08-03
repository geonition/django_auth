# -*- coding: utf-8 -*-
from django.conf.urls.defaults import patterns
from django.conf.urls.defaults import url

urlpatterns = patterns('auth.views',
            url(r'^register/$',
                'register',
                name="api_register"),
               
            url(r'^newpassword/$',
                'new_password',
                name="api_new_password"),
            url(r'^changepassword/$',
                'change_password',
                name="api_change_password"),
            
            url(r'^login/$',
                'login',
                name="api_login"),
            url(r'^logout/$',
                'logout',
                name="api_logout"),
            
            #url to create a session for anonymous user
            url(r'^session/$',
                'session',
                name="api_session"),
        )
