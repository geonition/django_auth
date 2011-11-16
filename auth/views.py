# -*- coding: utf-8 -*-
from django.contrib.auth import logout as django_logout
from django.contrib.auth import login as django_login
from django.contrib.auth import authenticate as django_authenticate
from django.contrib.auth.models import User
from django.contrib.auth.models import UserManager
from django.contrib.sites.models import Site
from django.core.exceptions import ValidationError
from django.core.mail import BadHeaderError, send_mail
from django.db import IntegrityError
from django.db import transaction
from django.db.models import Max
from geonition_utils.HttpResponseExtenders import HttpResponse
from geonition_utils.HttpResponseExtenders import HttpResponseBadRequest
from geonition_utils.HttpResponseExtenders import HttpResponseConflict
from geonition_utils.HttpResponseExtenders import HttpResponseCreated
from geonition_utils.HttpResponseExtenders import HttpResponseForbidden
from django.template.loader import render_to_string
from django.utils import simplejson as json
from geonition_utils.HttpResponseExtenders import HttpResponseUnauthorized
from random import random
from threading import Lock
from time import time

import logging

logger = logging.getLogger('api.user.view')
lock = Lock()   

def login(request):
    """
    This function does the login procedure and returns
    a suitable status code
    

    Returns:
        200 if successful
        400 for Bad Request
        401 for unauthorized (wrong password or username not found)

    """
    if(request.method == "GET"):
        return HttpResponseBadRequest("This url only accept POST requests")
        
    elif (request.method == "POST"):
        
        if request.user.is_authenticated() == True:
        
            return HttpResponseBadRequest("You have already signed in")
            
        values = None
        try:
            values = json.loads(request.POST.keys()[0])
        except ValueError, err:
        
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no login "
                                          "values could be retrieven from it")

    
             
        username = values.pop('username', None)
        password = values.pop('password', None)
                
        if(username == None):
            return HttpResponseBadRequest("You have to provide a username")
            
        if(password == None):
            return HttpResponseBadRequest("You have to provide a password")

 
        user = django_authenticate(username=username, password=password)
            
        if user is not None:
            django_login(request, user)
            
            response = HttpResponse(u"Login successfull")
            response['Access-Control-Allow-Origin'] = "*"
            return response
        else:
        
            response = HttpResponseUnauthorized(u"Wrong password or username "
                                                "not found")
            response['Access-Control-Allow-Origin'] = "*"
            return response
    
    
    elif (request.method == "OPTIONS"):
        
        response = HttpResponse("")
        response['Access-Control-Allow-Origin'] = "*"
        response['Access-Control-Allow-Methods'] = "POST, OPTIONS"
        response['Access-Control-Allow-Headers'] = "X-Requested-With"
        
        return response
    

def logout(request):
    """
    simple logout function

    Returns:
        200 if logout successful
    """
    django_logout(request)
    
    return HttpResponse("You have successfully signed out")

       
#registering for an softGIS API account
def register(request):
    """
    This function handles the registration form.

    GET
    does nothing at the moment, returns 200 OK

    POST
    With a POST request it registers a user if the values
    provided is correct

    The post should include
    {
    'username': <required>,
    'password': <required>
    }

    if email is provided it will be confirmed with an confirmation link
    sent to the user.

    notifications is if the user wants notification of updates to the service
    to his/her email
    
    
    Returns:
        201 if successful
        400 for Bad Request
        409 for Conflict
    """
    if(request.method == "GET"):
    
        return HttpResponse("")

    elif(request.method == "POST"):
        
        #check if anonymous user 
        if request.user.is_authenticated() == True:
            return HttpResponseBadRequest("You cannot register a user "
                                          "when logged in")
    
    
        values = None
        try:
            values = json.loads(request.POST.keys()[0])
        except ValueError, err:
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no register "
                                          "values could be retrieven from it")

        

        username = values.pop('username', None)
        password = values.pop('password', None)
        
        if(username == None or username == ""):
            return HttpResponseBadRequest(u"You have to provide a username")
        
        if(password == None or password == ""):
            return HttpResponseBadRequest(u"You have to provide a password")
            
        #validate password
        val_passwd_result = validate_password(password)
        if not val_passwd_result[0]:
            return HttpResponseBadRequest(val_passwd_result[1])
        
        
        #create user for django auth
        user = User(username = username,
                    password = password)
        user.set_password(password)
        
        try:
            user.validate_unique()
        except ValidationError, err:
            message = " "
            error_msg = []
    
            for desc in err.message_dict.keys():
                error_msg.append(err.message_dict[desc][0])
            
            details=message.join(error_msg)
    
            return HttpResponseConflict(details)

        try:
            user.full_clean()
        except ValidationError, err:
            message = " "
            details = message.join(error_msg)
            
            return HttpResponseBadRequest(details)
            
        try:
            sid = transaction.savepoint()
            user.save()
            transaction.savepoint_commit(sid)
        except IntegrityError, err:
            transaction.savepoint_rollback(sid)
            
            message = " "
            error_msg = []

            for desc in err.message_dict.keys():
                error_msg.append(err.message_dict[desc][0])
    
            details = message.join(error_msg)
            
            return HttpResponseConflict(details)
        
        #authenticate and login
        user = django_authenticate(username=username,
                                    password=password)
        
        if user is not None and user.is_active:
            django_login(request, user)
        
        return HttpResponseCreated(u"User was successfully created")
        
def session(request):
    """
    This function creates a user with
    no password set. This enables the user
    to stay anonymous but still save values
    in other softgis apps.
    
    GET request returns the session
    POST request creates a session for anonymous user
    DELETE request ends the session
    """
    if request.method == "GET":
        return HttpResponse(request.session.session_key)
        
    elif request.method == "POST":
    
        if request.user.is_authenticated():   
            return HttpResponse(u"session already created") 
        
        
        #should be unique enough and 27 char long
        new_user_id = "T%fR%f" % (time(), random())            
        User.objects.create_user(new_user_id,'', 'passwd')
        
        user = django_authenticate(username=new_user_id,
                                   password='passwd')
        
        django_login(request, user)
        user.set_unusable_password()
        
        return HttpResponse(u"session created")

    elif request.method == "DELETE":
        
        django_logout(request)
            
        return HttpResponse(u"session end")
        
        
def new_password(request):
    """
    This function sends new password to the given email address.
    
    Returns:
        200 if successful
        400 if email address is not confirmed
        404 if email address is not found

    """
    
    if(request.method == "POST"):
        try:
            request_json = json.loads(request.POST.keys()[0])
        except ValueError, err:
            logger.error("Error at new_password request. "
                         "Details: %s"  % str(err.args))
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no "
                                          "new_password value could be "
                                          "retrieven from it")
        
        email = request_json['email']
        try:
            current_user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("The user could not be found or the email address "
                           "hasn't been confirmed")
            return HttpResponseBadRequest(u"The user could not be found or "
                                          "the email address hasn't been "
                                          "confirmed") 
        
       
        um = UserManager()
        password = um.make_random_password()
        
        current_site = Site.objects.get_current()     
        context = {
            "current_user": current_user,
            "password": password,
            "current_site": current_site
        }
        subject = render_to_string(
            "email_templates/new_password_email_subject.txt", context)
        # remove superfluous line breaks
        subject = "".join(subject.splitlines())
        message = render_to_string(
            "email_templates/new_password_email_content.txt", context)
        
      
        try:
            send_mail(subject,
                        message,
                        'do_not_reply@pehmogis.fi',
                        [current_user.email])
            
            current_user.set_password(password)
            current_user.save()
                        
            return HttpResponse(u"New password was sent to %s" % current_user.email)
            
        except BadHeaderError:
            
            return HttpResponseBadRequest(u'Invalid header found.')
            

    return HttpResponseBadRequest("This URL only accepts POST requests")
    
def change_password(request):
    """
    This function changes the user password.
    
    Returns:
        200 if successful
        400 if old or new password is not provided
        401 if current password is not correct
        403 if user is not signed in

    """
    
    if not request.user.is_authenticated():
        return HttpResponseForbidden(u"The request has to be made by "
                                     "a signed in user")


    if(request.method == "POST"):
        
        try: 
            request_json = json.loads(request.POST.keys()[0])
        except ValueError, err:
            return HttpResponseBadRequest(u"JSON error: %s" % str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no "
                                          "change_password value could be "
                                          "retrieved from it")
            
        new_password = request_json['new_password']
        old_password = request_json['old_password']

        if(old_password == None or old_password == ''):
            return HttpResponseBadRequest(u"You have to enter your"
                                          "current password")

        if not request.user.check_password(old_password):
            return HttpResponseUnauthorized(u"Wrong password")
        
        if(new_password == None or new_password == ''):
            return HttpResponseBadRequest(u"You have to provide a password")
        
        passwd_val_result = validate_password(new_password)
        
        if passwd_val_result[0]:
            request.user.set_password(new_password)
            request.user.save()
        
            return HttpResponse(u"Password changed succesfully")
        else:
            return HttpResponseBadRequest(passwd_val_result[1])
    
    return HttpResponseBadRequest(u"This URL only accepts POST requests")   

def validate_password(password):
    
    #require the password to be certain length
    if len(password) < 8:
        return (False, u'The password has to be at least 8 characters long')
    
    return (True, u'The password is strong enough')