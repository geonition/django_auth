from django.contrib.auth import logout as django_logout
from django.contrib.auth import login as django_login
from django.contrib.auth import authenticate as django_authenticate
from django.contrib.auth.models import User
from django.contrib.auth.models import UserManager
from django.contrib.sites.models import Site
from django.core.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import BadHeaderError, send_mail
from django.db import IntegrityError
from django.db import transaction
from django.db.models import Max
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.template.loader import render_to_string
from django.utils import translation
from django.utils import simplejson as json
from django.views.decorators.csrf import requires_csrf_token
from geonition_utils.HttpResponseExtenders import HttpResponseUnauthorized
from threading import Lock

import logging
import sys

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
        
        logger.warning("There was a GET request to the url %s which accepts just POST request" % request.get_full_path())
        return HttpResponseBadRequest("This url only accept POST requests")
        
    elif (request.method == "POST"):
        
        logger.debug("An POST request was sent to login()")

        if request.user.is_authenticated() == True:
            logger.info("There was a login attempt when the user was already authenticated with username %s " % request.user.username)
            return HttpResponseBadRequest("You have already signed in")
            
        values = None
        try:
            values = json.loads(request.POST.keys()[0])
        except ValueError, err:
            logger.error("Error at login attempt. Details: %s"  % str(err.args))
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no login values could be retrieven from it")

    
             
        username = values.pop('username', None)
        password = values.pop('password', None)
                
        if(username == None):
            return HttpResponseBadRequest("You have to provide a username")
            
        if(password == None):
            return HttpResponseBadRequest("You have to provide a password")

 
        user = django_authenticate(username=username, password=password)
            
        if user is not None:
            django_login(request, user)
            
            response = HttpResponse(_(u"Login successfull"), status=200)
            response['Access-Control-Allow-Origin'] = "*"
            return response
        else:
            logger.info("Wrong username and password: %s / %s " %(username, password))
            response = HttpResponseUnauthorized(u"Wrong password or username not found")
            response['Access-Control-Allow-Origin'] = "*"
            return response
    
    
    elif (request.method == "OPTIONS"):
        
        logger.debug("An OPTIONS request was sent to login()")
        
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
    
    logger.debug("The user successfully logged out %s" % request.user.username)
    
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
        logger.warning("A GET request was sent to register() but it doesnt' accept GET requests")
        return HttpResponse("")

    elif(request.method == "POST"):
        
        #check if anonymous user 
        if request.user.is_authenticated() == True:
            logger.info("There was a register attempt when the user was already authenticated with username %s " % request.user.username)
            return HttpResponseBadRequest("You cannot register a user when logged in")
    
    
        values = None
        try:
            values = json.loads(request.POST.keys()[0])
        except ValueError, err:
            logger.error("Error at register attempt. Details: %s"  % str(err.args))
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no register values could be retrieven from it")

        

        username = values.pop('username', None)
        password = values.pop('password', None)
        
        
        if(username == None or username == ""):
            logger.warning("Register attept without providing an username")
            return HttpResponseBadRequest(u"You have to provide a username")
        
        if(password == None or password == ""):
            logger.warning("Register attept without providing a password")
            return HttpResponseBadRequest(u"You have to provide a password")
        
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
            
            logger.error("Username %s provided for register is not unique. Details: %s " %(username, details))    
            return HttpResponse(status=409, content=details)

        try:
            user.full_clean()
        except ValidationError, err:
            message = " "
            details = message.join(error_msg)
            
            logger.error("full_clean() generated an error for username %s . Details: %s " %(username, details))
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
            logger.error("Error when trying to save user %s into database. Details: %s " %(username, details))
            
            return HttpResponse(status=409, content=details)
        
        #authenticate and login
        user = django_authenticate(username=username,
                                    password=password)
        
        if user is not None and user.is_active:
            django_login(request, user)
        
        logger.debug("Registration and login was successfull for username %s " %username)
        return HttpResponse(status=201, content=(u"User was successfully created"))
        

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
        logger.debug("GET was called for current session. Session key returned: %s" %request.session.session_key)
        return HttpResponse(request.session.session_key)
        
    elif request.method == "POST":
        logger.debug("POST was called for session")
        
        if request.user.is_authenticated():
            logger.warning("POST attempt for session but there is a username %s already logged in" %request.user.username)    
            return HttpResponse(u"session already created") 
        
        
        #put lock to create critical section
        lock.acquire() 
        try:
            new_user_id = User.objects.aggregate(Max('id'))
    
            if(new_user_id['id__max'] == None):
                new_user_id['id__max'] = 1
            else:
                new_user_id['id__max'] = new_user_id['id__max'] + 1
            
            temp_user = User.objects.create_user(str(new_user_id),'', 'passwd')
        except Exception, e:
            logger.error("Error in the section critical of session creation. Details: %s" %e)

        #release lock
        lock.release()
        
        user = django_authenticate(username=str(new_user_id), password='passwd')
        
        django_login(request, user)
        user.set_unusable_password()
        
        logger.debug("Session created. Temp session username %s" %user.username)
        return HttpResponse(u"session created")

    elif request.method == "DELETE":
        
        logger.debug("Delete session was called")
        
        # check if it is an session anonymous user - delete it
        # otherwise just logout
        if request.user.is_authenticated() and request.user.username.find("id__max") > -1:
            logger.debug("Temp session username %s deleted" %request.user.username) 
            request.user.delete()
        else:
            logger.debug("User %s has been logged out" %request.user.username) 
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
            logger.error("Error at new_password request. Details: %s"  % str(err.args))
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no new_password value could be retrieven from it")
        
        email = request_json['email']
        try:
            current_user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("The user could not be found or the email address hasn't been confirmed")
            return HttpResponseBadRequest(u"The user could not be found or the email address hasn't been confirmed") 
        
       
        um = UserManager()
        password = um.make_random_password(length=10,
                                           allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')
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
                        
            logger.debug("New password was successfully sent to email %s" %current_user.email)
            return HttpResponse(status=200,
                                content=(u"New password was sent to %s" % current_user.email), mimetype="application/json")
            
        except BadHeaderError:
            logger.error("There was an error while trying to send the email with the new password")
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
        logger.warning("The change password was called by an unauthenticated user")
        return HttpResponseForbidden(u"The request has to be made by an signed in user")


    if(request.method == "POST"):
        
        try: 
            request_json = json.loads(request.POST.keys()[0])
        except ValueError, err:
            logger.error("Error at change_password request. Details: %s"  % str(err.args))
            return HttpResponseBadRequest("JSON error: " + str(err.args))
        except IndexError:
            return HttpResponseBadRequest("POST data was empty so no change_password value could be retrieven from it")
    
        
        new_password = request_json['new_password']
        old_password = request_json['old_password']

        if(old_password == None or old_password == ''):
            logger.warning("The change password for user %s was called without a current password" %request.user.username)
            return HttpResponseBadRequest(u"You have to enter your current password")

        if not request.user.check_password(old_password):
            logger.warning("The change password for user %s was called with a wrong password" %request.user.username)
            return HttpResponse(u"Wrong password", status=401)
        
        if(new_password == None or new_password == ''):
            logger.warning("The change password for user %s was called without a new password" %request.user.username)
            return HttpResponseBadRequest(u"You have to provide a password")
        
        request.user.set_password(new_password)
        request.user.save()
        
        logger.debug("User %s changed password successfully" % request.user.username)
        return HttpResponse(u"Password changed succesfully",
                                status=200)
    
    logger.warning("Method %s is not accepted for change_password for User %s" %request.method  % request.user.username)
    return HttpResponseBadRequest(u"This URL only accepts POST requests")   


