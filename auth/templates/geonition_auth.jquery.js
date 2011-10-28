/*
 This function registers a new user
 
 The function takes the following parameters:
 username - username of the user to be created (required)
 password - password for the user to be created (required)
 callback_function - function to be called after the response is received (optional)
 
 The callback_function will be passed the following parameters in a JSON object:
 status_code = 201/400/409
 message = message from server
*/
function register(username, password, callback_function) {

    var data = {};
    data['username'] = (username !== undefined) ? username : null;
    data['password'] = (password !== undefined) ? password : null;
   
    //add_CSRF_token_in_request_header();

    $.ajax({
      url: api_full_url + '{% url api_register %}',
      type: "POST",
      data: JSON.stringify(data),
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "json",
      beforeSend: function(xhr){
        //for cross site authentication using CORS
       xhr.withCredentials = true;
      }
    });
}

/*
 This function signs a user into the service.
 
 The function requires two parameters:
 username - The username of the user to sign in (required)
 password - The password of the user (required)
 callback_function - This function is called when the response is received from
                    the server. (optional)
                    
 The callback_function will be passed the following parameters in a JSON object:
 status_code = 201/400/409
 message = message from server
*/
function login(username, password, callback_function) {
    var data = {};
    data['username'] = (username !== undefined) ? username : null;
    data['password'] = (password !== undefined) ? password : null;

    //add_CSRF_token_in_request_header();
      
    $.ajax({
      url: api_full_url + '{% url api_login %}',
      type: "POST",
      data: JSON.stringify(data),
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "json",
      beforeSend: function(xhr){
        //for cross site authentication using CORS
       xhr.withCredentials = true;
      }
    });
}

/*
 The logout function send a logout request to the server
 
 The server returns 200 if logout successfull and
 400 if an error occured (no one is logged in)
 
 The logout function takes as parameter a callback function
 which will be passed the following parameters:
 status_code = 200
 message = message from server
*/
function logout(callback_function) {
    
    $.ajax({
      url: api_full_url + '{% url api_logout %}',
      type: "GET",
      data: {},
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "json"

    });
}


/*
This method creates a session for an anonymous user
so that the anonymoususer can save features and
profile values to other softgis apps.
*/
function create_session(callback_function) {

    //add_CSRF_token_in_request_header();
      
    $.ajax({
      url: api_full_url + '{% url api_session %}',
      type: "POST",
      data: {},
      async: false,
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "text",
      beforeSend: function(xhr){
        //for cross site authentication using CORS
       xhr.withCredentials = true;
      }
    });

}

/*
This method deletes the anonymoususers session
*/
function delete_session(callback_function) {
    
    //add_CSRF_token_in_request_header();
      
    $.ajax({
      url: api_full_url + '{% url api_session %}',
      type: "DELETE",
      data: {},
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "text",
      beforeSend: function(xhr){
        //for cross site authentication using CORS
       xhr.withCredentials = true;
      }
    });
    
}

/*
This method gets the session key for this user
*/
function get_session(callback_function) {
    
      $.ajax({
      url: api_full_url + '{% url api_session %}',
      type: "GET",
      data: {},
      success: function(data){
                    if(callback_function !== undefined) {
                        callback_function(data);
                    }
        },
      error: function(e) {
                    if(callback_function !== undefined) {
                        callback_function(e);    
                    }
      }, 
      dataType: "text",
      beforeSend: function(xhr){
        //for cross site authentication using CORS
       xhr.withCredentials = true;
      }
    });
    
    
}

/*
 This function send a new password for the user
 with the given email.
 
 The user is expected to be signed out when requesting
 a new password.
 
 Takes as parameters:
 email - email of the person that needs a new password (required)
 callback_function - the function to be called when a response from the server
                    is received (optional)
*/
function new_password(email, callback_function) {

    var data = {};
    data['email'] = (email !== undefined) ? email : null;
    
    //add_CSRF_token_in_request_header();
      
      
    $.ajax({
    url: api_full_url + '{% url api_new_password %}',
    type: "POST",
    data: JSON.stringify(data),
    success: function(data){
                  if(callback_function !== undefined) {
                      console.debug(data);
                      callback_function(data);
                  }
      },
    error: function(e) {
                  if(callback_function !== undefined) {
                      callback_function(e);    
                  }
    }, 
    dataType: "text",
    beforeSend: function(xhr){
      //for cross site authentication using CORS
      xhr.withCredentials = true;
    }
  });
}

/*
 This function changes the password for a user.
 
 It takes as parameters:
 new_password - the new password to change the old one to (required)
 callback_function - a callback function that will be called when a reponse
                    from the server is received (optional)
*/
function change_password(old_password, new_password, callback_function) { 
    var data = {};
    data['old_password'] = (old_password !== undefined) ? old_password : null;
    data['new_password'] = (new_password !== undefined) ? new_password : null;
    
    //add_CSRF_token_in_request_header();
      
      
    $.ajax({
        url: api_full_url + '{% url api_change_password %}',
        type: "POST",
        data: JSON.stringify(data),
        success: function(data){
                      if(callback_function !== undefined) {
                          callback_function(data);
                      }
          },
        error: function(e) {
                      if(callback_function !== undefined) {
                          callback_function(e);    
                      }
        }, 
        dataType: "text",
        beforeSend: function(xhr){
          //for cross site authentication using CORS
         xhr.withCredentials = true;
        }
    });
}
