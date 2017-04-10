#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import re
from string import letters

page_header = """
<!DOCTYPE html>
<html>
<head>
    <title>User Signup</title>
    <style type="text/css">
        .error {
            color: red;
        }
    </style>
</head>
<body style="background-color: skyblue">
    <h1 style="font-family: Garamond">
        <a href="/" style="text-decoration: none">LayneCode: Signup Page</a>
    </h1>
"""
master_form = """
<form method="post">
    <table>
        <tr>
        <th></th>
        <th></th>
        <th></th>
            <tr>
                <td><label style="font-family: Arial"><strong>
                    Create a username: </strong></label></td>
                <td><input type="text" name="username" style="background-color: lightblue" value="%(username)s")/></td>
                <td style="color: red">%(username_error)s</td>
            </tr>


            <tr>
                <td><label style="font-family: Arial"><strong>
                        Create a password:</strong></label></td>
                    <td><input type="password" name="password" style="background-color: lightblue" /></td>
                    <td style="color: red">%(password_error)s</td>
            </tr>


            <tr>
                <td><label style="font-family: Arial"><strong>
                        Verify your password: </strong></label></td>
                    <td><input type="password" name="verify_password" style="background-color: lightblue" /></td>
                    <td style="color: red">%(verify_error)s</td>
            </tr>

            <tr>
                <td><label style="font-family: Arial"><strong>
                    Enter email (optional): </strong></label></td>
                <td><input type="text" name="email" value="%(email)s"/></td>
                <td style="color: red">%(email_error)s</td>
            </tr>

            <tr>
                <td><input type="submit" name="submit"/></td>
            </tr>
    </table>
</form>
"""

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


page_footer = """
</body>
</html>
"""



class MainHandler(webapp2.RequestHandler):

    def writeform(self, username="", email="", username_error="", password_error="", verify_error="", email_error=""):

        params = {'username': username,
                'email': email,
                'username_error': username_error,
                'password_error': password_error,
                'verify_error': verify_error,
                'email_error': email_error
                    }

        content = page_header + master_form % (params) + page_footer
        self.response.write(content)

    def get(self):


        self.writeform()

    def post(self):

        have_error = False

        username = self.request.get("username")
        password = self.request.get("password")
        verify_password = self.request.get("verify_password")
        email = self.request.get("email")

        username_error = ""
        email_error = ""
        password_error = ""
        verify_error = ""

        if not valid_username(username):
            have_error = True
            username_error += "Not a valid username."

        if not valid_password(password):
            have_error = True
            password_error += "Not a valid password."

        if password != verify_password:
            have_error = True
            verify_error += "Passwords must match."

        if not valid_email(email):
            have_error = True
            email_error += "Not a valid email."

        if have_error:
            self.writeform(username, email, username_error, password_error, verify_error, email_error)
        else:
            self.redirect('/welcome?username=' + username)

class Welcome(webapp2.RequestHandler):

    def get(self):
        username = self.request.get('username')

        content = page_header + "<strong>Welcome!!! Glad to have you here, " + username  + page_footer
        self.response.write(content)


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', Welcome)
], debug=True)
