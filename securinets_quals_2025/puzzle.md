Intro:

Puzzle was a web challenge for the 2025 Securinets Qualifier CTF.
The challenge had the user find several misconfigurations in a web application that chained together would grant the user admin priviledges.
With those priviledges the user could download a password protected 'secrets.zip' file along with a 'dbconnect.exe' file.
With some simple inspection into the exe file you find a password for the zip file, getting the flag :)


Code inspection:


I always like to begin by reading provided code if I have it, so looking into it we see a couple of things:

app.py  auth.py  Dockerfile  models.py  requirements.txt  routes.py  static  templates

First and foremost I run 'grep -ri flag' and find . -name \*flag\* but I find no results.
This is one of the first times where a fake flag is not provided in the source code which I found to be quite interesting. 
Looking around I find a couple of things that might be handy later. Within routes.py we have this block of code:

```
@app.route('/users/<string:target_uuid>')
    def get_user_details(target_uuid):
        current_uuid = session.get('uuid')
        if not current_uuid:
            return jsonify({'error': 'Unauthorized'}), 401
        
        current_user = get_user_by_uuid(current_uuid)
        if not current_user or current_user['role'] not in ('0', '1'):
            return jsonify({'error': 'Invalid user role'}), 403
            
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("""
                SELECT uuid, username, email, phone_number, role, password
                FROM users 
                WHERE uuid = ?
            """, (target_uuid,))
            user = c.fetchone()
            
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'uuid': user['uuid'],
            'username': user['username'],
            'email': user['email'],
            'phone_number': user['phone_number'],
            'role': user['role'],
            'password': user['password']
        })
```

The route /users/[user uuid] supplies the client with the uuid, username, email, phone number, role, AND PASSWORD of the user with that uuid. >:)
This will be quite useful later. Now I need to find the uuid of a priviledged user. Inspecting the models.py file we see this piece of code:

```
        c.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
        if c.fetchone()[0] == 0:
            admin_uuid = str(uuid4())
            password = 'somepass'
            c.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", 
                     (admin_uuid, 'admin', 'admin@securinets.tn', '77777777', password, '0'))
```

Of course the password supplied is just a dummy, but what is useful here is that theres a priviledged user named admin.


Stealing admin uuid:


After some searching on the front end I find out that the uuid of any publisher is shown on a collaboration they create.
Testing with my own uuid I publish an article and see my own uuid on it. Now anyone can steal my account :(
Now all I need is an article that the admin created, however, a small line of code stands in my way:

```
 @app.route('/collab/accept/<string:request_uuid>', methods=['POST'])
    def accept_collaboration(request_uuid):
        if not session.get('uuid'):
            return jsonify({'error': 'Unauthorized'}), 401
        
        user = get_user_by_uuid(session['uuid'])
        if not user:
            return redirect('/login')
        if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403
        
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                c.execute("SELECT * FROM collab_requests WHERE uuid = ?", (request_uuid,))
                request = c.fetchone()
                
                if not request:
                    return jsonify({'error': 'Request not found'}), 404
                
                c.execute("""
                    INSERT INTO articles (uuid, title, content, author_uuid, collaborator_uuid)
                    VALUES (?, ?, ?, ?, ?)
                """, (request['article_uuid'], request['title'], request['content'], 
                      request['from_uuid'], request['to_uuid']))
                
                c.execute("UPDATE collab_requests SET status = 'accepted' WHERE uuid = ?", (request_uuid,))
                conn.commit()
                
                return jsonify({'message': 'Collaboration accepted'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
```

Right in the middle there:
```
if user['role'] == '0':
            return jsonify({'error': 'Admins cannot collaborate'}), 403
```
"Admins cannot collaborate". Well, that's it the website is secure.

Getting an admin article:

When making an article I know I can send a request for someone to collaborate with me, attempting to request an admin to collaborate is allowed, however the request just pends there.
At this point I went back into reading the code, and found the last bit I needed to steal an admin account, in the same block of code I pasted right above.
The code block does not check whether the user making the request to accept the collaboration request is the user that was requested to collaborate, in other words, anyone can authorize the collaboration of any article. All you would need is the request uuid.
This part is simple, request uuids are found when inspecting element on a pending collaboration request.

So, my exploitation chain was sending a collaboration request to admin, checking the html, taking the uuid, sending a request to /collab/accept/[request uuid], and finally, looking at the accepted request to find the admins uuid.

Now, armed with admins uuid, I send a request to /users/[admin uuid] and get admins login.


Post admin login:


After logging in as admin I go back to an interesting restricted endpoint: 
/data

On that endpoint I can download two files: 
'secrets.zip' and 'dbconnect.exe'.

secrets.zip is password protected, I first try admins login but it fails, I then go onto inspecting the dbconnect.exe file by using 'strings dbconnect.exe' and see the following line:
password = 'PUZZLE+7011_X207+!*'

Using that password I can finally unlock the secrets.zip file and am given a flag:

Securinets{777_P13c3_1T_Up_T0G3Th3R}
:D


Notes:


There is also an endpoint /db that allows the user to download an 'old.db' file containing various bcrypt hashes for various different users including admin.
I was able to crack admins password but it proved to be useless, unless I missed something?
