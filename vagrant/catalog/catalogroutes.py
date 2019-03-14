# Normal import for flask
from flask import (
    render_template,
    redirect,
    flash,
    jsonify,
    url_for,
    request,
    session,
    make_response,
)
from catalog.catalogDB import Catalog, CatalogsItem, User, oAuth
from catalog.flaskForms import LoginForm, SignUpForm
from catalog import app, ma, db, bcrypt, login_manager
from flask import session as login_session
import random, string, os, requests

# Authentication & login session
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

# from flask_dance.consumer.backend.sqla import SQLALchemyBackend
from flask_login import login_user, current_user, logout_user
from flask_bcrypt import Bcrypt

github_blueprint = make_github_blueprint(
    client_id="decaefc46f68ce0a6ff4",
    client_secret="d9f9f09ae8126025ac78f3a4b6cbb04a0a6f17f4",
)

app.register_blueprint(github_blueprint, url_prefix="/github_login")

CLIENT_ID = json.loads(open("client_secrets.json", "r").read())["web"]["client_id"]


@app.context_processor
def override_url_for():
    return dict(url_for=dated_url_for)


def dated_url_for(endpoint, **values):
    if endpoint == "static":
        filename = values.get("filename", None)
        if filename:
            file_path = os.path.join(app.root_path, endpoint, filename)
            values["q"] = int(os.stat(file_path).st_mtime)
    return url_for(endpoint, **values)


@app.route("/login", methods=["GET"])
def showlogin():
    state = "".join(
        random.choice(string.ascii_uppercase + string.digits) for x in xrange(32)
    )
    login_session["state"] = state

    return render_template("login.html", STATE=state)

@app.route('/localsignin', methods=["GET", "POST"])
def localsignins():
    form = LoginForm()
    user = User.query.filter_by(email=form.email.data).first()
    if user and bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for("displayCatalog"))
    else:
        return render_template("localsignin.html", form=form)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf - 8"
        )
        new_user = User(
            username=form.username.data, email=form.email.data, password=hash_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Account has been created for", "success")
        return redirect(url_for("testing"))
    else:
        return render_template("signup.html", form=form)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output



@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

def createUser(login_session):
    hash_password = bcrypt.generate_password_hash('password').decode(
            "utf - 8"
        )
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], password=hash_password)
    db.session.add(newUser)
    db.session.commit()
    user = db.session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = db.session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = db.session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['provider']
    
        flash("You have successfully been logged out.")
        return redirect(url_for('displayCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('displayCatalog'))


@app.route("/github")
def github_login():
    print(github.authorized)
    if not github.authorized:
        return redirect(url_for("github.login"))
    account_info = github.get("/user")
    if account_info.ok:
        account_info_json = account_info.json()
        return redirect(url_for("displayCatalog"))


@app.route("/", methods=["GET", "POST"])
def displayCatalog():
    displayCatalog = db.session.query(Catalog.cname).all()
    displayCatItems = (
        db.session.query(Catalog.cname, CatalogsItem.name)
        .filter(Catalog.id == CatalogsItem.catalogs_id)
        .all()
    )
    if 'username' in login_session:
        return render_template(
            "index.html", displayCatItems=displayCatItems, displayCatalog=displayCatalog
        )

    else:
        return render_template(
            "publicIndex.html",
            displayCatItems=displayCatItems,
            displayCatalog=displayCatalog,
        )


@app.route("/catalog/<name>/items", methods=["GET"])
def getCatalogItems(name):
    displayCatalogs = db.session.query(Catalog.cname).all()
    displayCatalog = (
        db.session.query(Catalog.cname).filter(Catalog.cname == name).first()
    )
    getItems = (
        db.session.query(Catalog, CatalogsItem)
        .filter((Catalog.id == CatalogsItem.catalogs_id) & (Catalog.cname == name))
        .all()
    )
    return render_template(
        "catalogItem.html",
        displayCatalogs=displayCatalogs,
        displayCatalog=displayCatalog,
        getItems=getItems,
    )


@app.route("/catalog/<getname>/<getdescname>", methods=["GET", "POST"])
def getCatalogDescription(getname, getdescname):
    getItem = db.session.query(CatalogsItem).filter(CatalogsItem.name == getdescname)
    if current_user.is_authenticated == False or 'username' not in login_session:
        return render_template("publicCatalogDescription.html", getItem=getItem)
    else:
        return render_template("catalogDescription.html", getItem=getItem)


@app.route("/catalog/<editname>/edit", methods=["GET", "POST"])
def editCatalog(editname):
    if 'username' not in login_session:
        return redirect('/login')
    editItem = db.session.query(CatalogsItem).filter_by(name=editname).one()
    #catalog = db.session.query(CatalogsItem).filter_by(id=editItem.user_id).one()
    #if login_session['user_id'] != editItem.user_id:
    #    return "<script>function myFunction() {alert('You are not authorized to edit this Catalo item. Please create your own Catalog item in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == "POST":
        if request.form["name"]:
            editItem.name = request.form["name"]
        if request.form["description"]:
            editItem.description = request.form["description"]
        if request.form["price"]:
            editItem.price = request.form["price"]
        db.session.add(editItem)
        flash("Catalog item successfully edited")
        db.session.commit()
        return redirect(url_for("displayCatalog"))
    else:
        return render_template("editCatalog.html", editItem=editItem)


@app.route("/catalog/<deletename>/delete", methods=["GET", "POST"])
def deleteCatalog(deletename):
    if 'username' not in login_session:
        return redirect('/login')
    deleteItem = db.session.query(CatalogsItem).filter_by(name=deletename).one()
    #catalog = db.session.query(CatalogsItem).filter_by(id=deleteItem.user_id).one()
    #if login_session['user_id'] != catalog.user_id:
    #    return(
    #        "<script>function myFunction() {alert('You are not authorized to delete this Catalog item. Please create your own Catalog item in order to delete.');}</script><body onload='myFunction()''>"
    #    )
    if request.method == "POST":
        db.session.delete(deleteItem)
        flash("Catalog successfully deleted")
        db.session.commit()
        return redirect(url_for("displayCatalog"))
    else:
        return render_template("deleteCatalog.html", deleteItem=deleteItem)


@app.route("/catalog/new", methods=["GET", "POST"])
def newCatalogItem():
    if current_user.is_authenticated == False:
        return redirect("/login")
    if request.method == "POST":
        getName = request.form["name"]
        getDescription = request.form["description"]
        getPrice = request.form["price"]
        getCatalog = request.form["catLog"]

        addCatalog = Catalog(cname=getCatalog)
        db.session.add(addCatalog)
        db.session.commit()

        addCatItem = CatalogsItem(
            name=getName,
            description=getDescription,
            price=getPrice,
            catalogs=addCatalog,
        )
        db.session.add(addCatItem)
        flash("you just added a new catalog item")
        db.session.commit()
        return redirect(url_for("displayCatalog"))
    else:
        return render_template("newCatalogItem.html")


class CatalogSchema(ma.Schema):
    class Meta:
        model = CatalogsItem


@app.route("/catalogs.json", methods=["GET"])
def catalogJSON():
    catalogs = CatalogsItem.query.all()
    catalogSchema = CatalogSchema(many=True)
    output = catalogSchema.dump(catalogs).data
    return jsonify({"Category": output})

