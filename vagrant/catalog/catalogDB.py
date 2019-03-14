from catalog import db, login_manager
from flask_login import UserMixin
from flask_dance.consumer.backend.sqla import OAuthConsumerMixin


@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)


class oAuth(OAuthConsumerMixin, db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship(User)
    # def __repr__(self):
    #    return f"User('{self.username}', '{self.email}')"


class Catalog(db.Model):

    cname = db.Column(db.String(250), nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    user = db.relationship(User)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    # def __repr__(self):
    #    return f"User('{self.id}', '{self.user}')"


class CatalogsItem(db.Model):
    name = db.Column(db.String(80), nullable=False)
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(250))
    price = db.Column(db.String(8))
    catalogs_id = db.Column(db.Integer, db.ForeignKey("catalog.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    catalogs = db.relationship(Catalog, backref="catalogsItem")
    user = db.relationship("User")

    # def __repr__(self):
    #    return f"User('{self.id}', '{self.description}', '{self.price}')"
