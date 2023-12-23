import os
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate
from flask_restful import Api
from marshmallow import Schema, fields, validate, ValidationError
from flask_sqlalchemy import SQLAlchemy
from passlib.handlers.pbkdf2 import pbkdf2_sha256

app = Flask(__name__)
app.config[
    'SQLALCHEMY_DATABASE_URI'] = 'postgresql://lab_4_db_user:yWLIJiZE6CIgdHNSeo1cRkYL2fNHPBGL@dpg-cm3fj2mn7f5s73bo8fi0-a.oregon-postgres.render.com/lab_4_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
os.environ["JWT_SECRET_KEY"] = "283129114377609256790918969598140128636"
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
db = SQLAlchemy(app)
migrate = Migrate(app, db)
api = Api(app)
jwt = JWTManager(app)


class User(db.Model):
    user_id = db.Column(db.String, primary_key=True)
    user_name = db.Column(db.String, nullable=False)
    user_password = db.Column(db.String, nullable=False)


class Category(db.Model):
    category_id = db.Column(db.String, primary_key=True)
    category_name = db.Column(db.String, nullable=False)
    visibility = db.Column(db.String)
    owner_id = db.Column(db.String)


class Record(db.Model):
    id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String, db.ForeignKey('user.user_id'), nullable=False)
    category_id = db.Column(db.String, db.ForeignKey('category.category_id'), nullable=False)
    creation_data = db.Column(db.String, nullable=False)
    cost = db.Column(db.String, nullable=False)


class UserSchema(Schema):
    user_name = fields.String(required=True)
    user_id = fields.String(required=True)
    user_password = fields.String(required=True)


class CategorySchema(Schema):
    category_id = fields.String(required=True)
    category_name = fields.String(required=True, validate=validate.Length(min=1))
    visibility = fields.String(validate=validate.OneOf(['public', 'private']))
    owner_id = fields.String()


class RecordSchema(Schema):
    id = fields.String(required=True)
    user_id = fields.String(required=True)
    category_id = fields.String(required=True)
    creation_data = fields.String(required=True)
    cost = fields.String(required=True)


user_schema = UserSchema()
category_schema = CategorySchema()
record_schema = RecordSchema()


@app.route('/')
def hello_world():
    return 'This is Lab-work #4'


@app.route('/register', methods=['POST'])
def register_user():
    try:
        user_data = user_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    existing_user = User.query.filter_by(user_name=user_data['user_name']).first()
    if existing_user:
        return jsonify({'error': 'User with this username already exists'}), 409

    hashed_password = pbkdf2_sha256.hash(user_data['user_password'])
    new_user = User(user_name=user_data['user_name'], user_password=hashed_password, user_id=user_data['user_id'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created!'}), 201


# Логін користувача
@app.route('/login', methods=['POST'])
def login_user():
    try:
        user_data = user_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    user = User.query.filter_by(user_name=user_data['user_name']).first()
    if not user or not pbkdf2_sha256.verify(user_data['user_password'], user.user_password):
        return jsonify({'error': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.user_id)
    return jsonify(access_token=access_token), 200


# Пользователи
@app.route('/user', methods=['POST'])
def create_user():
    try:
        user_data = user_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    new_user = User(user_id=user_data['user_id'], user_name=user_data['user_name'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created!'}), 201


@app.route('/users', methods=['GET'])
def get_users():
    users = User.query.all()
    return jsonify(user_schema.dump(users, many=True))


@app.route('/user/<user_id>', methods=['GET'])
def get_user(user_id):
    user = User.query.get(user_id)
    if user:
        return jsonify(user_schema.dump(user))
    return jsonify({'error': 'User not found'}), 404


@app.route('/user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id != user_id:
        return jsonify({'error': 'You are not authorized to delete this user'}), 403

    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'error': 'User not found'}), 404


# Категорії
# Створено перевірку, чи співпадає ID поточного користувача із вказаним параметром owner_id
@app.route('/category', methods=['POST'])
@jwt_required()
def create_category():
    try:
        category_data = category_schema.load(request.get_json())
        current_user_id = get_jwt_identity()
        new_category = Category(category_id=category_data['category_id'],
                                category_name=category_data['category_name'],
                                visibility=category_data.get('visibility'),
                                owner_id=category_data.get('owner_id'))

        if new_category.owner_id and new_category.owner_id != current_user_id:
            return jsonify({'error': 'You are not allowed to set a different owner for the category'}), 403

        db.session.add(new_category)
        db.session.commit()
        return jsonify(category_schema.dump(new_category))
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400


@app.route('/categories', methods=['GET'])
@jwt_required()
def get_categories():
    try:
        categories = Category.query.all()
        app.logger.debug("Categories retrieved from the database: %s", categories)
        return jsonify(category_schema.dump(categories, many=True))
    except Exception as e:
        app.logger.exception("An error occurred while getting categories: %s", e)
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/category/<category_id>', methods=['GET'])
@jwt_required()
def get_category(category_id):
    category = Category.query.get(category_id)
    if category:
        return jsonify(category_schema.dump(category))
    return jsonify({'error': 'Category not found'}), 404


# Створено перевірку, чи співпадає id поточного користувача із id власника категорії
@app.route('/category/<category_id>', methods=['DELETE'])
@jwt_required()
def delete_category(category_id):
    category = Category.query.get(category_id)
    current_user_id = get_jwt_identity()
    if category:
        if category.owner_id != current_user_id:
            return jsonify({'error': 'You are not authorized to delete this category'}), 403
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'})
    return jsonify({'error': 'Category not found'}), 404


# Записи
# Створено перевірку, вказане при створенні категорії user_id повинне співпадати із ID поточного користувача
@app.route('/record', methods=['POST'])
@jwt_required()
def create_record():
    try:
        record_data = record_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400
    current_user_id = get_jwt_identity()
    category_id = record_data['category_id']
    category = Category.query.get(category_id)
    if category is None:
        return jsonify({'error': 'Category not found'}), 404
    visibility = category.visibility
    if visibility == 'private':
        user_id = record_data['user_id']

        if user_id != current_user_id:
            return jsonify({'error': 'You are not allowed to use this category'}), 403
    new_record = Record(id=record_data['id'],
                        user_id=record_data['user_id'],
                        category_id=record_data['category_id'],
                        creation_data=record_data['creation_data'],
                        cost=record_data['cost'])
    db.session.add(new_record)
    db.session.commit()
    return jsonify(record_schema.dump(new_record))



@app.route('/records', methods=['GET'])
@jwt_required()
def get_records():
    user_id = request.args.get('user_id')
    category_id = request.args.get('category_id')
    if not user_id and not category_id:
        return jsonify({'error': 'At least one of user_id or category_id is required'}), 400

    if user_id:
        records = Record.query.filter_by(user_id=user_id).all()
    elif category_id:
        records = Record.query.filter_by(category_id=category_id).all()
    else:
        records = Record.query.all()

    return jsonify(record_schema.dump(records, many=True))


# Створено перевірку, тепер запис може тільки той користувач, який його створив
@app.route('/record/<record_id>', methods=['DELETE'])
@jwt_required()
def delete_record(record_id):
    record = Record.query.get(record_id)
    current_user_id = get_jwt_identity()
    if record:
        if record.user_id != current_user_id:
            return jsonify({'error': 'You are not authorized to delete this record'}), 403
        db.session.delete(record)
        db.session.commit()
        return jsonify({'message': 'Record deleted successfully'})
    return jsonify({'error': 'Record not found'}), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
    db.create_all()
