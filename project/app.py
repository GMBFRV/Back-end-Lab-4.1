import os
from flask import Flask, request, jsonify
from flask_migrate import Migrate
from marshmallow import Schema, fields, validate, ValidationError
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:l4N7328CpBRRlEq9o0tEjvZRkSTWhAY0@dpg-clsl98gcmk4c73cbclt0-a.oregon-postgres.render.com/lab3db_95dp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class User(db.Model):
    user_id = db.Column(db.String, primary_key=True)
    user_name = db.Column(db.String, nullable=False)


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
    return 'This is Lab-work #3'


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
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'error': 'User not found'}), 404


# Категории
@app.route('/category', methods=['POST'])
def create_category():
    try:
        category_data = category_schema.load(request.get_json())
        new_category = Category(category_id=category_data['category_id'],
                                category_name=category_data['category_name'],
                                visibility=category_data.get('visibility'),
                                owner_id=category_data.get('owner_id'))
        db.session.add(new_category)
        db.session.commit()

        return jsonify(category_schema.dump(new_category))
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400


@app.route('/categories', methods=['GET'])
def get_categories():
    try:
        categories = Category.query.all()
        app.logger.debug("Categories retrieved from the database: %s", categories)
        return jsonify(category_schema.dump(categories, many=True))
    except Exception as e:
        app.logger.exception("An error occurred while getting categories: %s", e)
        return jsonify({'error': 'Internal Server Error'}), 500


@app.route('/category/<category_id>', methods=['GET'])
def get_category(category_id):
    category = Category.query.get(category_id)
    if category:
        return jsonify(category_schema.dump(category))
    return jsonify({'error': 'Category not found'}), 404


@app.route('/category/<category_id>', methods=['DELETE'])
def delete_category(category_id):
    category = Category.query.get(category_id)
    if category:
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully'})
    return jsonify({'error': 'Category not found'}), 404


# Записи
@app.route('/record', methods=['POST'])
def create_record():
    try:
        record_data = record_schema.load(request.get_json())
    except ValidationError as err:
        return jsonify({'error': err.messages}), 400

    category_id = record_data['category_id']
    category = Category.query.get(category_id)
    if category is None:
        return jsonify({'error': 'Category not found'}), 404

    visibility = category.visibility
    if visibility == 'private':
        user_id = record_data['user_id']
        if user_id != category.owner_id:
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


@app.route('/record/<record_id>', methods=['DELETE'])
def delete_record(record_id):
    record = Record.query.get(record_id)
    if record:
        db.session.delete(record)
        db.session.commit()
        return jsonify({'message': 'Record deleted successfully'})
    return jsonify({'error': 'Record not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
    db.create_all()
