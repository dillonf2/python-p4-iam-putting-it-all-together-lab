#!/usr/bin/env python3

from flask import request, session, make_response, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
import ipdb
from config import app, db, api, bcrypt
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        if 'username' not in json or 'password' not in json:
            return {'error': 'Both username and password are required'}, 422

        existing_user = User.query.filter_by(username=json['username']).first()
        if existing_user:
            return {'error': 'Username already exists'}, 422

        hashed_password = bcrypt.generate_password_hash(json['password']).decode('utf-8')
        image_url = json.get('image_url', 'default_image_url')
        user = User(
            username=json.get('username'), 
            _password_hash=hashed_password,
            image_url=image_url,
            bio=json.get('bio')
        )
        db.session.add(user)
        db.session.commit()
        session['user_id']=user.id
        return {
            'username': user.username,
            'id': user.id,
            'image_url': user.image_url,
            'bio': user.bio
            }, 201

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')

        if user_id:
            user = User.query.filter_by(id=user_id).first()
            return {
                'username': user.username,
                'id': user.id,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {"Error": "No user is currently signed in."}, 401

class Login(Resource):
    def post(self):
        json = request.get_json()
        if 'username' not in json or 'password' not in json:
            return {'error': 'Both username and password are required'}, 400

        user = User.query.filter_by(username=json['username']).first()

        if user and user.authenticate(json['password']):

            session['user_id'] = user.id
            return {
                'username': user.username,
                'id': user.id,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200
        else:
            return {'error': 'Invalid username or password'}, 401


class Logout(Resource):
    def delete(self):
        user_id= session.get('user_id')
        if user_id is not None: 
            session['user_id']= None
            return {}, 204
        else:
            return {'error': 'No user is currently logged in.'}, 401

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            recipes = Recipe.query.filter_by(user_id=user.id).all()
            serialized_recipes = []
            for recipe in recipes:
                serialized_recipe = {
                    'title': recipe.title,
                    'instructions': recipe.instructions,
                    'minutes_to_complete': recipe.minutes_to_complete,
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'image_url': user.image_url,
                        'bio': user.bio
                    }
                }
                serialized_recipes.append(serialized_recipe)
            response_data = {
                'recipes': serialized_recipes
            }
            response = make_response(jsonify(serialized_recipes), 200)
            return response
        else:
            return {'error': 'You must log in to view recipes.'}, 401

    def post(self):
        user_id = session.get('user_id')
        if user_id:

            user = User.query.filter_by(id=user_id).first()

            json_data = request.get_json()
            title = json_data.get('title')
            instructions = json_data.get('instructions')
            minutes_to_complete = json_data.get('minutes_to_complete')

            if not (title and instructions and minutes_to_complete):
                return {'error': 'Title, instructions, and minutes_to_complete are required.'}, 422
            if len(instructions) < 50:
                return {'error': 'Instructions must be at least 50 characters long.'}, 422



            recipe = Recipe(
                title=title,
                instructions=instructions,
                minutes_to_complete=minutes_to_complete,
                user=user
            )   

            db.session.add(recipe)
            db.session.commit()

            serialized_recipe = {
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'image_url': user.image_url,
                    'bio': user.bio
                }
            }

            return serialized_recipe, 201
        else:
            return {'error': 'You must log in to create recipes.'}, 401

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)