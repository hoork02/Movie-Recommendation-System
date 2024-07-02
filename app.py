from flask import Flask,render_template, request, redirect, jsonify, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask import app
from datetime import datetime
from flask_login import LoginManager, UserMixin,login_required, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from decimal import Decimal
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message
import random
import string
import pandas as pd
from sklearn.metrics.pairwise import cosine_similarity
from sqlalchemy import or_
import requests
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import pandas as pd
import numpy as np
#---------------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------Initiliazations----------------------------------------------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:murti123@localhost/USMDB"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'hello_madarfaka!'


db = SQLAlchemy(app)

api_key = '6a29804ed5e0c1989e4e59d5c3dbb7ae'
BASE_URL = 'https://api.themoviedb.org/3'
DATABASE_URL = 'mysql://root:murti123@localhost/USMDB'
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.init_app(app)

# Ensure to set the login view
login_manager.login_view = 'login'

#-----------------------------------------------------------------------------------------------------------------------------------------
#-------------------------------------------------------Models(Classes representing Tables)-----------------------------------------------
class Movie(db.Model):
    __tablename__ = 'movie'
    movieID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    release_date = db.Column(db.Date, nullable=False)
    language = db.Column(db.String(50), nullable=False)
    length = db.Column(db.Integer, nullable = False)
    avg_rating = db.Column(db.Numeric(3, 2), nullable=False)

    def __repr__(self):
        return '<Movie %r>' % self.title
    
class Genre(db.Model):
    __tablename__ = 'genre'
    genreID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return '<Genre %r>' % self.name

class MovieGenre(db.Model):
    __tablename__ = 'movie_genre'

    movieID = db.Column(db.Integer, ForeignKey('movie.movieID'), primary_key=True)
    genreID = db.Column(db.Integer, ForeignKey('genre.genreID'), primary_key=True)

    # Define relationship with Movie and Genre tables
    movie = relationship('Movie', backref='genres')
    genre = relationship('Genre', backref='movies')

    def __repr__(self):
        return '<MovieGenre %r - %r>' % (self.movieID, self.genreID)

class Actor(db.Model):
    __tablename__ = 'actor'

    actorID = db.Column(db.Integer, primary_key=True, autoincrement = True)
    actorName = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return '<Actor %r>' % self.actorName

class MovieActor(db.Model):
    __tablename__ = 'movieactor'

    actorID = db.Column(db.Integer, db.ForeignKey('actor.actorID'), primary_key=True)
    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'), primary_key=True)

    # Define the relationship with the Actor table
    actor = db.relationship("Actor", backref="movie_actor")
    
    # Define the relationship with the Movie table
    movie = db.relationship("Movie", backref="movie_actor")

    def __repr__(self):
        return f'<MovieActor actorID={self.actorID} movieID={self.movieID}>'
    
class User(db.Model, UserMixin):
    __tablename__ = 'user'

    userID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(255), nullable=False)
    age = db.Column(db.Integer)
    email = db.Column(db.String(255), nullable=False)
    hashed_password = db.Column(db.String(255), nullable=False)
    

    def __repr__(self):
        return f'<User userID={self.userID} username={self.username} age={self.age} email={self.email} hashed_password={self.hashed_password}>'
    def get_id(self):
        return str(self.userID)

class Rating(db.Model):
    __tablename__ = 'rating'

    ratingID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    date = db.Column(db.Date)
    numeric_rating = db.Column(db.Float)
    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'))
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'))  # Establishing foreign key relationship

    user = db.relationship("User", backref="ratings")  # Define relationship with the User table
    # Define relationship with the Movie table
    movie = db.relationship("Movie", backref="ratings")


    def __repr__(self):
        return f'<Rating ratingID={self.ratingID} date={self.date} numeric_rating={self.numeric_rating} movieID={self.movieID} userID={self.userID}>'

class Comment(db.Model):
    __tablename__ = 'comment'

    commentID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    text = db.Column(db.Text)
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'))  # Establishing foreign key relationship
    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'))

    # Define relationship with the Movie table
    movie = db.relationship("Movie", backref="comments")
      # Define relationship with the User table
    user = db.relationship("User", backref="comments")  # Define relationship with the User table

    def __repr__(self):
        return f'<Comment commentID={self.commentID} text={self.text} userID={self.userID} movieID={self.movieID}>'

class Producer(db.Model):
    __tablename__ = 'producer'

    producerID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Producer producerID={self.producerID} name={self.name}>'

class MovieProducer(db.Model):
    __tablename__ = 'movie_producer'

    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'), primary_key=True)
    producerID = db.Column(db.Integer, db.ForeignKey('producer.producerID'), primary_key=True)

    movie = db.relationship("Movie", backref=db.backref("movie_producers"))
    producer = db.relationship("Producer", backref=db.backref("movie_producers"))

    def __repr__(self):
        return f'<MovieProducer movieID={self.movieID} producerID={self.producerID}>'

class Director(db.Model):
    __tablename__ = 'director'

    directorID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Director directorID={self.directorid} name={self.name}>'

class MovieDirector(db.Model):
    __tablename__ = 'moviedirector'

    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'), primary_key=True)
    directorID = db.Column(db.Integer, db.ForeignKey('director.directorID'), primary_key=True)

    # Define the relationship with the Movie table
    movie = db.relationship("Movie", backref="movie_directors")

    # Define the relationship with the Director table
    director = db.relationship("Director", backref="movie_directors")

    def __repr__(self):
        return f'<MovieDirector movieID={self.movieID} directorID={self.directorid}>'

class Admin(db.Model):
    __tablename__ = 'admin'

    adminID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'), nullable=False)

    # Establishing the relationship with the User model
    user = db.relationship("User", backref=db.backref("admins", lazy=True))

    def __repr__(self):
        return f'<Admin adminID={self.adminID} userID={self.userID}>'


class Recommendation(db.Model):
    __tablename__ = 'recommendation'

    recommendationID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'))
    movieID = db.Column(db.Integer, db.ForeignKey('movie.movieID'))

    # Define relationship with User and Movie tables
    user = db.relationship("User")
    movie = db.relationship("Movie")

    def __repr__(self):
        return f"<Recommendation(recommendationID={self.recommendationID}, userID={self.userID}, movieID={self.movieID})>"
    

class ChatMessage(db.Model):
    __tablename__ = 'chat_message'

    messageID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'), nullable=False)

    user = db.relationship("User", backref="chat_messages")

    def __repr__(self):
        return f'<ChatMessage messageID={self.messageID} content={self.content} timestamp={self.timestamp} userID={self.userID}>'
    
class AdminChatMessage(db.Model):
    __tablename__ = 'admin_chat_message'

    messageID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    adminID = db.Column(db.Integer, db.ForeignKey('admin.adminID'), nullable=False)
    userID = db.Column(db.Integer, db.ForeignKey('user.userID'), nullable=False)

    admin = db.relationship("Admin", backref="admin_chat_messages")
    user = db.relationship("User", backref="admin_chat_messages")

    def __repr__(self):
        return f'<AdminChatMessage messageID={self.messageID} content={self.content} timestamp={self.timestamp} adminID={self.adminID} userID={self.userID}>'



class Wishlist(db.Model):
    __tablename__ = 'wishlist'

    wishID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    userID = db.Column(db.Integer, ForeignKey('user.userID'), nullable=False)
    movieID = db.Column(db.Integer, ForeignKey('movie.movieID'), nullable=False)

    # Relationship with User and Movie models if available
    user = relationship("User")
    movie = relationship("Movie")

    def __repr__(self):
        return f"<Wishlist(wishID={self.wishID}, userID={self.userID}, movieID={self.movieID})>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#---------------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------ENDPOINTS--------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
     if request.method == 'POST':
         email = request.form['email']
         password = request.form['password']
        
         user = User.query.filter_by(email=email).first()
        
         if user and check_password_hash(user.hashed_password, password):
             login_user(user)
             next_page = request.args.get('next')
             return redirect(next_page or url_for('home'))
         else:
             flash('Invalid email or password', 'danger')

     return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        username = request.form['username']
        age = request.form['age']
        
        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_username = User.query.filter_by(username=username).first()
        
        if existing_user_email:
            flash('User with this email address already exists. Please try another email!', 'danger')
        elif existing_user_username:
            flash('Username already taken. Please choose another username.', 'danger')
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, age=age, email=email, hashed_password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful, please login', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html')



@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'signup' in request.form:
            return redirect(url_for('signup'))
        elif 'login' in request.form:
            return redirect(url_for('login'))
    return render_template('signup.html')


@app.route('/home', methods=['GET', 'POST'])
def home():
    if request.method == 'POST' and 'recommendations_button' in request.form:
        return redirect(url_for('recommendations'))
    else:
        # Fetch all movies from the database
        movies = Movie.query.all()

        if current_user.is_authenticated:
            # Check if the current user is an admin
            is_admin = Admin.query.filter_by(userID=current_user.userID).first()
            if is_admin:
                 page = request.args.get('page', 1, type=int)
                 per_page = 20
                 movies_paginated = Movie.query.paginate(page=page, per_page=per_page)
                 return render_template('admin_home.html', movies=movies_paginated)
        
        # If not an admin or not authenticated, render the regular home page
        # Pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        movies_paginated = Movie.query.paginate(page=page, per_page=per_page)
        return render_template('home.html', movies=movies_paginated)

# @app.route('/recommendations', methods=['GET', 'POST'])
# def recommendations():
#      if not current_user.is_authenticated:
#          # Handle the case where the user is not logged in
#          # You can redirect them to the login page or display a message
#          return render_template('login.html')  # Example: Redirect to login page

#      # Query the recommendations table to get all recommended movies for the current user
#      user_recommendations = Recommendation.query.filter_by(userID=current_user.userID).all()

#      # Extract the movie IDs from the recommendations
#      recommended_movie_ids = [recommendation.movieID for recommendation in user_recommendations]

#      # Query the Movie table to get details of the recommended movies
#      recommended_movies = Movie.query.filter(Movie.movieID.in_(recommended_movie_ids)).all()

#      # Render the recommendations.html template and pass the recommended movies
#      return render_template('recommended.html', movies=recommended_movies)


# def recommend_movies(user_id, genres, actors, directors):
#      genre_ids = [genre.genreID for genre in genres]
#      actor_ids = [actor.actorID for actor in actors]
#      director_ids = [director.directorID for director in directors]

#      genre_movies = db.session.query(Movie).join(MovieGenre).filter(MovieGenre.genreID.in_(genre_ids)).all()
#      actor_movies = db.session.query(Movie).join(MovieActor).filter(MovieActor.actorID.in_(actor_ids)).all()
#      director_movies = db.session.query(Movie).join(MovieDirector).filter(MovieDirector.directorID.in_(director_ids)).all()

#      recommended_movies = set(genre_movies + actor_movies + director_movies)

#      for movie in recommended_movies:
#          new_recommendation = Recommendation(userID=user_id, movieID=movie.movieID)
#          db.session.add(new_recommendation)

#      db.session.commit()


def calculate_user_similarity():
    user_ratings = Rating.query.all()
    if not user_ratings:
        # No ratings in the database yet, return None or an empty DataFrame
        return None  # or return pd.DataFrame()
    
    data = {
        'userID': [rating.userID for rating in user_ratings],
        'movieID': [rating.movieID for rating in user_ratings],
        'numeric_rating': [rating.numeric_rating for rating in user_ratings]
    }
    df = pd.DataFrame(data)
    user_item_matrix = df.pivot(index='userID', columns='movieID', values='numeric_rating').fillna(0)
    user_similarity = cosine_similarity(user_item_matrix)
    user_similarity_df = pd.DataFrame(user_similarity, index=user_item_matrix.index, columns=user_item_matrix.index)
    return user_similarity_df

def recommend_movies_cf(user_id, user_similarity_df, top_n=50):
    if user_id not in user_similarity_df.index:
        # User has not rated any movies yet, return an empty list of recommended movies
        return []
    
    similar_users = user_similarity_df[user_id].sort_values(ascending=False)
    similar_user_ids = similar_users.index[1:]
    similar_user_ratings = Rating.query.filter(Rating.userID.in_(similar_user_ids)).all()
    movie_scores = {}
    for rating in similar_user_ratings:
        if rating.movieID not in movie_scores:
            movie_scores[rating.movieID] = []
        movie_scores[rating.movieID].append(rating.numeric_rating)
    for movie_id in movie_scores:
        movie_scores[movie_id] = np.mean(movie_scores[movie_id])
    recommended_movies = sorted(movie_scores.items(), key=lambda x: x[1], reverse=True)[:top_n]
    recommended_movie_ids = [movie[0] for movie in recommended_movies]
    return Movie.query.filter(Movie.movieID.in_(recommended_movie_ids)).all()


@app.route('/recommendations', methods=['GET', 'POST'])
def recommendations():
    if not current_user.is_authenticated:
        return render_template('login.html')
    
    user_similarity_df = calculate_user_similarity()
    if user_similarity_df is None or user_similarity_df.empty:
        # Handle the case where there are no ratings in the database yet
        return render_template('recommended.html')
    
    recommended_movies = recommend_movies_cf(current_user.userID, user_similarity_df)
    return render_template('recommended.html', movies=recommended_movies)



@app.route('/movie/<int:movie_id>', methods=['GET', 'POST'])
def movie_details(movie_id):
    movie = Movie.query.get_or_404(movie_id)
    
    # Fetch associated actors, genres, directors, and producers
    actors = db.session.query(Actor).join(MovieActor).filter(MovieActor.movieID == movie_id).all()
    genres = db.session.query(Genre).join(MovieGenre).filter(MovieGenre.movieID == movie_id).all()
    directors = db.session.query(Director).join(MovieDirector).filter(MovieDirector.movieID == movie_id).all()
    producers = db.session.query(Producer).join(MovieProducer).filter(MovieProducer.movieID == movie_id).all()

    # Fetch existing rating and comment by the current user, if any
    existing_rating = None
    existing_comment = None
    if current_user.is_authenticated:
        existing_rating = Rating.query.filter_by(movieID=movie_id, userID=current_user.userID).first()
        existing_comment = Comment.query.filter_by(movieID=movie_id, userID=current_user.userID).first()

    if request.method == 'POST':
        if 'rating' in request.form:
            if existing_rating:
                flash('You have already rated this movie.', 'warning')
            else:
                rating = float(request.form['rating'])  # Convert to float for comparison
                if current_user.is_authenticated:
                    new_rating = Rating(
                        numeric_rating=rating,
                        movieID=movie_id,
                        userID=current_user.userID,
                        date=datetime.utcnow()
                    )
                    db.session.add(new_rating)

                    # Update the average rating logic
                    ratings = Rating.query.filter_by(movieID=movie_id).all()
                    total_ratings = len(ratings)
                    total_rating_sum = sum(float(rating.numeric_rating) for rating in ratings)
                    updated_avg_rating = total_rating_sum / total_ratings
                    movie.avg_rating = Decimal(updated_avg_rating)
                    db.session.commit()

                    if rating > 5:
                        pass
                        # recommend_movies(current_user.userID, genres, actors, directors)
                else:
                    flash('You need to log in to submit a rating.', 'danger')
                    return redirect(url_for('login', next=request.url))

        if 'comment' in request.form:
            if existing_comment:
                flash('You have already commented on this movie.', 'warning')
            else:
                comment = request.form['comment']
                if current_user.is_authenticated:
                    new_comment = Comment(
                        text=comment,
                        movieID=movie_id,
                        userID=current_user.userID
                    )
                    db.session.add(new_comment)
                    db.session.commit()
                else:
                    flash('You need to log in to submit a comment.', 'danger')
                    return redirect(url_for('login', next=request.url))

    comments = Comment.query.filter_by(movieID=movie_id).all()

    # Render the template with movie details, actors, genres, directors, producers, and comments
    # You can modify the template to display this information as required
    return render_template('movie.html', movie=movie, actors=actors, genres=genres, directors=directors, producers=producers, comments=comments)

    # Alternatively, if you want to display the actors and genres directly on the terminal, you can use jsonify
    
    #return jsonify({'movie': movie.title, 'actors': [actor.actorName for actor in actors], 'genres': [genre.name for genre in genres]})


@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '')
    source = request.args.get('source', '')
    admin_search = request.args.get('admin_search', '') == 'true'

    if source == 'recommendations':
        if current_user.is_authenticated:
            user_id = current_user.userID
            if query:
                # Perform case-insensitive search for movies in the recommendations list
                search_results = db.session.query(Movie).join(Recommendation).filter(
                    Recommendation.userID == user_id,
                    Movie.movieID == Recommendation.movieID,
                    Movie.title.ilike(f'%{query}%')
                ).all()
            else:
                search_results = db.session.query(Movie).join(Recommendation).filter(
                    Recommendation.userID == user_id,
                    Movie.movieID == Recommendation.movieID
                ).all()
        else:
            search_results = []
    else:
        if query:
            # Perform case-insensitive search for movies by title
            search_results = Movie.query.filter(Movie.title.ilike(f'%{query}%')).all()
        else:
            search_results = []

    # Choose the appropriate template based on the source of the search request
    if admin_search:
        return render_template('admin_search_result.html', query=query, movies=search_results)
    else:
        return render_template('search_results.html', query=query, movies=search_results)


@app.route('/user_profile', methods=['GET', 'POST'])
@login_required  # Ensures the user is logged in before accessing the profile
def user_profile():
    # Get the current user
    user = current_user

    # If the request is POST, update the user credentials
    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']
        new_age = request.form['age']
        new_password = request.form['password']
        confirm_password = request.form['confirm-password']

        # Check if the new username is already in use
        if User.query.filter_by(username=new_username).first() and new_username != user.username:
            flash('Username already in use. Please choose another username.', 'danger')
            return redirect(url_for('user_profile'))

        # Check if the new email is already in use
        if User.query.filter_by(email=new_email).first() and new_email != user.email:
            flash('Email already in use. Please choose another email.', 'danger')
            return redirect(url_for('user_profile'))

        # If new password and confirm password do not match
        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
            return redirect(url_for('user_profile'))

        # Update the user details
        user.username = new_username
        user.email = new_email
        user.age = new_age

        # If a new password is provided, update the password
        if new_password:
            user.hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')

        # Commit the changes to the database
        db.session.commit()

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('user_profile'))

    # Render the user profile template and pass the user details
    return render_template('user_profile.html', user=user)

@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))



@app.route('/admin_profile', methods=['GET'])
def admin_profile():
    if current_user.is_authenticated:
        # Check if the current user is an admin
        is_admin = Admin.query.filter_by(userID=current_user.userID).first()
        if is_admin:
            # Pagination
            page = request.args.get('page', 1, type=int)
            per_page = 20
            movies_paginated = Movie.query.paginate(page=page, per_page=per_page)
            return render_template('admin_profile.html', movies=movies_paginated)
    
    # If not an admin or not authenticated, redirect to home or login
    return redirect(url_for('home'))


@app.route('/delete_movie/<int:movie_id>', methods=['POST'])
def delete_movie(movie_id):
    try:
        # Find the movie by ID
        movie = Movie.query.get(movie_id)
        if not movie:
            flash('Movie not found', 'danger')
            return redirect(url_for('home'))

        # Delete related MovieGenre entries
        MovieGenre.query.filter_by(movieID=movie_id).delete()

        # Delete related MovieActor entries
        MovieActor.query.filter_by(movieID=movie_id).delete()

        # Delete related Ratings
        Rating.query.filter_by(movieID=movie_id).delete()

        # Delete related Comments
        Comment.query.filter_by(movieID=movie_id).delete()

        # Delete related MovieProducer entries
        MovieProducer.query.filter_by(movieID=movie_id).delete()

        # Delete related MovieDirector entries
        MovieDirector.query.filter_by(movieID=movie_id).delete()

        # Delete related Recommendations
        Recommendation.query.filter_by(movieID=movie_id).delete()

        # Finally, delete the movie itself
        db.session.delete(movie)
        db.session.commit()

        flash('Movie deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the movie: {str(e)}', 'danger')

    return redirect(url_for('admin_profile'))


@app.route('/insert_movie', methods=['GET', 'POST'])
def insert_movie():
    if request.method == 'POST':
        # Get the form data for the movie details
        title = request.form['title']
        description = request.form['description']
        release_date = request.form['releaseDate']
        language = request.form['language']
        length = request.form['length']

        # Check if the movie already exists
        existing_movie = Movie.query.filter_by(title=title, release_date=release_date, language=language).first()
        if existing_movie:
            flash('Movie already exists', 'danger')
            return redirect(url_for('insert_movie'))

        # Create a new movie object
        new_movie = Movie(title=title, description=description, release_date=release_date, language=language, length=length, avg_rating=0)
        db.session.add(new_movie)
        db.session.commit()

        # Get the form data for actors, directors, producers, and genres
        actors = request.form.getlist('actors[]')
        directors = request.form.getlist('directors[]')
        producers = request.form.getlist('producers[]')
        genres = request.form.getlist('genres[]')

        # Handle actors
        for actor_name in actors:
            # Check if the actor already exists
            existing_actor = Actor.query.filter_by(actorName=actor_name).first()
            if existing_actor:
                # Add the relation between the movie and actor
                movie_actor = MovieActor(actorID=existing_actor.actorID, movieID=new_movie.movieID)
                db.session.add(movie_actor)
            else:
                # Create a new actor object
                new_actor = Actor(actorName=actor_name)
                db.session.add(new_actor)
                db.session.commit()
                # Add the relation between the movie and actor
                movie_actor = MovieActor(actorID=new_actor.actorID, movieID=new_movie.movieID)
                db.session.add(movie_actor)

        # Handle directors
        for director_name in directors:
            # Check if the director already exists
            existing_director = Director.query.filter_by(name=director_name).first()
            if existing_director:
                # Add the relation between the movie and director
                movie_director = MovieDirector(directorID=existing_director.directorID, movieID=new_movie.movieID)
                db.session.add(movie_director)
            else:
                # Create a new director object
                new_director = Director(name=director_name)
                db.session.add(new_director)
                db.session.commit()
                # Add the relation between the movie and director
                movie_director = MovieDirector(directorID=new_director.directorID, movieID=new_movie.movieID)
                db.session.add(movie_director)

        # Handle producers
        for producer_name in producers:
            # Check if the producer already exists
            existing_producer = Producer.query.filter_by(name=producer_name).first()
            if existing_producer:
                # Add the relation between the movie and producer
                movie_producer = MovieProducer(producerID=existing_producer.producerID, movieID=new_movie.movieID)
                db.session.add(movie_producer)
            else:
                # Create a new producer object
                new_producer = Producer(name=producer_name)
                db.session.add(new_producer)
                db.session.commit()
                # Add the relation between the movie and producer
                movie_producer = MovieProducer(producerID=new_producer.producerID, movieID=new_movie.movieID)
                db.session.add(movie_producer)

        # Handle genres
        for genre_name in genres:
            # Check if the genre already exists
            existing_genre = Genre.query.filter_by(name=genre_name).first()
            if existing_genre:
                # Add the relation between the movie and genre
                movie_genre = MovieGenre(genreID=existing_genre.genreID, movieID=new_movie.movieID)
                db.session.add(movie_genre)
            else:
                # Create a new genre object
                new_genre = Genre(name=genre_name)
                db.session.add(new_genre)
                db.session.commit()
                # Add the relation between the movie and genre
                movie_genre = MovieGenre(genreID=new_genre.genreID, movieID=new_movie.movieID)
                db.session.add(movie_genre)

        db.session.commit()

        flash('Movie inserted successfully', 'success')
        return redirect(url_for('admin_profile'))

    # Render the insert_movie.html template for GET requests
    return render_template('insert_movie.html')


@app.route('/assign_admin/<int:user_id>', methods=['POST'])
def assign_admin(user_id):
    if not current_user.is_authenticated or not current_user.admins:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get(user_id)
    if user:
        if not Admin.query.filter_by(userID=user.userID).first():
            new_admin = Admin(userID=user.userID)
            db.session.add(new_admin)
            db.session.commit()
            flash(f'User {user.username} has been assigned as admin.', 'success')
        else:
            flash(f'User {user.username} is already an admin.', 'info')
    else:
        flash('User not found.', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_authenticated:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('admin_users'))
    
    user_to_delete = User.query.get(user_id)
    if not user_to_delete:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))

    # Check if the user to be deleted is an admin
    admin_to_delete = Admin.query.filter_by(userID=user_to_delete.userID).first()
    if admin_to_delete:
        flash('An admin cannot be deleted.', 'danger')
        return redirect(url_for('admin_users'))

    # Delete associated records if they exist
    ratings = Rating.query.filter_by(userID=user_to_delete.userID).all()
    if ratings:
        for rating in ratings:
            db.session.delete(rating)
    
    comments = Comment.query.filter_by(userID=user_to_delete.userID).all()
    if comments:
        for comment in comments:
            db.session.delete(comment)
    
    recommendations = Recommendation.query.filter_by(userID=user_to_delete.userID).all()
    if recommendations:
        for recommendation in recommendations:
            db.session.delete(recommendation)
    
    chat_messages = ChatMessage.query.filter_by(userID=user_to_delete.userID).all()
    if chat_messages:
        for message in chat_messages:
            db.session.delete(message)
    
    admin_chat_messages = AdminChatMessage.query.filter_by(userID=user_to_delete.userID).all()
    if admin_chat_messages:
        for message in admin_chat_messages:
            db.session.delete(message)
    
    wishlist_items = Wishlist.query.filter_by(userID=user_to_delete.userID).all()
    if wishlist_items:
        for item in wishlist_items:
            db.session.delete(item)

    db.session.delete(user_to_delete)
    db.session.commit()

    flash(f'User {user_to_delete.username} and all associated data have been deleted.', 'success')

    return redirect(url_for('admin_users'))

@app.route('/search_users', methods=['GET'])
def search_users():
    if not current_user.is_authenticated or not current_user.admins:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('admin_users'))
    
    query = request.args.get('query', '')
    if query:
        search_results = User.query.filter(User.username.ilike(f'%{query}%')).all()
    else:
        search_results = User.query.all()
    
    return render_template('user_search.html', users=search_results)


@app.route('/admin_users', methods=['GET'])
def admin_users():
    if not current_user.is_authenticated or not current_user.admins:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('home'))

    # Pagination
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=20)

    return render_template('users.html', users=users)


@app.route('/delete_own_account', methods=['GET', 'POST'])
@login_required
def delete_own_account():
    if request.method == 'POST':
        user = current_user  # Assuming you have a `current_user` object
        if user:
            # Delete associated records if they exist
            ratings = Rating.query.filter_by(userID=user.userID).all()
            if ratings:
                for rating in ratings:
                    db.session.delete(rating)
            
            comments = Comment.query.filter_by(userID=user.userID).all()
            if comments:
                for comment in comments:
                    db.session.delete(comment)
            
            recommendations = Recommendation.query.filter_by(userID=user.userID).all()
            if recommendations:
                for recommendation in recommendations:
                    db.session.delete(recommendation)
            
            chat_messages = ChatMessage.query.filter_by(userID=user.userID).all()
            if chat_messages:
                for message in chat_messages:
                    db.session.delete(message)
            
            admin_chat_messages = AdminChatMessage.query.filter_by(userID=user.userID).all()
            if admin_chat_messages:
                for message in admin_chat_messages:
                    db.session.delete(message)
            
            wishlist_items = Wishlist.query.filter_by(userID=user.userID).all()
            if wishlist_items:
                for item in wishlist_items:
                    db.session.delete(item)

            # Check if the user is an admin
            admin = Admin.query.filter_by(userID=user.userID).first()
            if admin:
                db.session.delete(admin)  # Remove admin record

            # Delete the user
            db.session.delete(user)
            db.session.commit()

            flash('Your account has been deleted.', 'success')
            return redirect(url_for('signup'))
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('home'))
    else:
        return render_template('confirm_delete_account.html')


@app.route('/update_movie/<int:movie_id>', methods=['GET', 'POST'])
def update_movie(movie_id):
    movie = Movie.query.get_or_404(movie_id)

    if request.method == 'POST':
        # Update movie details
        movie.title = request.form['title']
        movie.description = request.form['description']
        movie.release_date = request.form['releaseDate']
        movie.language = request.form['language']
        movie.length = request.form['length']

        # Clear existing associations
        MovieGenre.query.filter_by(movieID=movie_id).delete()
        MovieActor.query.filter_by(movieID=movie_id).delete()
        MovieDirector.query.filter_by(movieID=movie_id).delete()
        MovieProducer.query.filter_by(movieID=movie_id).delete()

        # Update associated genres
        genres = [g for g in request.form.getlist('genres[]') if g.strip()]
        for genre_name in genres:
            existing_genre = Genre.query.filter_by(name=genre_name).first()
            if existing_genre:
                movie_genre = MovieGenre(genreID=existing_genre.genreID, movieID=movie.movieID)
            else:
                new_genre = Genre(name=genre_name)
                db.session.add(new_genre)
                db.session.commit()
                movie_genre = MovieGenre(genreID=new_genre.genreID, movieID=movie.movieID)
            db.session.add(movie_genre)

        # Update associated actors
        actors = [a for a in request.form.getlist('actors[]') if a.strip()]
        for actor_name in actors:
            existing_actor = Actor.query.filter_by(actorName=actor_name).first()
            if existing_actor:
                movie_actor = MovieActor(actorID=existing_actor.actorID, movieID=movie.movieID)
            else:
                new_actor = Actor(actorName=actor_name)
                db.session.add(new_actor)
                db.session.commit()
                movie_actor = MovieActor(actorID=new_actor.actorID, movieID=movie.movieID)
            db.session.add(movie_actor)

        # Update associated directors
        directors = [d for d in request.form.getlist('directors[]') if d.strip()]
        for director_name in directors:
            existing_director = Director.query.filter_by(name=director_name).first()
            if existing_director:
                movie_director = MovieDirector(directorID=existing_director.directorID, movieID=movie.movieID)
            else:
                new_director = Director(name=director_name)
                db.session.add(new_director)
                db.session.commit()
                movie_director = MovieDirector(directorID=new_director.directorID, movieID=movie.movieID)
            db.session.add(movie_director)

        # Update associated producers
        producers = [p for p in request.form.getlist('producers[]') if p.strip()]
        for producer_name in producers:
            existing_producer = Producer.query.filter_by(name=producer_name).first()
            if existing_producer:
                movie_producer = MovieProducer(producerID=existing_producer.producerID, movieID=movie.movieID)
            else:
                new_producer = Producer(name=producer_name)
                db.session.add(new_producer)
                db.session.commit()
                movie_producer = MovieProducer(producerID=new_producer.producerID, movieID=movie.movieID)
            db.session.add(movie_producer)

        db.session.commit()

        flash('Movie updated successfully!', 'success')
        return redirect(url_for('update_movie', movie_id=movie_id))

    # Prepare existing data for the form
    existing_genres = [genre.genre.name for genre in movie.genres]
    existing_actors = [actor.actor.actorName for actor in movie.movie_actor]
    existing_directors = [director.director.name for director in movie.movie_directors]
    existing_producers = [producer.producer.name for producer in movie.movie_producers]

    return render_template('update_movie.html', movie=movie, existing_genres=existing_genres, existing_actors=existing_actors, existing_directors=existing_directors, existing_producers=existing_producers)


@app.route('/community_chat')
@login_required
def community_chat():
    messages = ChatMessage.query.order_by(ChatMessage.timestamp).all()
    return render_template('community_chat.html', messages=messages)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['content']
    user_id = current_user.userID
    new_message = ChatMessage(content=content, userID=user_id)
    db.session.add(new_message)
    db.session.commit()
    return redirect(url_for('community_chat'))

@app.route('/admin_chat')
@login_required
def admin_chat():
    messages = AdminChatMessage.query.order_by(AdminChatMessage.timestamp).all()
    for message in messages:
        user = User.query.filter_by(userID=message.userID).first()
        message.admin_username = user.username if user else "Unknown"
    return render_template('admin_chat.html', messages=messages)

@app.route('/send_admin_message', methods=['POST'])
@login_required
def send_admin_message():
    content = request.form['content']
    user_id = current_user.userID  
    admin = Admin.query.filter_by(userID=current_user.userID).first()
    if admin:
        admin_id = admin.adminID
        new_message = AdminChatMessage(content=content, adminID=admin_id, userID=user_id)
        db.session.add(new_message)
        db.session.commit()
    else:
        flash("You are not authorized to send admin messages.")
    return redirect(url_for('admin_chat'))


@app.route('/wishlist')
def wishlist():
    wishlist_entries = Wishlist.query.filter_by(userID=current_user.userID).all()
    wishlist_movies = []
    for entry in wishlist_entries:
        movie = Movie.query.get(entry.movieID)
        if movie:
            wishlist_movies.append(movie)
    return render_template('wishlist.html', movies=wishlist_movies)
# Add to wishlist route
@app.route('/add_to_wishlist/<int:movie_id>', methods=['POST'])
def add_to_wishlist(movie_id):
    # Check if the movie is already in the wishlist
    existing_wishlist_entry = Wishlist.query.filter_by(movieID=movie_id, userID=current_user.userID).first()
    if existing_wishlist_entry:
        flash('Movie is already in your wishlist.', 'warning')
    else:
        new_wishlist_entry = Wishlist(userID=current_user.userID, movieID=movie_id)
        db.session.add(new_wishlist_entry)
        db.session.commit()
        flash('Movie added to wishlist successfully.', 'success')
    return redirect(url_for('movie_details', movie_id=movie_id))

# Remove from wishlist route
@app.route('/remove_from_wishlist/<int:movie_id>', methods=['POST'])
def remove_from_wishlist(movie_id):
    wishlist_entry = Wishlist.query.filter_by(movieID=movie_id, userID=current_user.userID).first()
    if wishlist_entry:
        db.session.delete(wishlist_entry)
        db.session.commit()
        flash('Movie removed from wishlist successfully.', 'success')
    else:
        flash('Movie is not in your wishlist.', 'warning')
    return redirect(url_for('wishlist'))
#---------------------------------------------------------------------------------------------------------------------------------------------------
#------------------------------------------------------API INTEGRATION------------------------------------------------------------------------------



import requests
def fetch_movie_details(page=1):
    url = f"{BASE_URL}/discover/movie"
    params = {
        "api_key": api_key,
        "language": "en-US",
        "sort_by": "popularity.desc",
        "include_adult": "false",
        "include_video": "false",
        "page": page
    }

    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get("results", [])
    else:
        print("Failed to fetch movie data from TMDb API")
        return []

def fetch_actor_details(movie_id):
    url = f"{BASE_URL}/movie/{movie_id}/credits"
    params = {"api_key": api_key}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get("cast", [])
    else:
        print(f"Failed to fetch actor data for movie ID {movie_id} from TMDb API")
        return []

def fetch_director_details(movie_id):
    url = f"{BASE_URL}/movie/{movie_id}/credits"
    params = {"api_key": api_key}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        crew = data.get("crew", [])
        directors = [member for member in crew if member.get("job") == "Director"]
        return directors
    else:
        print(f"Failed to fetch director data for movie ID {movie_id} from TMDb API")
        return []

def fetch_producer_details(movie_id):
    # Assuming TMDb API does not provide producer information directly
    # You may need to use another data source or manually input producer details
    return []

def fetch_genre_details(movie_id):
    url = f"{BASE_URL}/movie/{movie_id}"
    params = {"api_key": api_key}

    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        return data.get("genres", [])
    else:
        print(f"Failed to fetch genre data for movie ID {movie_id} from TMDb API")
        return []

def populate_database():
    # Adjust the number of pages as needed to fetch more movies
    for page in range(1, 8):  # Fetching 5 pages of movies (each page contains 20 movies)
        movies = fetch_movie_details(page)
        for movie_data in movies:
            # Extract movie details
            title = movie_data.get("title")
            
            # Check if the movie already exists in the database by title
            existing_movie = Movie.query.filter_by(title=title).first()
            if existing_movie:
                # Movie already exists, skip adding it
                continue

            description = movie_data.get("overview")
            release_date = movie_data.get("release_date") or None  # Set release date to None if not available
            language = movie_data.get("original_language")
            length = movie_data.get("runtime") or 0  # Set default value to 0 if movie length is not available
            avg_rating = movie_data.get("vote_average")

            # Create Movie instance and add to database
            movie = Movie(
                title=title,
                description=description,
                release_date=release_date,
                language=language,
                length=length,
                avg_rating=avg_rating
            )
            db.session.add(movie)

            # Fetch and add actor details
            actors = fetch_actor_details(movie_data.get("id"))
            for actor_data in actors:
                actor_name = actor_data.get("name")
                # Check if actor already exists in database
                actor = Actor.query.filter_by(actorName=actor_name).first()
                if not actor:
                    actor = Actor(actorName=actor_name)
                    db.session.add(actor)
                # Check if MovieActor association already exists
                if not MovieActor.query.filter_by(actorID=actor.actorID, movieID=movie.movieID).first():
                    # Create MovieActor association
                    movie_actor = MovieActor(actor=actor, movie=movie)
                    db.session.add(movie_actor)

            # Fetch and add director details
            directors = fetch_director_details(movie_data.get("id"))
            for director_data in directors:
                director_name = director_data.get("name")
                # Check if director already exists in database
                director = Director.query.filter_by(name=director_name).first()
                if not director:
                    director = Director(name=director_name)
                    db.session.add(director)
                # Check if MovieDirector association already exists
                if not MovieDirector.query.filter_by(directorID=director.directorID, movieID=movie.movieID).first():
                    # Create MovieDirector association
                    movie_director = MovieDirector(director=director, movie=movie)
                    db.session.add(movie_director)

            # Fetch and add genre details
            genres = fetch_genre_details(movie_data.get("id"))
            for genre_data in genres:
                genre_name = genre_data.get("name")
                # Check if genre already exists in database
                genre = Genre.query.filter_by(name=genre_name).first()
                if not genre:
                    genre = Genre(name=genre_name)
                    db.session.add(genre)
                # Check if MovieGenre association already exists
                if not MovieGenre.query.filter_by(genreID=genre.genreID, movieID=movie.movieID).first():
                    # Create MovieGenre association
                    movie_genre = MovieGenre(genre=genre, movie=movie)
                    db.session.add(movie_genre)

        db.session.commit()





if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
        populate_database()  # Populate the database with TMDB data
    app.run(debug=True)
