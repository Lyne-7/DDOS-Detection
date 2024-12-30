# pip install Flask pandas matplotlib seaborn Werkzeug Flask-SQLAlchemy mysqlclien
from flask import Flask, render_template, request,redirect,url_for,session,flash
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import pickle
import dash
from network_dashboard import create_dash_app

import bcrypt
from io import StringIO
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy


import google.generativeai as genai
import os
from flask import Flask, render_template, request, jsonify

# Set your API key for Google Generative AI
os.environ["GOOGLE_API_KEY"] = "your api here"
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# Initialize the model
model = genai.GenerativeModel("models/gemini-pro")



#create app abject..........
app = Flask(__name__)



# database configuration------------------------------------------------------------------------------------------------
app.secret_key = "Secret Key"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql://root:@localhost/netdb"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize the database
db = SQLAlchemy(app)


#==========================load model and data
attack_model = pickle.load(open("NSL-KDD/attack_model.pkl",'rb'))
attack_encoder = pickle.load(open("NSL-KDD/attack_encoder.pkl",'rb'))
attack_rbscaler= pickle.load(open("NSL-KDD/attack_rbscaler.pkl",'rb'))


# Initialize the Dash app and link it to the Flask app
create_dash_app(app)



# creating tables in database and storage------------------------------------------------------------------------------

class Signup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100),unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)



#class Signin(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
 #   email = db.Column(db.String(100), nullable=False)
  #  password = db.Column(db.String(100), nullable=False)

# routes=======================================================
def is_signed_in():
    return 'id' in session


def is_signed_up():
    return 'id' not in session

def last_added_signup():
    return Signup.query.order_by(Signup.id.desc()).first()


#def last_added_signin():
 #   return Signin.query.order_by(Signin.id.desc()).first()

@app.route("/")
def home():
    #user_id = 1  # For example, you might get this from the session
    #user_name = get_user_name(user_id)
    return render_template('home.html')
@app.route("/home")
def home1():
    return render_template('home.html')
@app.route("/chatbot")
def chatbot():
    return render_template('chatbot.html')

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/index")
def index():
    user_name = None
    # Check if the user is signed in
    if is_signed_in():
        user = Signup.query.get(session['id'])  # Assuming 'id' is stored in session
        if user:
            user_name = user.fname  # Assuming 'fname' is the user's first name
        return render_template('index.html',user_name=user_name)
    # If the user is signed up but not signed in
    elif is_signed_up():
        return render_template("home.html", message_must_sign="Please log in...")
    # If the user is not signed up
    else:
        return render_template("home.html", message_must_sign="Please sign up...")


@app.route("/analysis")
def analysis():
    # This will render the Dash app
    return redirect('/analysis/')

# Route for signup page
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        fname = request.form.get('firstname')
        lname = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email is already registered
        if Signup.query.filter_by(email=email).first():
            flash("Email already registered.", 'error')
            return redirect('/signup')  # Redirect to signup to try again

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create a new user
        new_user = Signup(fname=fname, lname=lname, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            # Debug: Check if the user is added
            users = Signup.query.all()
            print(users)  # Log users to the console

            flash("Sign up successful! Please log in.", 'success')
            return redirect('/signin')  # Redirect to sign in page after successful signup

        except Exception as e:
            print(f"Error occurred during signup: {e}")  # Log the error
            db.session.rollback()  # Rollback the session in case of error
            flash("An error occurred during sign up.", 'error')
            return redirect('/signup')

    return render_template("home.html")


# Route for signin page
@app.route('/signin', methods=['POST', 'GET'])
def signin():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Debugging: Ensure data retrieval
        print(f"Email entered: {email}, Password entered: {password}")

        # Find user by email
        user = Signup.query.filter_by(email=email).first()
        print(f"User found: {user}")

        if user:
            # Check if the entered password matches the stored hashed password
            if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                session['id'] = user.id  # Store user ID in session
                flash(f"Welcome {user.fname} {user.lname}!", 'success')
                return redirect('/index')  # Redirect to a home or dashboard page
            else:
                flash("Invalid password.", 'error')
                return redirect('/signin')  # Redirect to signin page to try again
        else:
            flash("Email not registered.", 'error')
            return redirect('/signin')  # Redirect to signin page

    return render_template('index.html')







@app.route('/pred', methods=['POST'])
def pred():
    if request.method == 'POST':
        try:
            # Retrieve data from the form
            duration = int(request.form['duration'])
            protocol_type = request.form['protocol_type']
            service = request.form['service']
            flag = request.form['flag']
            src_bytes = int(request.form['src_bytes'])
            dst_bytes = int(request.form['dst_bytes'])
            logged_in = int(request.form['logged_in'])
            count = int(request.form['count'])
            srv_count = int(request.form['srv_count'])
            serror_rate = float(request.form['serror_rate'])
            srv_serror_rate = float(request.form['srv_serror_rate'])
            rerror_rate = float(request.form['rerror_rate'])
            same_srv_rate = float(request.form['same_srv_rate'])
            dst_host_count = int(request.form['dst_host_count'])
            dst_host_srv_count = int(request.form['dst_host_srv_count'])

            # Step 1: Create a DataFrame with the input data
            data = pd.DataFrame({
                'duration': [duration],
                'protocol_type': [protocol_type],
                'service': [service],
                'flag': [flag],
                'src_bytes': [src_bytes],
                'dst_bytes': [dst_bytes],
                'logged_in': [logged_in],
                'count': [count],
                'srv_count': [srv_count],
                'serror_rate': [serror_rate],
                'srv_serror_rate': [srv_serror_rate],
                'rerror_rate': [rerror_rate],
                'same_srv_rate': [same_srv_rate],
                'dst_host_count': [dst_host_count],
                'dst_host_srv_count': [dst_host_srv_count]
            })

            # Step 2: Encode the categorical features using the fitted encoder
            encoded_data = attack_encoder.transform(data[['protocol_type', 'service', 'flag']])

            # Create a DataFrame with the encoded columns
            encoded_df = pd.DataFrame(encoded_data,
                                      columns=attack_encoder.get_feature_names_out(
                                          ['protocol_type', 'service', 'flag']))

            # Drop the original categorical columns and concatenate the encoded columns
            data_encoded = pd.concat([data.drop(columns=['protocol_type', 'service', 'flag']), encoded_df], axis=1)

            # Step 3: Scale the numerical features using the same scaler
            data_scaled = attack_rbscaler.transform(data_encoded)

            # Step 4: Make a prediction using the trained model
            prediction = attack_model.predict(data_scaled)

            # Convert prediction to a more readable format if necessary
            prediction_result = "Alert Detected!" if prediction[0] == 1 else "All Clear"

            # Return the prediction result as JSON
            return jsonify({'prediction': prediction_result})

        except Exception as e:
            print(f"Error: {e}")
            return jsonify({'prediction': "An error occurred during prediction."})

    return jsonify({'prediction': "Please submit the form."})



# chatbot functionality here/=========================================================
# Modify the function to pass previous context
def generate_software_details(prompt, chat_history=None):
    # If there is any chat history, append it to the current prompt
    if chat_history:
        context = "\n".join(
            [f"User: {msg['text']}" if msg['text'].startswith('User') else f"AI: {msg['text']}" for msg in
             chat_history])
        prompt = f"{context}\nUser: {prompt}\nAI:"

    # Generate the AI response
    response = model.generate_content(prompt)

    # Return only the new AI response
    return response.text

# Store chats in memory (or use a database for persistence in production)
chats = [{'name': 'New Chat', 'id': 1, 'messages': []}]  # Default first chat




# Route to get the list of chats
@app.route('/get_chats', methods=['GET'])
def get_chats():
    return jsonify({'chats': chats})

# Route to get chat history for a specific chat
@app.route('/get_chat_history', methods=['GET'])
def get_chat_history():
    chat_id = int(request.args.get('chat_id'))
    chat = next((chat for chat in chats if chat['id'] == chat_id), None)
    if chat:
        return jsonify({'messages': chat['messages']})
    return jsonify({'messages': []})

# Updated route for generating AI responses
@app.route('/generate', methods=['POST'])
def generate():
    data = request.get_json()
    user_input = data.get('input')
    chat_id = data.get('chat_id')

    # Find the relevant chat and get the chat history
    chat = next((chat for chat in chats if chat['id'] == chat_id), None)
    chat_history = chat['messages'] if chat else []

    # Generate the AI response with context
    response = generate_software_details(user_input, chat_history)

    # Append user input and AI response to the chat history
    if chat:
        chat['messages'].append({'text': f'User: {user_input}'})
        chat['messages'].append({'text': f'AI: {response}'})

    return jsonify({'response': response})


# Route to create a new chat
@app.route('/new_chat', methods=['POST'])
def new_chat():
    data = request.get_json()
    chat_name = data.get('chat_name')
    new_chat_id = len(chats) + 1
    new_chat = {'name': chat_name, 'id': new_chat_id, 'messages': []}
    chats.append(new_chat)
    return jsonify({'status': 'Chat created successfully', 'chat_id': new_chat_id})

# Route to delete a chat
@app.route('/delete_chat', methods=['POST'])
def delete_chat():
    data = request.get_json()
    chat_id = data.get('chat_id')
    global chats
    chats = [chat for chat in chats if chat['id'] != chat_id]
    return jsonify({'status': f'Chat {chat_id} deleted successfully'})

def get_user_name(user_id):
    # Connect to your database
    user = Signup.query.filter_by(id=user_id).first()  # Returns the first matching user or None
    
    if user:
        return f"{user.fname}"
    else:
        return None
# python main
if __name__ == "__main__":
    app.run(debug=True)
