import os
from flask import Flask, render_template, request, redirect, url_for, session
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# Define the absolute path to your templates directory
template_folder = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'templates')

# Initialize Flask app
app = Flask(__name__, template_folder= "templates")

app.secret_key = 'your_secret_key'  # Secret key for session management

# Load dataset
dataset = pd.read_csv(r"C:\Users\Lenovo\OneDrive\Desktop\malicious_url_detector\balanced_urls.csv")

# Ensure that the dataset contains the 'url' and 'label' columns
dataset = dataset[['url', 'label', 'result']]  # Selecting only relevant columns

# Checking the dataset shape to ensure proper loading
print(dataset.head())  # Optional: Just to verify the dataset

# Step 2: Prepare Sample Dataset
# Now, create a DataFrame with the required 'url' and 'label' columns
df = dataset[['url', 'label', 'result']]

# Step 3: Vectorization of URLs
vectorizer = TfidfVectorizer(token_pattern=r'[A-Za-z0-9]+', max_features=3000)
X = vectorizer.fit_transform(df['url'])  # Feature matrix based on 'url' column
y = df['result']  # Labels (0 = safe, 1 = unsafe)

# Step 4: Train the model
model = LogisticRegression(max_iter=1000)  # Increase max_iter if convergence warning occurs
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model.fit(X_train, y_train)

# ================= Routes ==================
# Route for the Registration Page
@app.route('/')
def register_page():
    return render_template('register.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Dummy validation logic
        if password == confirm_password:
            print(f"New User Registered: Username: {username}, Password: {password}")
            return redirect(url_for('login_page'))  # Redirect to login page
        else:
            error_message = "Passwords do not match. Please try again."
            return render_template('register.html', error=error_message)

    return render_template('register.html')


# Route for the Login Page
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Dummy validation for login
        if username and password:  # Basic check (replace with real authentication logic)
            session['logged_in'] = True
            return redirect(url_for('malicious_detector'))
        else:
            error_message = "Invalid credentials. Please try again."
            return render_template('login.html', error=error_message)

    return render_template('login.html')

# Route for the Malicious URL Detector Page
@app.route('/malicious_detector')
def malicious_detector():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('malicious_detector.html')

# Route to Predict Malicious URLs
@app.route('/predict', methods=['POST'])
def predict():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))

    # Get the URL from the form input
    url_input = request.form['url']
    url_features = vectorizer.transform([url_input])  # Transform input URL to feature vector
    prediction = model.predict(url_features)  # Make prediction using the trained model
    result = "Malicious" if prediction[0] == 1 else "Benign"  # Map prediction to result

    return render_template('malicious_detector.html', prediction_text=f"The URL '{url_input}' is {result}.")

# Route to Logout
@app.route('/logout')
def logout():
    session.pop('logged_in', None)  # Clear session
    return redirect(url_for('login_page'))

# ================= Run the App ==================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Get port from environment or default to 5000
    app.run(debug=True, host="0.0.0.0", port=port)
