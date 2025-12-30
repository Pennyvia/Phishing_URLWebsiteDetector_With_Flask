import requests
from flask import Flask, request, render_template, jsonify
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
from flask_cors import CORS

from features_extraction import extract_features

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Load your Random Forest model
model = joblib.load('random_forest_classifier1.pkl')


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Check if the request is JSON (from the Chrome extension)
        if request.is_json:
            url = request.json['url']
        else:  # The request is form data (from the form)
            url = request.form['url']

        # Extract features from the URL
        feature = extract_features(url)

        # Make a prediction using the trained model
        prediction = model.predict(np.array([feature]))

        # Convert the prediction to a readable format
        readable_prediction = 'Legitimate' if prediction[0] == 1 else 'Phishing'

        # Return the result as a JSON response if the request is from the Chrome extension
        if request.is_json:
            return jsonify({'prediction': readable_prediction})
        else:  # Return the result as a rendered template if the request is from the form
            return render_template('result.html', prediction=readable_prediction)
    except requests.exceptions.SSLError as se:
        error_message = 'Please enter a valid URL: ' + str(se)
    except Exception:
        error_message = ('An error occurred. This means the site is suspicious. Do not enter sensitive information on '
                         'the site.')

    # Return the error message as a JSON response if the request is from the Chrome extension
    if request.is_json:
        return jsonify({'error': error_message})
    else:  # Return the error message as a rendered template if the request is from the form
        return render_template('result.html', error=error_message)


if __name__ == '__main__':
    app.run(debug=True)
