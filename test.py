from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
from features_extraction import extract_features

# Prompt the user for a URL
url = input('Enter the URL to classify: ')

# Extract features from the URL
features = extract_features(url)

# Load the trained model
model = joblib.load('random_forest_classifier1.pkl')

# Make a prediction using the trained model


prediction = model.predict([features])

# Print the prediction
if prediction[0] == 1:
    print('Legitimate')
else:
    print('Phishing')

