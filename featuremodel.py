import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier

# Assume you have an already trained model
rfc = joblib.load('random_forest_classifier1.pkl')


# Get the feature names from the model
feature_names = rfc.feature_names_in_

# Print the feature names
print("Feature Names:")
print(feature_names)

# Create a Pandas DataFrame with the feature names
feature_names_df = pd.DataFrame({'Feature Names': feature_names})
print(feature_names_df)