import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

df = pd.read_csv('PhishingDataset.csv')

X = df.drop('Result', axis=1)
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


def train_rf_classifier(X_train, y_train):
    # Instantiate the Random Forest Classifier with adjusted parameters
    rf = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42)

    # Fit the model on the training data
    rf.fit(X_train, y_train)

    return rf


# Train the RF Classifier
rf_classifier = train_rf_classifier(X_train, y_train)

# Evaluate the model on the test data
y_pred = rf_classifier.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
confusion = confusion_matrix(y_test, y_pred)

print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print("Classification Report:")
print(classification_report(y_test, y_pred))
print('Confusion Matrix:')
print(confusion)

with open("random_forest_classifier1.pkl", "wb") as f:
    joblib.dump(rf_classifier, f)

print("Model dumped successfully.")