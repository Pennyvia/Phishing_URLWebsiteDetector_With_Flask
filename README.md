# Phishing URL Website Detector (Flask + Chrome Extension)

This project detects phishing websites using a machine learning model. It analyzes
features extracted from URLs and web content to classify sites as legitimate or
malicious, helping users avoid phishing attacks in real time. The backend is a
Flask application that exposes the classifier, and the user-facing workflow is
provided through a Chrome extension for quick URL checks and warnings.

## What the project does
- Extracts lexical and content-based features from URLs and web pages.
- Uses a trained Random Forest classifier to predict phishing vs. legitimate.
- Provides a simple web/extension interface for submitting URLs and receiving
  safety verdicts.

## My specific contribution
- Designed and trained the Random Forest classification model.
- Implemented data preprocessing and feature extraction for URLs and web content.
- Evaluated model performance and tuned the feature set.
- Built the Chrome extension UI to let users paste URLs or receive automatic
  warnings while browsing.

## Deployment status
- Deployed as a functional Chrome extension for demonstration and testing.
- Not publicly released on the Chrome Web Store.
- Fully runnable from this repository by loading the extension locally.

## Repository layout
- `app.py`: Flask application and prediction endpoint.
- `features_extraction.py`: Feature extraction utilities.
- `featuremodel.py` / `train.py`: Model training scripts.
- `random_forest_classifier1.pkl`: Trained Random Forest model.
- `Extension/`: Chrome extension sources.

## Quick start
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Run the Flask server:
   ```bash
   python app.py
   ```
3. Load the extension:
   - Open Chrome → Extensions → Enable Developer Mode.
   - Click **Load unpacked** and select the `Extension/` folder.

## Notes
- The model and feature extraction pipeline can be retrained using `train.py`.
- For Docker-based execution, see `README.Docker.md`.
