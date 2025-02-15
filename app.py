from flask import Flask, request, render_template
import pickle
import numpy as np
import pandas as pd
from urllib.parse import urlparse


model_path = 'malicious_url_detection_model.pkl'
with open(model_path, 'rb') as file:
    model = pickle.load(file)

app = Flask(__name__)


def extract_features(url):
    features = {}
    features['url_length'] = len(url)  
    features['num_dots'] = url.count('.')  
    features['num_slashes'] = url.count('/')  
    features['has_https'] = 1 if url.startswith('https') else 0  

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    features['domain_length'] = len(domain)  
    features['num_subdomains'] = domain.count('.') - 1  

    suspicious_keywords = ['login', 'secure', 'bank', 'pay', 'account', 'signin', 'update']
    features['has_suspicious_keyword'] = int(any(keyword in url for keyword in suspicious_keywords))  

    return pd.DataFrame([features])  

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['URL']  

    
    print("Received URL:", url)

    
    features = extract_features(url)  

    
    prediction = model.predict(features)
    output = 'Malicious' if prediction[0] == 1 else 'Safe'

    return render_template('index.html', prediction_text=f'Prediction: {output}')

if __name__ == "__main__":
    app.run(debug=True)
