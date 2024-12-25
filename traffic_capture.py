from scapy.all import sniff
import json
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler
from collections import deque

packet_data = deque(maxlen=100)  # Store up to 100 packets
alerts = []  # Store any alerts triggered, to pass to dashboard

# Load the models and scalers
scaler = pickle.load(open('attack_rbscaler.pkl', 'rb'))
encoder = pickle.load(open('attack_encoder.pkl', 'rb'))
model = pickle.load(open('attack_model.pkl', 'rb'))

# Preprocess the packet data
def preprocess_data(packet_info):
    # Convert packet info to DataFrame
    df = pd.DataFrame([packet_info])
    print(f"Raw Data: {df}")
    processed_data = df[['len']]
    processed_data_scaled = scaler.transform(processed_data)  # Apply scaling

    return processed_data_scaled

# Predict using the trained model
def predict_ddos(processed_data):
    predictions = model.predict(processed_data)
    return predictions[0]
# Handle packet data and integrate preprocessing and prediction
def packet_callback(packet):
    global packet_data, alerts
    try:
        packet_info = {
            "length": len(packet),
            "src": packet[0][1].src if packet.haslayer('IP') else "N/A",
            "dst": packet[0][1].dst if packet.haslayer('IP') else "N/A",
            "proto": packet[0][1].proto
        }

        # Preprocess the data and make a prediction
        processed_data = preprocess_data(packet_info)
        prediction = predict_ddos(processed_data)

        # Update packet data for visualization in the dashboard
        packet_data.append(packet_info)

        if prediction == 1:  # DDoS detected
            alert_message = f"DDoS Attack Detected! Source IP: {packet_info['src']}"
            print(alert_message)
            alerts.append(alert_message)  # Store the alert for use by the dashboard

        else:
            pass

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing network traffic
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=False)  # Capture packets

if __name__ == "__main__":
    start_sniffing()