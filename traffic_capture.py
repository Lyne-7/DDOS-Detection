from scapy.all import sniff, TCP
import pickle
import pandas as pd
from sklearn.preprocessing import StandardScaler
from collections import deque

# Store up to 100 packets
packet_data = deque(maxlen=100)
alerts = []  # Store any alerts triggered, to pass to the dashboard

# Load the models and scalers
scaler = pickle.load(open(r"C:\Users\LENOVO\DDOS DETECTION\Ddos Attack Detection and Net Traffic Analsysis and Dashboard\NSL-KDD\attack_rbscaler.pkl", 'rb'))
encoder = pickle.load(open(r"C:\Users\LENOVO\DDOS DETECTION\Ddos Attack Detection and Net Traffic Analsysis and Dashboard\NSL-KDD\attack_encoder.pkl", 'rb'))
model = pickle.load(open(r"C:\Users\LENOVO\DDOS DETECTION\Ddos Attack Detection and Net Traffic Analsysis and Dashboard\NSL-KDD\attack_model.pkl", 'rb'))

# Define the selected features
selected_features = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 
    'dst_bytes', 'logged_in', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'same_srv_rate', 'dst_host_count', 
    'dst_host_srv_count'
]

# Function to extract features from a packet
def extract_packet_features(packet):
    # Initialize packet info with default or derived values
    packet_info = {
        'duration': packet.time,  # Duration can be the packet timestamp
        'protocol_type': packet.proto,  # Protocol type (e.g., TCP, UDP)
        'service': 'http' if packet.haslayer(TCP) and packet.dport == 80 else 'unknown',  # Add logic for services
        'flag': 'SF' if packet.haslayer(TCP) and packet[TCP].flags == 0x02 else 'unknown',  # SF flag check
        'src_bytes': len(packet),  # Length of the packet as the bytes sent
        'dst_bytes': len(packet),  # Length of the packet as the bytes received
        'logged_in': 0,  # Placeholder: Add logic to check if the user is logged in
        'count': 1,  # Placeholder: Calculate number of packets in this connection
        'srv_count': 1,  # Placeholder: Count packets for the service
        'serror_rate': 0,  # Placeholder: Error rate for the connection
        'srv_serror_rate': 0,  # Placeholder: Error rate for the service
        'rerror_rate': 0,  # Placeholder: Remote error rate
        'same_srv_rate': 0,  # Placeholder: Same service rate
        'dst_host_count': 1,  # Placeholder: Count of destinations
        'dst_host_srv_count': 1,  # Placeholder: Service count on destination host
    }
    return packet_info

# Preprocess the packet data to match training format
def preprocess_data(packet_info):
    # Convert packet info to DataFrame
    df = pd.DataFrame([packet_info])  # This ensures df is a 2D structure.
    print(f"Raw Data: {df}")
    
    # Select the required features and apply transformations
    processed_data = df[selected_features]
    
    # Handle categorical features with encoder
    processed_data['protocol_type'] = encoder.transform(processed_data['protocol_type'])
    processed_data['service'] = encoder.transform(processed_data['service'])
    processed_data['flag'] = encoder.transform(processed_data['flag'])
    
    # Apply scaling
    processed_data_scaled = scaler.transform(processed_data)  # This now works correctly, as it's a DataFrame.
    
    return processed_data_scaled

# Predict using the trained model
def predict_ddos(processed_data):
    predictions = model.predict(processed_data)
    return predictions[0]

# Handle packet data and integrate preprocessing and prediction
def packet_callback(packet):
    global packet_data, alerts
    try:
        packet_info = extract_packet_features(packet)

        # Preprocess the data and make a prediction
        processed_data = preprocess_data(packet_info)
        prediction = predict_ddos(processed_data)

        # Update packet data for visualization in the dashboard
        packet_data.append(packet_info)

        if prediction == 1:  # DDoS detected
            alert_message = f"DDoS Attack Detected! Source IP: {packet_info['src']} - Duration: {packet_info['duration']}"
            print(alert_message)
            alerts.append(alert_message)  # Store the alert for use by the dashboard

        else:
            pass

    except Exception as e:
        print(f"Error processing packet: {e}")

# Start sniffing network traffic
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=False)  # Capture packets on all interfaces

if __name__ == "__main__":
    start_sniffing()
