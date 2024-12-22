from scapy.all import sniff
from dash import Dash, dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from collections import deque
import threading

# Initialize Dash app
app = Dash(__name__)

# Data storage for live updates
packet_data = deque(maxlen=100)  # Store up to 100 packets

# Define the dashboard layout
app.layout = html.Div([
    html.Div(
        html.H1("Network Traffic Dashboard"),
        style={
            'textAlign': 'center',
            'padding': '10px',
            'backgroundColor': '#4CAF50',
            'color': 'white',
            'fontFamily': 'Arial, sans-serif'
        }
    ),
    html.Div(
        dcc.Graph(id='live-traffic-graph'),
        style={
            'padding': '20px'
        }
    ),
    dcc.Interval(
        id='interval-component',
        interval=1000,  # Update every second
        n_intervals=0
    ),
    html.Div(
        "Real-time visualization of network traffic. Data updates every second.",
        style={
            'textAlign': 'center',
            'marginTop': '10px',
            'fontStyle': 'italic',
            'fontSize': '14px',
            'color': '#555'
        }
    )
], style={
    'fontFamily': 'Arial, sans-serif',
    'backgroundColor': '#f9f9f9',
    'margin': '0',
    'padding': '0'
})

# Callback to update the graph
def update_graph_live(n):
    global packet_data
    
    if len(packet_data) == 0:
        return {
            'data': [],
            'layout': go.Layout(title='No packets captured yet')
        }

    x_values = list(range(len(packet_data)))
    packet_lengths = [pkt['length'] for pkt in packet_data]

    figure = {
        'data': [go.Scatter(x=x_values, y=packet_lengths, mode='lines+markers', line=dict(color='#4CAF50'))],
        'layout': go.Layout(
            title="Live Network Packet Lengths",
            xaxis=dict(title="Packet Index", gridcolor='#eee'),
            yaxis=dict(title="Packet Length (bytes)", gridcolor='#eee'),
            plot_bgcolor='#ffffff',
            paper_bgcolor='#f9f9f9'
        )
    }

    return figure

# Add the callback to the app
app.callback(
    Output('live-traffic-graph', 'figure'),
    Input('interval-component', 'n_intervals')
)(update_graph_live)

# Packet sniffing function
def packet_callback(packet):
    global packet_data
    try:
        packet_info = {
            'length': len(packet),
            'src': packet[0][1].src if packet.haslayer('IP') else "N/A",
            'dst': packet[0][1].dst if packet.haslayer('IP') else "N/A"
        }
        packet_data.append(packet_info)
    except Exception as e:
        print(f"Error processing packet: {e}")

# Run sniffing in a separate thread
def start_sniffing():
    sniff(prn=packet_callback, store=False)

if __name__ == '__main__':
    # Start sniffing thread
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()

    # Run the dashboard
    app.run_server(debug=True)
