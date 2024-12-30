from dash import Dash, dcc, html
from dash.dependencies import Input, Output
import plotly.graph_objs as go
from collections import deque
import threading
from scapy.all import sniff

# Global variables for storing packet data and alerts
packet_data = deque(maxlen=100)  # Store up to 100 packets
alerts = []  # Store DDoS alerts

def create_dash_app(flask_app):
    """
    Create and configure a Dash app as a sub-application of the provided Flask app.

    Args:
        flask_app: The Flask app to attach the Dash app to.

    Returns:
        dash_app: Configured Dash app instance.
    """
    dash_app = Dash(__name__, server=flask_app, url_base_pathname='/analysis/')

    # Define the Dash app layout
    dash_app.layout = html.Div([
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
        html.Div([
            html.H3("Alerts"),
            html.Div(id="alerts-container", style={"padding": "10px", "backgroundColor": "#f8d7da", "color": "#721c24"})
        ], style={"padding": "10px", "backgroundColor": "#f8d7da", "marginTop": "20px"}),
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
    ])

    # Callback to update the graph
    @dash_app.callback(
        Output('live-traffic-graph', 'figure'),
        Input('interval-component', 'n_intervals')
    )
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

    # Callback to update alerts
    @dash_app.callback(
        Output('alerts-container', 'children'),
        Input('interval-component', 'n_intervals')
    )
    def update_alerts(n):
        global alerts

        if len(alerts) == 0:
            return "No alerts yet."

        latest_alert = alerts[-1]  # Get the latest alert
        return html.Div(latest_alert, style={"color": "red"})  # Display the alert in red

    return dash_app


# Packet sniffing function
def packet_callback(packet):
    global packet_data, alerts
    try:
        packet_info = {
            'length': len(packet),
            'src': packet[0][1].src if packet.haslayer('IP') else "N/A",
            'dst': packet[0][1].dst if packet.haslayer('IP') else "N/A"
        }
        packet_data.append(packet_info)

        # Example alert generation (this should be based on your DDoS detection logic)
        if len(packet_data) < 50:  # Example condition for an alert
            alerts.append(f"Potential DDoS alert: {len(packet_data)} packets captured.")
    except Exception as e:
        print(f"Error processing packet: {e}")

# Run sniffing in a separate thread
def start_sniffing():
    sniff(prn=packet_callback, store=False)

# Start sniffing thread
sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()
