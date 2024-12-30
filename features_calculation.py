# feature_calculations.py

def calculate_duration(session_start_time, session_end_time):
    """
    Calculate the duration of the session in seconds.
    """
    return session_end_time - session_start_time


def calculate_protocol_type(packet_data):
    """
    Calculate the protocol type used in the session.
    This can be a set of protocols or a common one.
    """
    protocols = set(packet['protocol'] for packet in packet_data)
    return ','.join(protocols)  # In case multiple protocols are involved


def calculate_service(packet_data):
    """
    Calculate the services involved in the session.
    """
    services = set(packet['service'] for packet in packet_data)
    return ','.join(services)


def calculate_flag(packet_data):
    """
    Count unique flags in the session.
    """
    flags = set(packet['flag'] for packet in packet_data)
    return len(flags)  # Return the count of unique flags


def calculate_src_bytes(packet_data):
    """
    Calculate the total number of bytes sent from the source.
    """
    return sum(packet['length'] for packet in packet_data if packet['direction'] == 'from_src')


def calculate_dst_bytes(packet_data):
    """
    Calculate the total number of bytes sent to the destination.
    """
    return sum(packet['length'] for packet in packet_data if packet['direction'] == 'to_dst')


def calculate_logged_in(packet_data):
    """
    Calculate whether the user is logged in (binary feature).
    """
    login_flags = ['LOGIN_SUCCESS', 'USER_LOGGED_IN']  # Add actual flags or conditions here
    return 1 if any(packet['flag'] in login_flags for packet in packet_data) else 0


def calculate_count(packet_data):
    """
    Calculate the total number of packets in the session.
    """
    return len(packet_data)


def calculate_srv_count(packet_data):
    """
    Count distinct services used in the session.
    """
    services = set(packet['service'] for packet in packet_data)
    return len(services)


def calculate_serror_rate(packet_data):
    """
    Calculate the rate of service errors in the session.
    """
    total_packets = len(packet_data)
    service_errors = sum(1 for packet in packet_data if packet['flag'] == 'SERVICE_ERROR')
    return service_errors / total_packets if total_packets > 0 else 0


def calculate_srv_serror_rate(packet_data):
    """
    Calculate the rate of service-specific errors in the session.
    """
    total_packets = len(packet_data)
    srv_errors = sum(1 for packet in packet_data if packet['flag'] == 'SRV_SERVICE_ERROR')
    return srv_errors / total_packets if total_packets > 0 else 0


def calculate_rerror_rate(packet_data):
    """
    Calculate the rate of remote errors in the session.
    """
    total_packets = len(packet_data)
    remote_errors = sum(1 for packet in packet_data if packet['flag'] == 'REMOTE_ERROR')
    return remote_errors / total_packets if total_packets > 0 else 0


def calculate_same_srv_rate(packet_data):
    """
    Calculate the rate of packets belonging to the same service in the session.
    """
    total_packets = len(packet_data)
    same_service_count = sum(1 for packet in packet_data if packet['service'] == 'same_service')
    return same_service_count / total_packets if total_packets > 0 else 0


def calculate_dst_host_count(packet_data):
    """
    Calculate the number of unique destination hosts in the session.
    """
    dst_hosts = set(packet['dst_host'] for packet in packet_data)
    return len(dst_hosts)


def calculate_dst_host_srv_count(packet_data):
    """
    Calculate the number of destination hosts with the same service.
    """
    dst_host_services = {}
    for packet in packet_data:
        dst_host = packet['dst_host']
        service = packet['service']
        if dst_host not in dst_host_services:
            dst_host_services[dst_host] = set()
        dst_host_services[dst_host].add(service)
    
    # Return the number of distinct destination-host-service pairs
    return sum(len(services) for services in dst_host_services.values())


def calculate_selected_features(packet_data, session_start_time, session_end_time):
    """
    Calculate all the selected features for the session.
    """
    features = {
        'duration': calculate_duration(session_start_time, session_end_time),
        'protocol_type': calculate_protocol_type(packet_data),
        'service': calculate_service(packet_data),
        'flag': calculate_flag(packet_data),
        'src_bytes': calculate_src_bytes(packet_data),
        'dst_bytes': calculate_dst_bytes(packet_data),
        'logged_in': calculate_logged_in(packet_data),
        'count': calculate_count(packet_data),
        'srv_count': calculate_srv_count(packet_data),
        'serror_rate': calculate_serror_rate(packet_data),
        'srv_serror_rate': calculate_srv_serror_rate(packet_data),
        'rerror_rate': calculate_rerror_rate(packet_data),
        'same_srv_rate': calculate_same_srv_rate(packet_data),
        'dst_host_count': calculate_dst_host_count(packet_data),
        'dst_host_srv_count': calculate_dst_host_srv_count(packet_data),
    }

    return features


# Example usage:
if __name__ == "__main__":
    # Example packet data (simplified)
    packet_data = [
        {'length': 1200, 'direction': 'to_dst', 'timestamp': 1, 'protocol': 'TCP', 'flag': 'SYN', 'service': 'HTTP', 'dst_host': '192.168.1.1'},
        {'length': 800, 'direction': 'from_src', 'timestamp': 2, 'protocol': 'TCP', 'flag': 'ACK', 'service': 'HTTP', 'dst_host': '192.168.1.2'},
        {'length': 1600, 'direction': 'to_dst', 'timestamp': 3, 'protocol': 'UDP', 'flag': 'SYN', 'service': 'FTP', 'dst_host': '192.168.1.1'},
        # Add more packets as needed...
    ]

    # Example session start and end times
    session_start_time = 0
    session_end_time = 5

    # Calculate selected features
    features = calculate_selected_features(packet_data, session_start_time, session_end_time)

    # Print the features
    print(features)
