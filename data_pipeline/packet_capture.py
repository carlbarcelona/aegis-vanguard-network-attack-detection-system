import subprocess
import pandas as pd
import numpy as np
import os
from datetime import datetime
from app.config import *


def _get_timestamp():
    '''
    Helper function to provide unique tracking ids for each file
    '''
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

def preprocess_flows(converted_flows):
    '''
    Handles the preprocessing of the flows
    '''
    try:
        df_converted_flows = pd.read_csv(converted_flows, encoding='latin-1')
        df_converted_flows = df_converted_flows.copy()

        # Impute values in the dataset
        cols_to_clean = df_converted_flows.select_dtypes(include=[np.number]).columns
        df_converted_flows[cols_to_clean] = pd.DataFrame(np.nan_to_num(df_converted_flows[cols_to_clean], nan=0, posinf=0, neginf=0),
                        columns=df_converted_flows[cols_to_clean].columns,
                        index=df_converted_flows[cols_to_clean].index)
        
        # Detect inf and nan vals
        if np.any(np.isinf(df_converted_flows[cols_to_clean].values)) or np.any(np.isnan(df_converted_flows[cols_to_clean].values)):
            print("Warning: Data still contains inf or nan values")

        # Rename the columns as the original
        df_converted_flows.rename(columns=RENAME_MAP, inplace=True)
        # Fix the order of the columns like the original
        df_converted_flows = df_converted_flows[ORDER_MAP]

        # Convert time columns from seconds to microseconds
        time_columns = ['Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 
                        'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 
                        'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
                        'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min']
        df_converted_flows[time_columns] = df_converted_flows[time_columns] * 1000000

        return df_converted_flows
    
    except pd.errors.EmptyDataError:
        return pd.DataFrame()

def convert_packets(pcap_path, output_name: str = None):
    '''
    Converts the pcap file into a preprocessed csv
    '''
    if not isinstance(output_name, str) and output_name is not None:
        raise ValueError("outname not string") 

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Output file construction
    if output_name is None:
        file_id = _get_timestamp()
        output_name = f"flow_{file_id}"
    output_path = os.path.join(OUTPUT_DIR, f"{output_name}.csv")

    # Terminal commands for cicflowmeter from documenatation: https://pypi.org/project/cicflowmeter/
    subprocess.run([
        "cicflowmeter",
        "-f", str(pcap_path),
        "-c", output_path
    ], check=True)

    # Preprocess
    preprocessed_df = preprocess_flows(output_path)
    preprocessed_df.to_csv(output_path, index=False)

    return output_path, preprocessed_df

def capture(capture_seconds: int, interface="wlan0"):  # wlan0 = WiFi, eth0 = Ethernet. Check your system first
    '''
    Captured the live traffic, then outputs a PCAP file
    '''
    # Create the directory if it doesn't exist
    if not os.path.exists(PCAP_DIR):
        os.makedirs(PCAP_DIR, exist_ok=True)

    # Output file construction
    file_id = _get_timestamp()
    filename = f"traffic_{file_id}.pcap"
    output_file = os.path.join(PCAP_DIR, filename)

    subprocess.run([
        "tcpdump",
        "-i", interface,
        "-G", str(capture_seconds),      
        "-W", "1",          
        "-w", output_file
    ], check=True)

    return output_file


# Local Testing
if __name__ == '__main__':
    pcap_file = capture(capture_seconds=10, interface="eth0")
    if not os.path.exists(pcap_file):
        print("PCAP not found:", pcap_file)
    else:
        print("PCAP created:", pcap_file)

    csv_path, df = convert_packets(pcap_file)
    if not os.path.exists(csv_path):
        print("CSV not found:", csv_path)
    else:
        print("CSV created:", csv_path)