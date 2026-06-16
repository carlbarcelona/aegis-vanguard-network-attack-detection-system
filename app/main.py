import pandas as pd
import numpy as np
import joblib
import subprocess
import os
import shutil
from pathlib import Path

from app.config import *
from data_pipeline.packet_capture import *

from dotenv import load_dotenv
load_dotenv()

def binary_layer(X, binary_model):
    '''
    Classifies the behaviour of traffic if
    BENIGN - Normal
    ATTCK - Threat detected
    '''

    X = X.copy()
    pred = binary_model.predict(X)
    pred_proba = binary_model.predict_proba(X)
    pred = pred.tolist()
    print(pred_proba)

    if pred[0] == 1:
        return "ATTACK"
    if pred[0] == 0:
        return "BENIGN"

def attack_layer(X, attack_model):
    '''
    Classifies the type of attack detected according to the encoded map from training
    '''

    attack_map = {
        0: 'Bot',
        1: 'DDoS',
        2: 'DoS GoldenEye',
        3: 'DoS Hulk',
        4: 'DoS Slowhttptest',
        5: 'DoS slowloris',
        6: 'FTP-Patator',
        7: 'Heartbleed',
        8: 'Infiltration',
        9: 'PortScan',
        10: 'SSH-Patator',
        11: 'Web Attack'
    }

    X = X.copy()

    pred = attack_model.predict(X)
    return attack_map[pred]

def predict(df, binary_model, attack_model):
    ''' 
    Predict the incoming flows 
    '''

    feature_cols = df.drop(columns=METADATA_COLS)

    for index, row in feature_cols.iterrows():
        meta = df.loc[index]
        # Feed the model row by row
        row_df = pd.DataFrame([row], columns=feature_cols.columns)
        network_status = binary_layer(row_df, binary_model)
        
        if network_status == "BENIGN":
            print(f"Status: BENIGN | {meta['src_ip']} -> {meta['dst_ip']}: {meta['timestamp']}")
            continue
        if network_status == "ATTACK":  
            attack_type = attack_layer(row_df, attack_model)
            print(f"!!! ALERT !!!")
            print(f"File: ")
            print(f"Type: {attack_type}")
            print(f"Source: {meta['src_ip']}:{meta['src_port']}")
            print(f"Target: {meta['dst_ip']}:{meta['dst_port']}")
            print(f"Protocol: {meta['protocol']}")
            print(f"Time: {meta['timestamp']}")
            print(f"----------------------------------------------")
            continue

def main(binary_model, attack_model): 
    '''
    Scan incoming folder, process new flow CSVs, then move to scanned folder
    '''

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(SCANNED_DIR, exist_ok=True)
    # Sort directories 
    files = sorted(os.listdir(OUTPUT_DIR))  

    for file in files:
        if not file.startswith("flow") or not file.endswith(".csv"):
            continue
        # Stage the file
        file_path = os.path.join(OUTPUT_DIR, file)

        # Load CSV, then feed to model
        try:
            print(f"Processing: {file}")
            df = pd.read_csv(file_path)

            if df.empty:
                print(f'{file_path} skipped and deleted: Empty df')
                os.remove(file_path)
            else:
                print()
                print(f"---------START---------")
                print(f"File:{file_path}")
                predict(df, binary_model, attack_model) 
                print(f"File:{file_path}")
                print(f"---------!END!---------")
                print()

            # After the file is scanned, it will be moved to converted_flows/scanned
            destination = os.path.join(SCANNED_DIR, file)
            shutil.move(file_path, destination)
            
        except pd.errors.EmptyDataError:
            # Clear the entire incoming directory upon every iteration to delete empty csvs
            print(f"Parsing error on {file}. Deleting file.")
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"Error processing {file}: {e}")
    
def run(models: list, capture_seconds: int = 10, interface="eth0", cycle: str = None):
    count = 0
    try: 
        while cycle is None or count < cycle:
                print(f"Started on {interface}. Iteration {count}")
                count += 1
                pcap_file = capture(capture_seconds=capture_seconds, interface=interface)
                if not os.path.exists(pcap_file):
                    print("PCAP not found:", pcap_file)
                print("PCAP created:", pcap_file)

                csv_path, df = convert_packets(pcap_file)
                if not os.path.exists(csv_path):
                    print("CSV not found:", csv_path)
                print("CSV created:", csv_path)
                
                # Feed to the model
                main(models["binary_model"], models["attack_model"])

    except KeyboardInterrupt:
        print("Interrupted")
            
if __name__ == '__main__':

    models = {
        "binary_model": joblib.load(BINARY_MODEL),
        "attack_model": joblib.load(CLASSIFIER_MODEL),
    }

    run(models=models, capture_seconds=240, interface="eth0", cycle= None)


    

    


