router ip

192.168.0.100

mosquitto 
mosquitto -c C:\mosquitto_data\mosquitto.conf -v

Run this on the broker laptop (Windows PowerShell or CMD):
tshark -i Wi-Fi -w data\pcap_files\capture.pcap -b duration:5

python live_ids.py ^
    --pcap-dir ".\data\pcap_files" ^
    --model ".\model_outputs\biflow\random_forest\random_forest\model_rf.joblib" ^
    --meta ".\model_outputs\biflow\random_forest\train_metadata.json" ^
    --out-log ".\ids_alerts.log"

