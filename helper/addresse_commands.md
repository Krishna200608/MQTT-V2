router ip

192.168.0.100

mosquitto 
mosquitto -c C:\mosquitto_data\mosquitto.conf -v

Run this on the broker laptop (Windows PowerShell or CMD):
tshark -i Wi-Fi -w data\pcap_files\capture.pcap -b duration:5

python live_ids.py `
  --pcap-dir "D:\Research\Code\MQTT V2\pcap_files" `
  --model "D:\Research\Code\MQTT V2\model_outputs\biflow\random_forest\random_forest\model_rf.joblib" `
  --meta "D:\Research\Code\MQTT V2\model_outputs\biflow\random_forest\train_metadata.json" `
  --out-log "D:\Research\Code\MQTT V2\ids_alerts.log" `
  --csv-out "D:\Research\Code\MQTT V2\ids_summary.csv" `
  --broker-only `
  --broker-ip 192.168.0.102 `
  --broker-port 1883 `
  --prob-threshold 0.75




