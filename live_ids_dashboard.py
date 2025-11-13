#!/usr/bin/env python3
"""
Colored Real-Time IDS Dashboard

Reads alerts.log created by live_ids.py
Displays:
 - Attack counters
 - Flow stats
 - Latest alert info
 - Live updates every second
"""

import time, json, os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

ALERT_FILE = "ids_alerts.log"   # same file used by live_ids.py

console = Console()

def load_alerts(path):
    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        lines = f.readlines()[-50:]   # show only last 50 entries
        alerts = []
        for l in lines:
            try:
                alerts.append(json.loads(l.strip()))
            except:
                pass
    return alerts

def main():
    console.clear()
    console.print("[bold cyan]MQTT IDS - Live Dashboard[/bold cyan]")

    while True:
        alerts = load_alerts(ALERT_FILE)

        attack_counts = {
            "scan_A": 0,
            "scan_sU": 0,
            "sparta": 0,
            "mqtt_bruteforce": 0
        }
        
        last_entry = None

        for a in alerts:
            lbl = a.get("predicted_label", "unknown")
            if lbl in attack_counts:
                attack_counts[lbl] += 1
            last_entry = a
        
        table = Table(title="Attack Counters", style="bold magenta")
        table.add_column("Attack Type")
        table.add_column("Detected Count", justify="right")

        for k,v in attack_counts.items():
            table.add_row(k, str(v))

        console.clear()
        console.print(Panel.fit("[bold cyan]MQTT IDS – Real-Time Attack Dashboard[/bold cyan]"))
        console.print(table)

        if last_entry:
            console.print(
                Panel(
                    f"[bold red]LATEST ALERT[/bold red]\n\n"
                    f"[yellow]Attack:[/yellow] {last_entry.get('predicted_label')}\n"
                    f"[yellow]Probability:[/yellow] {last_entry.get('probability')}\n"
                    f"[yellow]Source:[/yellow] {last_entry['flow'].get('src')}\n"
                    f"[yellow]Destination:[/yellow] {last_entry['flow'].get('dst')}\n"
                    f"[yellow]PCAP:[/yellow] {last_entry.get('pcap')}",
                    title="⚠ ALERT DETECTED"
                )
            )
        else:
            console.print(Panel("[green]No attacks detected yet[/green]"))

        time.sleep(1)

if __name__ == "__main__":
    main()
