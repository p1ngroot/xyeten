# RPi4 Multitool - 5GHz WiFi Jammer

Порт ESP32 Multitool на Raspberry Pi 4 с Ubuntu Server.

## 🚀 Возможности

- **WiFi Scanner** - сканирование 5GHz сетей
- **WiFi Sniffer** - перехват пакетов на 5GHz
- **WiFi Deauth** - деаутентификация клиентов
- **Beacon Flood** - флуд фейковыми точками доступа
- **5GHz Jammer** - глушилка WiFi на 5GHz диапазоне
- **Web Interface** - управление через браузер
- **GPIO Control** - физические кнопки для управления

## ⚠️ ВНИМАНИЕ

**Использование глушилок WiFi незаконно в большинстве стран!**
Этот проект предназначен **только для образовательных целей** на собственных сетях в контролируемой среде.

## 📋 Требования

### Железо
- Raspberry Pi 4 (рекомендуется 2GB+ RAM)
- WiFi адаптер с поддержкой 5GHz и monitor mode
- Кнопки (опционально): 2x тактовые кнопки + резисторы
- LED (опционально): 1x LED + резистор

### Софт
- Ubuntu Server 22.04+ (или Raspberry Pi OS)
- Python 3.8+
- Root доступ

## 🔧 Установка

### Быстрая установка

```bash
cd /home/nroot/Изображения
sudo bash install.sh
```

### Ручная установка

```bash
# 1. Установка зависимостей
sudo apt-get update
sudo apt-get install -y python3 python3-pip aircrack-ng wireless-tools iw

# 2. Установка Python пакетов
sudo pip3 install -r requirements.txt

# 3. Копирование файлов
sudo mkdir -p /opt/rpi-multitool
sudo cp rpi_multitool.py /opt/rpi-multitool/
sudo cp -r templates /opt/rpi-multitool/
sudo chmod +x /opt/rpi-multitool/rpi_multitool.py

# 4. Установка сервиса (опционально)
sudo cp rpi-multitool.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable rpi-multitool.service
```

## 🎮 Использование

### Запуск вручную

```bash
sudo python3 /opt/rpi-multitool/rpi_multitool.py
```

### Управление сервисом

```bash
sudo systemctl start rpi-multitool    # Запуск
sudo systemctl stop rpi-multitool     # Остановка
sudo systemctl restart rpi-multitool  # Перезапуск
sudo systemctl status rpi-multitool   # Статус
sudo journalctl -u rpi-multitool -f   # Логи в реальном времени
```

### Веб-интерфейс

Откройте в браузере: `http://<IP_адрес_RPi>:80`

Например: `http://192.168.1.100:80`

## 🔌 GPIO Подключение

### Схема подключения кнопок

```
GPIO17 (pin 11) ----[Button]---- GND
GPIO27 (pin 13) ----[Button]---- GND
GPIO22 (pin 15) ----[LED]----[220Ω]---- GND
```

### Функции кнопок

- **GPIO17 (NAV)** - Переключение между модулями
- **GPIO27 (ACT)** - Запуск/остановка текущего модуля
- **GPIO22 (LED)** - Индикатор состояния

## 📡 Настройка WiFi адаптера

### Проверка поддержки monitor mode

```bash
sudo iw list | grep "Supported interface modes" -A 8
```

Должен быть режим `monitor`.

### Проверка поддержки 5GHz

```bash
sudo iw list | grep "Band 2"
```

### Ручное включение monitor mode

```bash
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```

## 🛠️ Конфигурация

Отредактируйте `/opt/rpi-multitool/rpi_multitool.py`:

```python
# GPIO пины
BTN_NAV_PIN = 17  # Кнопка навигации
BTN_ACT_PIN = 27  # Кнопка действия
LED_PIN = 22      # LED индикатор

# WiFi интерфейс
WIFI_INTERFACE = "wlan0"  # Измените на ваш интерфейс
```

## 📖 Модули

### 1. WiFi Scanner
Сканирует доступные 5GHz сети и отображает:
- SSID
- BSSID (MAC адрес)
- Канал
- Уровень сигнала (RSSI)
- Тип шифрования

### 2. WiFi Sniffer
Перехватывает WiFi пакеты на выбранном канале:
- Management frames (beacon, probe, deauth)
- Data frames
- Control frames

### 3. WiFi Deauth
Отправляет deauth фреймы для отключения клиентов от выбранной сети.

### 4. Beacon Flood
Создаёт множество фейковых точек доступа с разными SSID.

### 5. 5GHz Jammer
**Глушилка WiFi** - отправляет шумовые пакеты на выбранном канале для создания помех.

## 🐛 Решение проблем

### WiFi адаптер не найден

```bash
# Проверка наличия адаптера
iw dev

# Проверка драйверов
lsmod | grep 80211
```

### Monitor mode не включается

```bash
# Остановка NetworkManager
sudo systemctl stop NetworkManager

# Убить мешающие процессы
sudo airmon-ng check kill

# Попробовать снова
sudo iw wlan0 set monitor none
```

### Ошибка "Operation not permitted"

Убедитесь что запускаете с `sudo`.

### Порт 80 занят

Измените порт в `rpi_multitool.py`:

```python
socketio.run(app, host='0.0.0.0', port=8080, ...)
```

## 📝 Логи

```bash
# Системные логи
sudo journalctl -u rpi-multitool -f

# Логи приложения
sudo tail -f /var/log/syslog | grep rpi-multitool
```

## 🔒 Безопасность

- Приложение требует root доступ для работы с WiFi
- Веб-интерфейс не имеет аутентификации - используйте в изолированной сети
- Не запускайте на публичных серверах

## 📄 Лицензия

Educational purposes only. Используйте ответственно и законно.

## 🤝 Благодарности

Основано на ESP32 Multitool v2.0 WEB UI Edition.
