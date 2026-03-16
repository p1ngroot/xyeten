#!/bin/bash
# Установка RPi4 Multitool - 5GHz WiFi Jammer
# Для Raspberry Pi 4 на Ubuntu Server

set -e

echo "=========================================="
echo "  RPi4 Multitool Installation"
echo "  5GHz WiFi Jammer + Web Interface"
echo "=========================================="
echo ""

# Проверка root
if [ "$EUID" -ne 0 ]; then 
    echo "[ERROR] Запустите скрипт с sudo!"
    echo "Usage: sudo bash install.sh"
    exit 1
fi

echo "[1/7] Обновление системы..."
apt-get update -qq

echo "[2/7] Установка зависимостей..."
apt-get install -y python3 python3-pip aircrack-ng wireless-tools iw

echo "[3/7] Установка Python пакетов..."
pip3 install -r requirements.txt

echo "[4/7] Создание директории приложения..."
mkdir -p /opt/rpi-multitool
cp rpi_multitool.py /opt/rpi-multitool/
cp -r templates /opt/rpi-multitool/
chmod +x /opt/rpi-multitool/rpi_multitool.py

echo "[5/7] Установка systemd сервиса..."
cp rpi-multitool.service /etc/systemd/system/
systemctl daemon-reload

echo "[6/7] Настройка автозапуска..."
read -p "Включить автозапуск при загрузке? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl enable rpi-multitool.service
    echo "✓ Автозапуск включен"
else
    echo "✓ Автозапуск отключен (запуск вручную)"
fi

echo "[7/7] Проверка WiFi адаптера..."
if iw dev | grep -q "Interface"; then
    IFACE=$(iw dev | grep Interface | awk '{print $2}' | head -n1)
    echo "✓ Найден WiFi адаптер: $IFACE"
    echo ""
    echo "ВАЖНО: Убедитесь что в rpi_multitool.py указан правильный интерфейс:"
    echo "  WIFI_INTERFACE = \"$IFACE\""
else
    echo "⚠ WiFi адаптер не найден!"
fi

echo ""
echo "=========================================="
echo "  Установка завершена!"
echo "=========================================="
echo ""
echo "Управление сервисом:"
echo "  sudo systemctl start rpi-multitool    # Запуск"
echo "  sudo systemctl stop rpi-multitool     # Остановка"
echo "  sudo systemctl status rpi-multitool   # Статус"
echo "  sudo journalctl -u rpi-multitool -f   # Логи"
echo ""
echo "Или запуск вручную:"
echo "  sudo python3 /opt/rpi-multitool/rpi_multitool.py"
echo ""
echo "Веб-интерфейс: http://$(hostname -I | awk '{print $1}'):80"
echo ""
echo "GPIO кнопки:"
echo "  GPIO17 (pin 11) - Навигация (переключение модулей)"
echo "  GPIO27 (pin 13) - Действие (старт/стоп)"
echo "  GPIO22 (pin 15) - LED статус"
echo ""
echo "⚠ ВНИМАНИЕ: Использование глушилок WiFi незаконно!"
echo "   Только для образовательных целей на своих сетях!"
echo ""
