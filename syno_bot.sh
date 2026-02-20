#!/bin/bash


CONFIG_FILE="/etc/synobot.conf"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "------------------------------------------"
    echo "🤖 ПЕРВОНАЧАЛЬНАЯ НАСТРОЙКА БОТА"
    echo "------------------------------------------"
    read -p "🔹 Введите TOKEN вашего бота: " USER_TOKEN
    read -p "🔹 Введите ваш Telegram ADMIN_ID: " USER_ID
    
    echo "TOKEN=\"$USER_TOKEN\"" > "$CONFIG_FILE"
    echo "ADMIN_ID=\"$USER_ID\"" >> "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    echo "✅ Настройки сохранены в $CONFIG_FILE"
    echo "------------------------------------------"
fi


source "$CONFIG_FILE"


URL="https://api.telegram.org/bot$TOKEN"
OFFSET=0

if ! command -v jq &> /dev/null; then
    wget -q -O /bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && chmod +x /bin/jq
fi

send_msg() {
    curl -s -X POST "$URL/sendMessage" \
        -d chat_id="$ADMIN_ID" \
        -d parse_mode="HTML" \
        -d disable_web_page_preview="true" \
        --data-urlencode "text=$1" \
        --data-urlencode "reply_markup=$2" > /dev/null
}

send_action() {
    curl -s -X POST "$URL/sendChatAction" -d chat_id="$ADMIN_ID" -d action="typing" > /dev/null
}


KB_MAIN='{
    "keyboard": [
        [{"text": "💻 Система"}, {"text": "⚙️ Apps"}]
    ],
    "resize_keyboard": true
}'

KB_SYSTEM='{
    "keyboard": [
        [{"text": "📊 Статус"}, {"text": "🌐 Сеть"}],
        [{"text": "🏥 S.M.A.R.T."}, {"text": "🔥 Firewall Off"}],
        [{"text": "🔌 SSH Toggle"}, {"text": "🔄 Перезагрузка"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'

KB_AUTO='{
    "keyboard": [
        [{"text": "🐳 Докер"}, {"text": "📦 Apps"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'


watch_sys_logs() {
    tail -n 0 -qF /var/log/messages /var/log/synolog/synosys.log /var/log/synolog/synobackup.log 2>/dev/null | grep --line-buffered -iE "bad sector|I/O error|crashed|degrade|temperature|download.*finish|download.*complet|success.*download|task.*finish|backup.*finish|backup.*success|backup.*fail" | while read -r line; do
        if ! echo "$line" | grep -qiE "nginx|systemd|winbindd|smbd"; then
            CLEAN_LINE=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[ \t]*//')
            send_msg "🔔 <b>Событие DSM:</b> <code>$CLEAN_LINE</code>" ""
        fi
    done
}

watch_pkg_logs() {
    tail -n 0 -qF /var/log/synopkg.log 2>/dev/null | grep --line-buffered -iE "start |stop |restart |crashed|error|fail" | while read -r line; do
        CLEAN_LINE=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^[ \t]*//')
        send_msg "📦 <b>Пакет Synology:</b> <code>$CLEAN_LINE</code>" ""
    done
}

watch_docker_logs() {
    docker events --filter 'event=die' --filter 'event=start' --format '{{.Actor.Attributes.name}}|{{.Status}}' 2>/dev/null | while IFS='|' read -r name status; do
        if [ "$status" == "start" ]; then
            send_msg "🟢 <b>Docker:</b> Контейнер <b>$name</b> запущен." ""
        elif [ "$status" == "die" ]; then
            send_msg "🔴 <b>Docker:</b> Контейнер <b>$name</b> остановлен (или упал)!" ""
        fi
    done
}

watch_ssh_logs() {
    tail -n 0 -qF /var/log/auth.log 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "sshd.*session opened for user"; then
            USER=$(echo "$line" | sed -n 's/.*user \([^ ]*\).*/\1/p')
            send_msg "🟢 <b>Вход по SSH</b> 👤 Пользователь: <b>$USER</b>" ""
        elif echo "$line" | grep -q "sshd.*session closed for user"; then
            USER=$(echo "$line" | sed -n 's/.*user \([^ ]*\).*/\1/p')
            send_msg "⚪️ <b>Выход из SSH</b> 👤 Пользователь: <b>$USER</b>" ""
        fi
    done
}

watch_web_logs() {
    DB_FILE="/var/log/synolog/.SYNOCONNDB"
    
    LAST_ID=$(sqlite3 "$DB_FILE" "SELECT MAX(id) FROM logs;" 2>/dev/null)
    [ -z "$LAST_ID" ] && LAST_ID=0

    while true; do
        sleep 5
        
        NEW_LOGS=$(sqlite3 "$DB_FILE" "SELECT id, user, ip, msg FROM logs WHERE id > $LAST_ID ORDER BY id ASC;" 2>/dev/null)
        
        if [ -n "$NEW_LOGS" ]; then
            while IFS='|' read -r log_id log_user log_ip log_msg; do
                
                
                if echo "$log_msg" | grep -qi "signed in to \[DSM\] successfully"; then
                    send_msg "🟢 <b>Вход в DSM (Web)</b>👤 Пользователь: <b>$log_user</b>🌐 IP: <code>$log_ip</code>" ""
                
                
                elif echo "$log_msg" | grep -qiE "fail.*sign in|fail.*log in"; then
                    send_msg "🔴 <b>Ошибка входа</b>👤 Пользователь: <b>$log_user</b>🌐 IP: <code>$log_ip</code>" ""
                fi
                
                LAST_ID=$log_id
            done <<< "$NEW_LOGS"
        fi
    done
}


pkill -f "tail -qF"
pkill -f "tail -n 0 -qF"
pkill -f "docker events --filter"
pkill -f "watch_web_logs"


watch_sys_logs &
watch_pkg_logs &
watch_docker_logs &
watch_ssh_logs &
watch_web_logs &


echo "🚀 Бот запущен..."
send_msg "✅ <b>Бот запущен!</b>Привет Босс." "$KB_MAIN"

while true; do
    UPDATES=$(curl -s "$URL/getUpdates?offset=$OFFSET&timeout=30")
    
    if [ -z "$UPDATES" ] || [ "$(echo "$UPDATES" | jq '.ok')" != "true" ]; then
        sleep 5; continue
    fi

    echo "$UPDATES" | jq -c '.result[]' | while read -r UPDATE; do
        MSG_ID=$(echo "$UPDATE" | jq -r '.update_id')
        CHAT_ID=$(echo "$UPDATE" | jq -r '.message.chat.id')
        TEXT=$(echo "$UPDATE" | jq -r '.message.text')

        [ "$CHAT_ID" != "$ADMIN_ID" ] && continue

        case "$TEXT" in
            "/start" | "/menu" | "🔙 Назад в меню")
                send_msg "<b>🎛 Главное меню</b>" "$KB_MAIN"
                ;;
                
            "💻 Система")
                send_msg "<b>💻 Управление NAS:</b>" "$KB_SYSTEM"
                ;;
                
            "⚙️ Apps" | "⚙️ Apss")
                send_msg "<b>⚙️ Контейнеры и пакеты:</b>" "$KB_AUTO"
                ;;

            # 
            "/status" | "📊 Статус")
                send_action
                UPTIME=$(uptime -p | sed 's/up //')
                
                TEMP_RAW=$(cat /sys/class/hwmon/hwmon*/temp1_input 2>/dev/null | head -n 1)
                if [ -n "$TEMP_RAW" ]; then
                    CPU_TEMP=$(awk -v t="$TEMP_RAW" 'BEGIN {printf "%.0f", t/1000}')"°C"
                else
                    CPU_TEMP="N/A"
                fi

                MEM_USED=$(free -m | awk '/Mem:/ {print $3}')
                MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
                
                DISK_INFO=""
                while read -r line; do
                    VOL=$(echo "$line" | awk '{print $6}')
                    PERC=$(echo "$line" | awk '{print $5}')
                    FREE=$(echo "$line" | awk '{print $4}')
                    DISK_INFO="${DISK_INFO}"$'\n'"💾 <b>$VOL</b>: $PERC (Своб: $FREE)"
                done <<< "$(df -h | grep "^/dev/" | grep "/volume" | grep -vE "@|docker|snap")"
                
                HDD_TEMPS=""
                for disk in /dev/sd[a-z] /dev/sata[0-9]*; do
                    [ -e "$disk" ] || continue
                    [[ "$disk" == *p[0-9]* ]] && continue

                    TEMP_HDD=$(smartctl -A -d sat "$disk" 2>/dev/null | grep -i "Temperature_Celsius" | awk '{print $10}')
                    if [ -n "$TEMP_HDD" ]; then
                        DISK_NAME=$(basename "$disk")
                        HDD_TEMPS="${HDD_TEMPS} $DISK_NAME:<b>${TEMP_HDD}°C</b> |"
                    fi
                done

                send_msg "🖥 <b>System Info</b>
⏱ Up: <code>$UPTIME</code>
🌡 CPU: <code>$CPU_TEMP</code>
🧠 RAM: ${MEM_USED}MB / ${MEM_TOTAL}MB
------------------
$DISK_INFO
------------------
🌡 <b>HDD Temp:</b>
${HDD_TEMPS%|}" "$KB_SYSTEM"
                ;;

            "/ip" | "🌐 Сеть")
                send_action
                EXT_IP=$(curl -s -4 https://api.ipify.org)
                
                IFACE_INFO=""
                while read -r line; do
                    IFNAME=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
                    STATE=$(echo "$line" | grep -o "state [A-Z]*" | awk '{print $2}')
                    
                    IP_ADDR=$(ip -4 addr show "$IFNAME" 2>/dev/null | grep "inet" | awk '{print $2}' | cut -d/ -f1 | head -n 1)
                    
                    if [ "$STATE" == "UP" ]; then
                         ICON="🟢"
                    elif [ "$STATE" == "UNKNOWN" ]; then
                         ICON="🟡"
                    else
                         ICON="🔴"
                    fi
                    
                    if [ -n "$IP_ADDR" ]; then
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: <code>$IP_ADDR</code>"
                    else
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: (нет IP)"
                    fi
                done <<< "$(ip -o link show | grep -vE "lo|docker|veth|br-")"
                
                send_msg "🌐 <b>Сетевые интерфейсы:</b>
🌍 <b>WAN IP:</b> <code>$EXT_IP</code>
$IFACE_INFO" "$KB_SYSTEM"
                ;;

            "🏥 S.M.A.R.T.")
                send_action
                MSG="🏥 <b>Выберите диск для проверки:</b>"
                
                for disk in /dev/sd[a-z] /dev/sata[0-9]*; do
                    [ -e "$disk" ] || continue
                    [[ "$disk" == *p[0-9]* ]] && continue

                    DISK_NAME=$(basename "$disk")
                    MSG="${MSG}"$'\n'"💿 <b>$DISK_NAME</b> — /smart_$DISK_NAME"
                done
                
                send_msg "$MSG" "$KB_SYSTEM"
                ;;
            
            /smart_*)
                DISK_DEV="/dev/${TEXT#"/smart_"}"
                if [ -e "$DISK_DEV" ]; then
                    send_action
                    send_msg "⏳ Считываю S.M.A.R.T. для <b>$DISK_DEV</b>..." ""
                    
                    HEALTH=$(smartctl -H -d sat "$DISK_DEV" | grep "test result" | awk -F': ' '{print $2}')
                    MODEL=$(smartctl -i -d sat "$DISK_DEV" | grep "Device Model" | awk -F': ' '{print $2}')
                    SERIAL=$(smartctl -i -d sat "$DISK_DEV" | grep "Serial Number" | awk -F': ' '{print $2}')
                    
                    ATTRS=$(smartctl -A -d sat "$DISK_DEV")
                    BAD_SECTORS=$(echo "$ATTRS" | grep -w "5 Reallocated_Sector_Ct" | awk '{print $10}')
                    PENDING=$(echo "$ATTRS" | grep -w "197 Current_Pending_Sector" | awk '{print $10}')
                    HOURS=$(echo "$ATTRS" | grep -w "9 Power_On_Hours" | awk '{print $10}')
                    TEMP=$(echo "$ATTRS" | grep -i "Temperature_Celsius" | awk '{print $10}')
                    
                    send_msg "🏥 <b>Отчет $DISK_DEV</b>
🏷 <b>Модель:</b> $MODEL
🔢 <b>Серийный:</b> $SERIAL
Health Status: <b>$HEALTH</b>

🔥 Температура: <b>${TEMP}°C</b>
⏳ Часы работы: <b>${HOURS}ч</b>
💀 Битые сектора: <b>$BAD_SECTORS</b>
⚠️ Ожидают переназначения: <b>$PENDING</b>" "$KB_SYSTEM"
                else
                    send_msg "❌ Диск не найден."
                fi
                ;;

            "/firewall_off" | "🔥 Firewall Off")
                synofirewall --disable && send_msg "🔥 Firewall OFF. Доступ открыт." "$KB_SYSTEM"
                ;;
          
		  
		  
		  "🔌 SSH Toggle")
                send_action
                
                
                export USER=root
                export HOME=/root
                
                
                if systemctl is-active --quiet sshd; then
                    # 🔴 Служба работает
                    /usr/syno/bin/synowebapi --exec api=SYNO.Core.Terminal method=set version=1 enable_ssh=false > /tmp/ssh_api.log 2>&1
                    send_msg "🔒 <b>SSH Выключен.</b>" "$KB_SYSTEM"
                else
                    # 🟢 Служба НЕ работает
                    /usr/syno/bin/synowebapi --exec api=SYNO.Core.Terminal method=set version=1 enable_ssh=true > /tmp/ssh_api.log 2>&1
                    send_msg "🔓 <b>SSH Включен.</b> Можно подключаться." "$KB_SYSTEM"
                fi
                ;;

            
            "/docker" | "🐳 Докер")
                send_action
                D_MSG="🐳 <b>Контейнеры:</b>"
                EXISTING=$(docker ps -a --format "{{.Names}}|{{.State}}")
                while IFS='|' read -r name state; do
                    if [ "$state" == "running" ]; then
                        D_MSG="${D_MSG}"$'\n'"🟢 <b>$name</b>"$'\n'"   └ /restart_$name"
                    else
                        D_MSG="${D_MSG}"$'\n'"🔴 <b>$name</b>"$'\n'"   └ /start_$name"
                    fi
                done <<< "$EXISTING"
                send_msg "$D_MSG" "$KB_AUTO"
                ;;

            "/apps" | "📦 Apps" | "📦 Пакеты")
                send_action
                send_msg "⏳ Опрашиваю приложения..." "$KB_AUTO"
                A_MSG="📦 <b>Пакеты Synology:</b>"
                RAW_LIST=$(synopkg list --name 2>/dev/null)
                while read -r PKG; do
                    [ -z "$PKG" ] && continue
                    [[ "$PKG" =~ (Library|Codec|OAuth|SynoFinder|Python|PHP|Service|SignIn|Default) ]] && continue
                    STATUS_OUT=$(synopkg status "$PKG" 2>/dev/null)
                    if echo "$STATUS_OUT" | grep -q '"status":"running"'; then
                        A_MSG="${A_MSG}"$'\n'"🟢 <b>$PKG</b> — ОК"$'\n'"   └ /pkgrestart_$PKG"
                    else
                        A_MSG="${A_MSG}"$'\n'"🔴 <b>$PKG</b> — Стоп"$'\n'"   └ /pkgstart_$PKG"
                    fi
                done <<< "$RAW_LIST"
                send_msg "$A_MSG" "$KB_AUTO"
                ;;

            
            /restart_*) docker restart "${TEXT#"/restart_"}" >/dev/null && send_msg "✅ Рестарт OK";;
            /start_*) docker start "${TEXT#"/start_"}" >/dev/null && send_msg "🚀 Старт OK";;
            /pkgrestart_*) synopkg restart "${TEXT#"/pkgrestart_"}" >/dev/null && send_msg "✅ Пакет перезагружен";;
            /pkgstart_*) synopkg start "${TEXT#"/pkgstart_"}" >/dev/null && send_msg "🚀 Пакет запущен";;
            
        esac
    done

    LAST_ID=$(echo "$UPDATES" | jq -r '.result[-1].update_id')
    [ "$LAST_ID" != "null" ] && OFFSET=$((LAST_ID + 1))
done
