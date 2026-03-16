#!/bin/bash

CONFIG_FILE="/etc/synobot.conf"
[ ! -f "$CONFIG_FILE" ] && touch "$CONFIG_FILE" && chmod 600 "$CONFIG_FILE"
source "$CONFIG_FILE"

CONFIG_UPDATED=0


if [ -z "$TOKEN" ] || [ -z "$ADMIN_ID" ] || [ -z "$NAS_USER" ] || [ -z "$NAS_PASS" ] || [ -z "$DL_FOLDER" ]; then
    echo "------------------------------------------"
    echo "🤖 Обновление конфига"
    echo "------------------------------------------"

    if [ -z "$TOKEN" ]; then
        read -p "🔹 Введите TOKEN вашего бота: " TOKEN
        echo "TOKEN=\"$TOKEN\"" >> "$CONFIG_FILE"
        CONFIG_UPDATED=1
    fi

    if [ -z "$ADMIN_ID" ]; then
        read -p "🔹 Введите ваш Telegram ADMIN_ID: " ADMIN_ID
        echo "ADMIN_ID=\"$ADMIN_ID\"" >> "$CONFIG_FILE"
        CONFIG_UPDATED=1
    fi

    if [ -z "$NAS_USER" ]; then
        read -p "🔹 Логин администратора NAS : " NAS_USER
        echo "NAS_USER=\"$NAS_USER\"" >> "$CONFIG_FILE"
        CONFIG_UPDATED=1
    fi

    if [ -z "$NAS_PASS" ]; then
        read -p "🔹 Пароль администратора NAS: " NAS_PASS
        echo "NAS_PASS=\"$NAS_PASS\"" >> "$CONFIG_FILE"
        CONFIG_UPDATED=1
    fi

    if [ -z "$DL_FOLDER" ]; then
        read -p "🔹 Имя папки для загрузок (например, Xboot/downloads): " DL_FOLDER
        echo "DL_FOLDER=\"$DL_FOLDER\"" >> "$CONFIG_FILE"
        CONFIG_UPDATED=1
    fi

    if [ "$CONFIG_UPDATED" -eq 1 ]; then
        echo "✅ Настройки успешно обновлены и сохранены в $CONFIG_FILE"
        echo "------------------------------------------"
    fi
fi

source "$CONFIG_FILE"


TUNE_FLAG="/etc/synobot_autotune.enabled"

if [ -f "$TUNE_FLAG" ]; then
    echo "🤖 Применяю настройки ядра..."

    (
        sleep 30
        sysctl -w vm.swappiness=1 >/dev/null
        echo "✅ Swappiness успешно применен."
    ) &
fi



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
        [{"text": "🔥 Нагрузка"}, {"text": "💽 Память"}],
        [{"text": "👥 Кто онлайн"}, {"text": "🏥 S.M.A.R.T."}],
        [{"text": "🔓 Сброс 2FA"}, {"text": "🔄 Перезагрузка"}],
        [{"text": "🔌 SSH Toggle"}, {"text": "🛡 Разбан IP"}],
        [{"text": "⚡️ Ускорение DSM"}, {"text": "🆘 Создать Админа"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'

KB_AUTO='{
    "keyboard": [
        [{"text": "🐳 Докер"}, {"text": "📦 Apps"}],
        [{"text": "📥 Загрузки (Download Station)"}],
        [{"text": "💻 Включить ПК"}, {"text": "🗜 Дедупликация"}],
        [{"text": "🧠 Тюнинг Ядра"}, {"text": "👁 Радар папок"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'


watch_sys_logs() {
    
    tail -n 0 -qF /var/log/messages /var/log/synolog/synosys.log /var/log/synolog/synobackup.log 2>/dev/null | grep --line-buffered -iE "bad sector|I/O error|crashed|degrade|temperature|download.*finish|package.*update|system.*update|backup.*finish|backup.*success|backup.*fail|backup.*error|surveillance" | while read -r line; do
        
        
        if ! echo "$line" | grep -qiE "nginx|systemd|winbindd|smbd|GetActiveBackupServiceStatus|status\.lock"; then
            
            
            CLEAN_LINE=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[ \t]*//')
            
            
            if echo "$CLEAN_LINE" | grep -qi "Download task.*finished"; then
                TASK_NAME=$(echo "$CLEAN_LINE" | sed -n 's/.*\[\(.*\)\].*/\1/p')
                [ -z "$TASK_NAME" ] && TASK_NAME="Файл"
                MSG="📥 <b>Скачивание завершено:</b> $TASK_NAME"
            
            elif echo "$CLEAN_LINE" | grep -qi "package.*update"; then
                PKG_NAME=$(echo "$CLEAN_LINE" | sed -n 's/.*Package \[\([^]]*\)\].*/\1/p')
                [ -z "$PKG_NAME" ] && PKG_NAME="Приложение"
                MSG="📦 <b>Обновление:</b> Пакет $PKG_NAME успешно обновлен."
                
            
            elif echo "$CLEAN_LINE" | grep -qiE "backup.*success|backup.*finish"; then
                MSG="✅ <b>Резервное копирование:</b> Успешно завершено."
                
            
            elif echo "$CLEAN_LINE" | grep -qiE "backup.*fail|backup.*error"; then
                MSG="🔴 <b>Ошибка бэкапа:</b>\n<code>$CLEAN_LINE</code>"
                
            elif echo "$CLEAN_LINE" | grep -qiE "bad sector|I/O error|crashed|degrade"; then
                MSG="💀 <b>КРИТИЧЕСКАЯ ОШИБКА ДИСКА:</b>\n<code>$CLEAN_LINE</code>"
                
            elif echo "$CLEAN_LINE" | grep -qi "surveillance"; then
                EVENT_TEXT=$(echo "$CLEAN_LINE" | sed 's/.*Surveillance Station: //i')
                MSG="🚨 <b>SS:</b>\n$EVENT_TEXT"
                
            else
                MSG="🔔 <b>Событие системы:</b>\n<code>$CLEAN_LINE</code>"
            fi
            
            send_msg "$MSG" ""
        fi
    done
}
watch_folder_daemon() {
    while true; do
        if [ -f "/etc/synobot_watch.conf" ]; then
            W_DIR=$(cat /etc/synobot_watch.conf)
            if [ -d "$W_DIR" ]; then
                
                find "$W_DIR" -type f -print0 | xargs -0 stat -c "%s %n" 2>/dev/null | sort > /tmp/watch_dir.new
                
                if [ -f "/tmp/watch_dir.old" ]; then
                    
                    CHANGES=$(diff /tmp/watch_dir.old /tmp/watch_dir.new)
                    
                    if [ -n "$CHANGES" ]; then
                        
                        ADDED=$(echo "$CHANGES" | grep "^> " | sed 's/^> [0-9]* //')
                        REMOVED=$(echo "$CHANGES" | grep "^< " | sed 's/^< [0-9]* //')
                        
                        MSG="👁 <b>Радар папки:</b>\n<code>$W_DIR</code>"
                        [ -n "$ADDED" ] && MSG="${MSG}\n\n➕ <b>Новые / Измененные:</b>\n<code>$ADDED</code>"
                        [ -n "$REMOVED" ] && MSG="${MSG}\n\n➖ <b>Удаленные файлы:</b>\n<code>$REMOVED</code>"
                        
                        if [ ${#MSG} -gt 3500 ]; then
                            MSG="${MSG:0:3500}...\n\n<i>(Список слишком большой, показана только часть)</i>"
                        fi
                        
                        send_msg "$MSG" ""
                    fi
                fi
                
                mv /tmp/watch_dir.new /tmp/watch_dir.old
            fi
        fi
        sleep 30
    done
}


watch_pkg_logs() {
    
    tail -n 0 -qF /var/log/synopkg.log 2>/dev/null | grep --line-buffered -iE "successfully|crashed|error|fail" | while read -r line; do
        
        
        CLEAN_LINE=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^[ \t]*//')
        PKG_NAME=$(echo "$CLEAN_LINE" | awk '{print $2}' | tr -d ':')
        if echo "$CLEAN_LINE" | grep -qi "start.*successfully"; then
            send_msg "▶️ <b>Пакет запущен:</b> $PKG_NAME" ""
            
        elif echo "$CLEAN_LINE" | grep -qi "stop.*successfully"; then
            send_msg "⏹ <b>Пакет остановлен:</b> $PKG_NAME" ""

        elif echo "$CLEAN_LINE" | grep -qi "uninstall.*successfully"; then
            send_msg "🗑 <b>Пакет удален:</b> $PKG_NAME" ""
            
        elif echo "$CLEAN_LINE" | grep -qi "install.*successfully"; then
            send_msg "🆕 <b>Пакет установлен:</b> $PKG_NAME" ""
            
        elif echo "$CLEAN_LINE" | grep -qi "update.*successfully"; then
            send_msg "🔄 <b>Пакет обновлен:</b> $PKG_NAME" ""
            
        elif echo "$CLEAN_LINE" | grep -qiE "fail|error|crashed"; then
            send_msg "🔴 <b>Ошибка пакета $PKG_NAME:</b>\n<code>$CLEAN_LINE</code>" ""
        fi
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
pkill -f "watch_folder_daemon"


watch_sys_logs &
watch_pkg_logs &
watch_docker_logs &
watch_ssh_logs &
watch_web_logs &
watch_folder_daemon &


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
        DOC_ID=$(echo "$UPDATE" | jq -r '.message.document.file_id')
        DOC_NAME=$(echo "$UPDATE" | jq -r '.message.document.file_name')
        

        [ "$CHAT_ID" != "$ADMIN_ID" ] && continue
		
		
		
	
        if [ -f /tmp/syno_reboot.lock ]; then
            EXPECTED_CODE=$(cat /tmp/syno_reboot.lock)
            rm -f /tmp/syno_reboot.lock 
            
            if [ "$TEXT" == "$EXPECTED_CODE" ]; then
                send_action
                send_msg "🔄 <b>Код $EXPECTED_CODE принят!</b> NAS уходит в перезагрузку..." "$KB_MAIN"
                sleep 5
                reboot
                continue 
            else
                send_msg "❌ <b>Отмена перезагрузки.</b> Введен неверный код или другая команда." ""
                
            fi
        fi
        

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

                    TEMP_HDD=$(smartctl -A -d sat "$disk" 2>/dev/null | grep -iE "Temperature_Celsius|Temperature_Internal|Airflow_Temperature_Cel" | awk '{print $10}' | head -n 1)
                    DISK_NAME=$(basename "$disk")
                    
                    if [ -n "$TEMP_HDD" ]; then
                        HDD_TEMPS="${HDD_TEMPS} $DISK_NAME:<b>${TEMP_HDD}°C</b> |"
                    else
                        HDD_TEMPS="${HDD_TEMPS} $DISK_NAME:<b>N/A</b> |"
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
				
				
				"🔄 Перезагрузка")
                REBOOT_CODE=$((RANDOM % 9000 + 1000))
                echo "$REBOOT_CODE" > /tmp/syno_reboot.lock
                send_action
                send_msg "⚠️ <b>ПОДТВЕРЖДЕНИЕ ПЕРЕЗАГРУЗКИ</b> ⚠️ Вы точно хотите перезагрузить NAS?Если да, отправьте мне в ответ этот код:<code>$REBOOT_CODE</code> <i>(Для отмены просто нажмите любую кнопку в меню)</i>" "$KB_SYSTEM"
                ;;

            "/ip" | "🌐 Сеть")
                send_action
                EXT_IP=$(curl -s -4 https://api.ipify.org)
                
                # Достаем системные DNS и Шлюз
                DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd ", " -)
                [ -z "$DNS_SERVERS" ] && DNS_SERVERS="Не задан"
                
                GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
                [ -z "$GATEWAY" ] && GATEWAY="Не задан"
                
                IFACE_INFO=""
                while read -r line; do
                    IFNAME=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
                    STATE=$(echo "$line" | grep -o "state [A-Z]*" | awk '{print $2}')
                    IP_WITH_MASK=$(ip -4 addr show "$IFNAME" 2>/dev/null | grep -w "inet" | awk '{print $2}' | head -n 1)
                    
                    if [ "$STATE" == "UP" ]; then
                         ICON="🟢"
                    elif [ "$STATE" == "UNKNOWN" ]; then
                         ICON="🟡"
                    else
                         ICON="🔴"
                    fi
                    
                    if [ -n "$IP_WITH_MASK" ]; then
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: <code>$IP_WITH_MASK</code>"
                    else
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: (нет IP)"
                    fi
                done <<< "$(ip -o link show | grep -vE "lo|docker|veth|br-")"
                
                send_msg "🌐 <b>Сетевая информация:</b>
🌍 <b>WAN IP:</b> <code>$EXT_IP</code>
🧭 <b>Шлюз:</b> <code>$GATEWAY</code>
🗄 <b>DNS:</b> <code>$DNS_SERVERS</code>
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
                    TEMP=$(echo "$ATTRS" | grep -iE "Temperature_Celsius|Temperature_Internal|Airflow_Temperature_Cel" | awk '{print $10}' | head -n 1)
                    [ -z "$TEMP" ] && TEMP="N/A"
                    
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
                synofirewall --disable && send_msg "🔥 Firewall OFF. " "$KB_SYSTEM"
                ;;
          
		  
		  
		  "🔌 SSH Toggle")
                send_action
                
                
                export USER=root
                export HOME=/root
                
                
                if systemctl is-active --quiet sshd; then

                    /usr/syno/bin/synowebapi --exec api=SYNO.Core.Terminal method=set version=1 enable_ssh=false > /tmp/ssh_api.log 2>&1
                    send_msg "🔒 <b>SSH Выключен.</b>" "$KB_SYSTEM"
                else

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



            
            "📥 Загрузки (Download Station)")
                send_msg "Отправь мне <b>magnet-ссылку</b> или <b>прямую ссылку (http/https)</b>, и я закину это в Download Station." "$KB_AUTO"
                ;;

        
            "http"* | "magnet:"*)
                send_action
                send_msg "⏳ Отправляю ссылку на NAS..." ""
                
                # Авторизация под ТВОИМ логином
                LOGIN_RES=$(curl -s "http://localhost:5000/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=login&account=$NAS_USER&passwd=$NAS_PASS&session=DownloadStation&format=sid")
                SID=$(echo "$LOGIN_RES" | grep -o '"sid":"[^"]*' | cut -d'"' -f4)
                
                if [ -n "$SID" ]; then
                    TASK_RES=$(curl -s -X POST "http://localhost:5000/webapi/DownloadStation/task.cgi" \
                        -d "api=SYNO.DownloadStation.Task" \
                        -d "version=3" \
                        -d "method=create" \
                        --data-urlencode "uri=$TEXT" \
                        --data-urlencode "destination=$DL_FOLDER" \
                        -d "_sid=$SID")
                        
                    if echo "$TASK_RES" | grep -q '"success":true'; then
                        send_msg "✅ <b>ГОТОВО!</b> Ссылка добавлена в очередь NAS в папку: <code>$DL_FOLDER</code>." "$KB_AUTO"
                    else
                        send_msg "⚠️ <b>Ошибка Download Station:</b>\n<code>$TASK_RES</code>\n\n<i>Папка: $DL_FOLDER</i>" "$KB_AUTO"
                    fi
                    
                    curl -s "http://localhost:5000/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=logout&session=DownloadStation&_sid=$SID" > /dev/null 2>&1
                else
                    send_msg "❌ <b>Ошибка авторизации:</b>\n<code>$LOGIN_RES</code>" "$KB_AUTO"
                fi
                ;;
				
				"🔓 Сброс 2FA")
                send_action
                send_msg "⚠️ <b>Сброс 2FA (Secure SignIn)</b>
                
Чтобы отключить двухфакторку, отправьте команду с именем пользователя:
<code>/reset2fa_admin</code> 
<i>(замените admin на ваш логин, если он другой)</i>" "$KB_SYSTEM"
                ;;

            /reset2fa_*)
                TARGET_USER="${TEXT#"/reset2fa_"}"
                send_action
                send_msg "⏳ Сбрасываю 2FA для пользователя <b>$TARGET_USER</b>..." ""

                synowebapi -s --exec api=SYNO.Core.OTP.EnforcePolicy method=set version=1 enable_otp_enforcement=false otp_enforce_option=\"none\" >/dev/null 2>&1
                synowebapi -s --exec api=SYNO.SecureSignIn.AMFA.Policy method=set version=1 type=\"none\" >/dev/null 2>&1
                
                synowebapi -s --exec api=SYNO.SecureSignIn.Method.Admin method=reset version=1 account=\"$TARGET_USER\" keep_amfa_settings=true >/dev/null 2>&1

                PREF_FILE="/usr/syno/etc/packages/SecureSignIn/preference/${TARGET_USER}/method.config"
                if [ -f "$PREF_FILE" ]; then
                    sed -i "s|status=on|status=off|g" "$PREF_FILE"
                fi
                
                CONF_FILE="/usr/syno/etc/packages/SecureSignIn/secure_signin.conf"
                if [ -f "$CONF_FILE" ]; then
                    sed -i "s|list=.*$|list=|; s|type=.*$|type=none|" "$CONF_FILE"
                fi

                send_msg "✅ <b>Готово!</b>
Двухфакторная аутентификация для <b>$TARGET_USER</b> отключена. 
Теперь вы можете войти в DSM только по паролю." "$KB_SYSTEM"
                ;;
				
				"🛡 Разбан IP")
                send_action
                if [ -f "/etc/synoautoblock.db" ]; then
            
                    sqlite3 /etc/synoautoblock.db "DELETE FROM AutoBlockIP;" >/dev/null 2>&1

                    iptables -F INPUT
                    iptables -P INPUT ACCEPT
                    
                    send_msg "✅ <b>Блокировки полностью сняты!</b>

База данных AutoBlock очищена, и фильтры ядра (iptables) сброшены. 
Доступ ко всем службам восстановлен для всех IP." "$KB_SYSTEM"
                else
                    send_msg "❌ База данных блокировок не найдена." "$KB_SYSTEM"
                fi
                ;;

            "🆘 Создать Админа")
                send_action
                TEMP_PASS="Admin_$(date +%s)"
                synouser --add rr_admin "$TEMP_PASS" "Emergency_Admin" 0 "" 1 >/dev/null 2>&1
                synogroup --memberadd administrators rr_admin >/dev/null 2>&1
                
                send_msg "🚨 <b>Экстренный админ создан!</b>
                
👤 Логин: <code>rr_admin</code>
🔑 Пароль: <code>$TEMP_PASS</code>

⚠️ <i>Зайдите в DSM и удалите эту учетную запись после восстановления основного доступа!</i>" "$KB_SYSTEM"
                ;;
				
				"🔥 Нагрузка")
                send_action
                LOAD_AVG=$(cat /proc/loadavg | awk '{print $1", "$2", "$3}')
                TOP_CPU=$(top -b -n 1 2>/dev/null | head -n 12 | tail -n 5)
                [ -z "$TOP_CPU" ] && TOP_CPU="Данные недоступны"
                
                send_msg "🔥 <b>Нагрузка системы:</b>

📈 <b>Load Average:</b> <code>$LOAD_AVG</code>

💀 <b>Топ-5 процессов (CPU):</b>
<code>$TOP_CPU</code>" "$KB_SYSTEM"
                ;;

            "💽 Память")
                send_action
                MEM_USED=$(free -m | awk '/Mem:/ {print $3}')
                MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
                TOP_RAM=$(ps aux | awk 'NR>1 {split($11, a, "/"); cmd=a[length(a)]; mem[cmd]+=$6} END {for (i in mem) print mem[i], i}' | sort -rn | head -n 7 | awk '{printf "%.0f MB - %s\n", $1/1024, $2}')
                [ -z "$TOP_RAM" ] && TOP_RAM="Данные недоступны"
                
                send_msg "🧠 <b>Оперативная память (ОЗУ):</b>

📊 <b>Занято:</b> ${MEM_USED}MB из ${MEM_TOTAL}MB

💀 <b>Топ-7 служб (Суммарно):</b>
<code>$TOP_RAM</code>" "$KB_SYSTEM"
                ;;
                
            "💻 Включить ПК")
                send_action
                send_msg "⚡️ <b>Wake-on-LAN</b>
                
Отправьте мне MAC-адрес устройства, которое нужно разбудить, в таком формате:
<code>/wol AA:BB:CC:DD:EE:FF</code>" "$KB_AUTO"
                ;;
                
                /wol\ *)
                send_action
                MAC=$(echo "$TEXT" | awk '{print $2}')
                if [[ ! "$MAC" =~ ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$ ]]; then
                    send_msg "❌ <b>Ошибка:</b> Неверный формат MAC-адреса. 
Пример: <code>/wol 1A:2B:3C:4D:5E:6F</code>" "$KB_AUTO"
                else

                    python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(b'\xff'*6 + bytes.fromhex('$MAC'.replace(':',''))*16, ('255.255.255.255', 9))" 2>/dev/null
                    
                    send_msg "✅ <b>Магический пакет отправлен!</b>
MAC: <code>$MAC</code>
Сеть: 255.255.255.255" "$KB_AUTO"
                fi
                ;;
				
				"👥 Кто онлайн")
                send_action
                
                SSH_USERS=""
                while read -r line; do
                    [ -z "$line" ] && continue
                    USER=$(echo "$line" | awk '{print $1}')
                    TTY=$(echo "$line" | awk '{print $2}')
                    IP=$(echo "$line" | grep -oE "\((.*)\)" | tr -d '()')
                    [ -z "$IP" ] && IP="unknown"
                    
                    KICK_CMD="🔫 /kick_$(echo "$TTY" | tr '/' '_')"
                    SSH_USERS="${SSH_USERS}"$'\n'"🔌 <b>$USER</b> (IP: $IP)"$'\n'"   └ $KICK_CMD"
                done <<< "$(who | grep "pts")"
                [ -z "$SSH_USERS" ] && SSH_USERS="Никого нет"

                SMB_USERS=""
                if command -v smbstatus >/dev/null; then
                    SMB_RAW=$(smbstatus -b 2>/dev/null | tail -n +5 | grep -v "^$" | grep -v "IPC\\$")
                    while read -r line; do
                        [ -z "$line" ] && continue
                        PID=$(echo "$line" | awk '{print $1}')
                        USER=$(echo "$line" | awk '{print $2}')
                        IP=$(echo "$line" | awk '{print $4}')
                        
                        SMB_USERS="${SMB_USERS}"$'\n'"📁 <b>$USER</b> (IP: $IP)"$'\n'"   └ 🔫 /kick_$PID"
                    done <<< "$SMB_RAW"
                fi
                [ -z "$SMB_USERS" ] && SMB_USERS="Никого нет"

                WEB_RAW=$(/usr/syno/bin/synowebapi --exec api=SYNO.Core.CurrentConnection method=list version=1 2>/dev/null)
                WEB_USERS=$(echo "$WEB_RAW" | sed -n '/^{/,$p' | jq -r '.data.items[]? | select(.protocol == "HTTP/HTTPS") | "🌐 <b>\(.who)</b> (IP: \(.from))\n   ├ \(.descr)\n   ├ Сбросить: /kickweb_\(.did | gsub(",";"_CM_") | gsub("-";"_DS_"))\n   └ Бан: /ban_\(.from | gsub("\\.";"_"))"' 2>/dev/null)
                
                [ -z "$WEB_USERS" ] && WEB_USERS="Никого нет"

                send_msg "🕵️‍♂️ <b>Активные пользователи:</b>
                
🔌 <b>По SSH:</b>
$SSH_USERS

📁 <b>По SMB:</b>
$SMB_USERS

🖥 <b>Веб-интерфейс:</b>
$WEB_USERS" "$KB_SYSTEM"
                ;;

            
                
            /kick_*)
                send_action
                TARGET_PID="${TEXT#"/kick_"}"
                if [[ "$TARGET_PID" =~ ^[0-9]+$ ]]; then
                    ( sleep 1 && kill -9 "$TARGET_PID" ) >/dev/null 2>&1 &
                    send_msg "🔫 Процесс (PID: $TARGET_PID) убит!" "$KB_SYSTEM"
                fi
                ;;
                
            /kickweb_*)
                send_action
                SAFE_ID="${TEXT#"/kickweb_"}"
                TARGET_ID=$(echo "$SAFE_ID" | sed 's/_CM_/,/g; s/_DS_/-/g')
                if [ -f "/usr/syno/etc/private/session/current.users" ]; then
                    sed -i "/$TARGET_ID/d" /usr/syno/etc/private/session/current.users
                fi
				
                /usr/syno/bin/synowebapi --exec api=SYNO.Core.CurrentConnection method=kick version=1 id_list='["'"$TARGET_ID"'"]' >/dev/null 2>&1 &

                ( /usr/syno/bin/synosystemctl restart synocgid ) >/dev/null 2>&1 &
                
                send_msg "🚀 <b> Закрываю сесию!</b>
ID: <code>$TARGET_ID</code>.
<i>Шутка удалась.</i>" "$KB_SYSTEM"
                ;;
				
				
				"⚡️ Ускорение DSM")
                send_action
                BOOT_TIME=$(tail -n 20 /var/log/synobootup.log 2>/dev/null | grep -iE "took.*second|finish" | tail -n 1 | sed -e 's/^[ \t]*//')
                [ -z "$BOOT_TIME" ] && BOOT_TIME="Данные не найдены"

                MSG="⚡️ <b>Оптимизация скорости DSM (RAID md0)</b>\ ⏱ <b>Последняя загрузка:</b>\ <code>$BOOT_TIME</code>\ 💽 <b>Диски в системном разделе:</b>"
                MD_DEVS=$(ls -d /sys/block/md0/md/dev-* 2>/dev/null)
                for dev_path in $MD_DEVS; do
                    dev_name=$(basename "$dev_path" | sed 's/dev-//')
                    real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                    rot=$(cat /sys/block/$real_dev/queue/rotational 2>/dev/null)
                    if [ "$rot" == "1" ]; then D_TYPE="HDD 🧲"; elif [ "$rot" == "0" ]; then D_TYPE="SSD ⚡️"; else D_TYPE="???"; fi
                    
                    state=$(cat "$dev_path/state" 2>/dev/null)
                    if echo "$state" | grep -q "write_mostly"; then
                        MSG="${MSG}"$'\n\n'"🐢 <b>$dev_name</b> ($D_TYPE)\n   ├ Режим: <b>WriteMostly</b>\n   └ Сделать основным: /wmoff_$dev_name"
                    else
                        MSG="${MSG}"$'\n\n'"🚀 <b>$dev_name</b> ($D_TYPE)\n   ├ Режим: <b>Normal</b>\n   └ Пометить медленным: /wmon_$dev_name"
                    fi
                done
                MSG="${MSG}"$'\n\n'"🤖 <b>Авто:</b>\n└ Настроить всё автоматически (если есть SSD): /wmauto"
                send_msg "$MSG" "$KB_SYSTEM"
                ;;

            "/wmauto")
                send_action
                HAS_SSD=0
                MD_DEVS=$(ls -d /sys/block/md0/md/dev-* 2>/dev/null)
                for dev_path in $MD_DEVS; do
                    dev_name=$(basename "$dev_path" | sed 's/dev-//')
                    real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                    if [ "$(cat /sys/block/$real_dev/queue/rotational 2>/dev/null)" == "0" ]; then HAS_SSD=1; break; fi
                done

                if [ "$HAS_SSD" == "1" ]; then
                    MSG_LOG="🤖 <b>Авто-оптимизация выполнена!</b>\n"
                    for dev_path in $MD_DEVS; do
                        dev_name=$(basename "$dev_path" | sed 's/dev-//')
                        real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                        rot=$(cat /sys/block/$real_dev/queue/rotational 2>/dev/null)
                        if [ "$rot" == "1" ]; then
                            echo writemostly > "$dev_path/state" 2>/dev/null
                            MSG_LOG="${MSG_LOG}"$'\n'"🧲 <code>$dev_name</code> ➔ <b>Медленный</b>"
                        elif [ "$rot" == "0" ]; then
                            echo -writemostly > "$dev_path/state" 2>/dev/null
                            MSG_LOG="${MSG_LOG}"$'\n'"⚡️ <code>$dev_name</code> ➔ <b>Основной</b>"
                        fi
                    done
                    send_msg "$MSG_LOG" "$KB_SYSTEM"
                else
                    send_msg "⚠️ <b>Авто-режим отменен.</b>\ Я не нашел ни одного SSD. Выберите медленные диски вручную в меню." "$KB_SYSTEM"
                fi
                ;;

            /wmon_*)
                send_action
                TARGET_DEV="${TEXT#"/wmon_"}"
                echo writemostly > "/sys/block/md0/md/dev-${TARGET_DEV}/state" 2>/dev/null
                send_msg "✅ <b>Ускорение применено!</b>\ Диск <code>$TARGET_DEV</code> помечен как медленный." "$KB_SYSTEM"
                ;;
                
            /wmoff_*)
                send_action
                TARGET_DEV="${TEXT#"/wmoff_"}"
                echo -writemostly > "/sys/block/md0/md/dev-${TARGET_DEV}/state" 2>/dev/null
                send_msg "🔄 <b>Метка снята.</b>\nДиск <code>$TARGET_DEV</code> возвращен в нормальный режим." "$KB_SYSTEM"
                ;;
				
				"👁 Радар папок")
                send_action
                send_msg "👁 <b>Радар папок (Слежка за файлами)</b>
                
Чтобы запустить радар, скопируй команду ниже, подставь свой путь и отправь мне:
<code>/watch /volume1/твой/путь</code>

<i>Пример: /watch /volume1/docker</i>

Для остановки слежки просто нажми сюда: 👉 /watch_stop" "$KB_AUTO"
                ;;

            "/watch "*)
                send_action
                TARGET_DIR="${TEXT#"/watch "}"
                if [ -d "$TARGET_DIR" ]; then
                    echo "$TARGET_DIR" > /etc/synobot_watch.conf
                    rm -f /tmp/watch_dir.old
                    send_msg "👁 <b>Радар запущен!</b>
Папка: <code>$TARGET_DIR</code>

Проверяю её каждые 30 секунд. Если появятся новые файлы или кто-то удалит старые — я пришлю отчет. 
<i>(Для остановки нажми /watch_stop)</i>" "$KB_AUTO"
                else
                    send_msg "❌ <b>Ошибка:</b> Папки <code>$TARGET_DIR</code> не существует на NAS!" "$KB_AUTO"
                fi
                ;;
                
            "/watch stop" | "/watch_stop")
                send_action
                rm -f /etc/synobot_watch.conf
                rm -f /tmp/watch_dir.old
                send_msg "🛑 <b>Радар остановлен.</b> Я больше не слежу за файлами." "$KB_AUTO"
                ;;
				
				"🗜 Дедупликация")
                send_action
                send_msg "🗜 <b>Настройка Дедупликации (007revad)</b>
                
Выберите режим, который бот установит на NAS:

👉 <code>/dedupe_max</code> — <b>Максимальный</b> 🚀
(Забирает больше ОЗУ, работает быстрее. Идеально для 16+ ГБ)

👉 <code>/dedupe_tiny</code> — <b>Экономный</b> 🪶
(Режим Tiny. Экономит ОЗУ, работает чуть медленнее)

<i>* Оба режима включают поддержку HDD и неоригинальных SSD.</i>" "$KB_AUTO"
                ;;

            "/dedupe_"*)
                send_action
                MODE="${TEXT#"/dedupe_"}"
                
                if [ "$MODE" == "max" ]; then
                    FLAGS="--hdd"
                    MODE_NAME="Максимальный 🚀"
                elif [ "$MODE" == "tiny" ]; then
                    FLAGS="--hdd --tiny"
                    MODE_NAME="Экономный (Tiny) 🪶"
                else
                    continue
                fi
                
                send_msg "⏳ <b>Запускаю патч...</b>\ Режим: <b>$MODE_NAME</b>. Это займет пару секунд." "$KB_AUTO"
                
                SCRIPT_URL="https://raw.githubusercontent.com/007revad/Synology_enable_Deduplication/main/syno_enable_dedupe.sh"
                curl -sL "$SCRIPT_URL" -o /tmp/syno_enable_dedupe.sh
                
                if [ -f "/tmp/syno_enable_dedupe.sh" ]; then
                    chmod +x /tmp/syno_enable_dedupe.sh

                    OUTPUT=$(bash /tmp/syno_enable_dedupe.sh $FLAGS 2>&1)
                    rm -f /tmp/syno_enable_dedupe.sh
                    
                    if [ ${#OUTPUT} -gt 3500 ]; then
                        OUTPUT="${OUTPUT:0:3500}...\n[Лог обрезан]"
                    fi
                    
                    send_msg "✅ <b>Патч успешно отработал!</b>
                    
<b>Лог работы:</b>
<code>$OUTPUT</code>

⚠️ <i>Обязательно отправь NAS в перезагрузку!</i>" "$KB_AUTO"
                else
                    send_msg "❌ <b>Ошибка:</b> Не удалось скачать скрипт." "$KB_AUTO"
                fi
                ;;
				
				"/ban_"*)
                send_action
                BAN_IP="${TEXT#"/ban_"}"
                BAN_IP="${BAN_IP//_/.}"
                if [ "$BAN_IP" == "127.0.0.1" ]; then
                    send_msg "⚠️ <b>Отказ:</b> Банить системный адрес (<code>127.0.0.1</code>) категорически запрещено! Это сломает NAS." "$KB_SYSTEM"
                else
                    NOW=$(date +%s)
                    sqlite3 /etc/synoautoblock.db "REPLACE INTO AutoBlockIP (IP, RecordTime, ExpireTime, Deny, IPStd, Type, Meta) VALUES ('$BAN_IP', $NOW, 0, 1, '', 0, '');"
                    iptables -I INPUT 1 -s "$BAN_IP" -j DROP
                    send_msg "⛔️ <b>IP ЖЕСТКО ЗАБЛОКИРОВАН!</b>
                    
Адрес <code>$BAN_IP</code> занесен в ЧС.
Ядро сбросило все активные соединения (iptables DROP).
Доступ полностью закрыт." "$KB_SYSTEM"
                fi
                ;;
				
				"🧠 Тюнинг Ядра")
                send_action
                SWAP_VAL=$(cat /proc/sys/vm/swappiness 2>/dev/null)
                MEM_COMP=$(grep '^mem_compress=' /etc/synoinfo.conf | cut -d'"' -f2)
                [ "$MEM_COMP" == "yes" ] || [ -z "$MEM_COMP" ] && MEM_TXT="🟢 Включено" || MEM_TXT="🔴 Выключено"
                if [ -f "/etc/synobot_autotune.enabled" ]; then
                    AUTO_STATUS="✅ <b>АКТИВЕН</b> (Применяю 1 после перезагрузки)"
                    AUTO_CMD="/autotune_off"
                    AUTO_BTN="Выключить авто-режим"
                else
                    AUTO_STATUS="⚪️ <b>ВЫКЛЮЧЕН</b> (Система сама решит)"
                    AUTO_CMD="/autotune_on"
                    AUTO_BTN="Включить авто-режим"
                fi

                send_msg "🧠 <b>Тюнинг Ядра (Оптимизация)</b>
                
1️⃣ <b>Файл подкачки (Swappiness)</b>
Текущая агрессивность: <b>$SWAP_VAL</b>
👉 Сделать (1): /swap_1
👉 Вернуть (60): /swap_60

2️⃣ <b>Сжатие памяти (ZRAM)</b>
Текущий статус: $MEM_TXT
👉 Изменить: /memcomp_on | /memcomp_off

3️⃣ <b>Авто (После перезагрузки)</b>
Статус: $AUTO_STATUS
👉 $AUTO_BTN: $AUTO_CMD" "$KB_AUTO"
                ;;
				
            "/autotune_on")
                send_action
                touch "/etc/synobot_autotune.enabled"
                send_msg "🚀 <b>Авто включен!</b>\ Теперь при каждом запуске бота я сам буду выставлять Swappiness=1 ." "$KB_AUTO"
                ;;

            "/autotune_off")
                send_action
                rm -f "/etc/synobot_autotune.enabled"
                send_msg "⚪️ <b>Авто выключен.</b>\nБольше не трогаю систему при старте." "$KB_AUTO"
                ;;
				/swap_*)
                send_action
                VAL="${TEXT#"/swap_"}"
                if [[ "$VAL" =~ ^[0-9]+$ ]]; then
                    sysctl -w vm.swappiness="$VAL" >/dev/null
                    send_msg "✅ <b>Swappiness установлен в $VAL!</b>\nЯдро подхватило настройку без перезагрузки." "$KB_AUTO"
                fi
                ;;

            /memcomp_on)
                send_action
                synosetkeyvalue /etc/synoinfo.conf mem_compress yes
                synosetkeyvalue /etc.defaults/synoinfo.conf mem_compress yes
                send_msg "🔄 <b>Сжатие памяти ВКЛЮЧЕНО.</b>\ ⚠️ <b>Нужна перезагрузка NAS</b>, чтобы ядро подхватило настройку." "$KB_AUTO"
                ;;

            /memcomp_off)
                send_action
                synosetkeyvalue /etc/synoinfo.conf mem_compress no
                synosetkeyvalue /etc.defaults/synoinfo.conf mem_compress no
                send_msg "✅ <b>Сжатие памяти ОТКЛЮЧЕНО!</b>\ ⚠️ <b>Нужна перезагрузка</b> для выгрузки модуля ZRAM." "$KB_AUTO"
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
