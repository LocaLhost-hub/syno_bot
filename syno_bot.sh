#!/bin/bash

# ==========================================
# 🤖 SYNO BOT v2.3 (Full Suite: DSM Backup, HyperBackup, /du, WAN IP, Scheduler)
# ==========================================

CONFIG_FILE="/etc/synobot.conf"
PID_FILE="/var/run/synobot.pid"
MUTE_DIR="/etc/synobot_mute"
TUNE_FLAG="/etc/synobot_autotune.enabled"
SCRIPT_PATH="$(readlink -f "$0")"

[ "$EUID" -ne 0 ] && echo "Запустите от root (sudo)!" && exit 1

[ ! -f "$CONFIG_FILE" ] && touch "$CONFIG_FILE" && chmod 600 "$CONFIG_FILE"
mkdir -p "$MUTE_DIR"
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
        read -p "🔹 Логин администратора NAS: " NAS_USER
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

# --- ЗАЩИТА ОТ ДУБЛИРОВАНИЯ ПРОЦЕССОВ ---
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && [ "$OLD_PID" != "$$" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "♻️ Останавливаю предыдущий экземпляр бота (PID: $OLD_PID)..."
        pkill -P "$OLD_PID" 2>/dev/null
        kill "$OLD_PID" 2>/dev/null
        sleep 2
    fi
fi
echo $$ > "$PID_FILE"

cleanup() {
    pkill -P $$ 2>/dev/null
    rm -f "$PID_FILE"
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# --- АВТОТЮНИНГ ЯДРА ---
if [ -f "$TUNE_FLAG" ]; then
    echo "🤖 Применяю настройки ядра..."
    (
        sleep 30
        sysctl -w vm.swappiness=1 >/dev/null 2>&1
    ) &
fi

URL="https://api.telegram.org/bot$TOKEN"
FILE_URL="https://api.telegram.org/file/bot$TOKEN"
OFFSET=0

if ! command -v jq &> /dev/null; then
    wget -q -O /bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 && chmod +x /bin/jq
fi

# Экранирование спецсимволов HTML для Telegram
html_escape() {
    printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
}

send_msg() {
    local text="$1"
    local kb="$2"
    if [ -n "$kb" ]; then
        curl -s --connect-timeout 10 --max-time 20 -X POST "$URL/sendMessage" \
            -d chat_id="$ADMIN_ID" \
            -d parse_mode="HTML" \
            -d disable_web_page_preview="true" \
            --data-urlencode "text=$text" \
            --data-urlencode "reply_markup=$kb" > /dev/null
    else
        curl -s --connect-timeout 10 --max-time 20 -X POST "$URL/sendMessage" \
            -d chat_id="$ADMIN_ID" \
            -d parse_mode="HTML" \
            -d disable_web_page_preview="true" \
            --data-urlencode "text=$text" > /dev/null
    fi
}


send_doc() {
    local file_path="$1"
    local caption="$2"
    local kb="$3"
    if [ -n "$kb" ]; then
        curl -s --connect-timeout 15 --max-time 60 -X POST "$URL/sendDocument" \
            -F chat_id="$ADMIN_ID" \
            -F parse_mode="HTML" \
            -F caption="$caption" \
            -F reply_markup="$kb" \
            -F document=@"$file_path" > /dev/null
    else
        curl -s --connect-timeout 15 --max-time 60 -X POST "$URL/sendDocument" \
            -F chat_id="$ADMIN_ID" \
            -F parse_mode="HTML" \
            -F caption="$caption" \
            -F document=@"$file_path" > /dev/null
    fi
}

send_action() {
    curl -s --connect-timeout 5 --max-time 10 -X POST "$URL/sendChatAction" \
        -d chat_id="$ADMIN_ID" -d action="typing" > /dev/null
}

is_muted() {
    [ -f "$MUTE_DIR/$1.muted" ]
}

# --- КЛАВИАТУРЫ ---
KB_MAIN='{
    "keyboard": [
        [{"text": "💻 Система"}, {"text": "⚙️ Apps"}],
        [{"text": "🔔 Уведомления"}, {"text": "🤖 Бот"}]
    ],
    "resize_keyboard": true
}'

KB_SYSTEM='{
    "keyboard": [
        [{"text": "📊 Статус"}, {"text": "🌐 Сеть"}],
        [{"text": "🔥 Нагрузка"}, {"text": "💽 Память"}],
        [{"text": "👥 Кто онлайн"}, {"text": "🏥 S.M.A.R.T."}],
        [{"text": "🗑 Корзины"}, {"text": "🔐 SSL"}],
        [{"text": "💾 Бэкап DSM"}, {"text": "📂 Топ папок (/du)"}],
        [{"text": "🔓 Сброс 2FA"}, {"text": "🔄 Перезагрузка"}],
        [{"text": "🔌 SSH Toggle"}, {"text": "🛡 Разбан IP"}],
        [{"text": "⚡️ Ускорение DSM"}, {"text": "🆘 Создать Админа"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'

KB_AUTO='{
    "keyboard": [
        [{"text": "🐳 Докер"}, {"text": "🔄 Обновить Compose"}],
        [{"text": "📦 Apps"}, {"text": "📥 Загрузки (Download Station)"}],
        [{"text": "📦 Hyper Backup"}, {"text": "⏱ Планировщик"}],
        [{"text": "💻 Включить ПК"}, {"text": "🗜 Дедупликация"}],
        [{"text": "🧠 Тюнинг Ядра"}, {"text": "👁 Радар папок"}],
        [{"text": "🔙 Назад в меню"}]
    ],
    "resize_keyboard": true
}'

# ==========================================
# 👁 ФОНОВЫЕ МОНИТОРЫ (WATCHERS)
# ==========================================

watch_sys_logs() {
    tail -n 0 -qF /var/log/messages /var/log/synolog/synosys.log /var/log/synolog/synobackup.log 2>/dev/null | \
    grep --line-buffered -iE "bad sector|I/O error|crashed|degrade|temperature|download.*finish|package.*update|system.*update|backup.*finish|backup.*success|backup.*fail|backup.*error|surveillance" | \
    while read -r line; do
        is_muted "sys" && continue
        if ! echo "$line" | grep -qiE "nginx|systemd|winbindd|smbd|GetActiveBackupServiceStatus|status\.lock"; then
            CLEAN_LINE=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | sed 's/^[ \t]*//')
            SAFE_LINE=$(html_escape "$CLEAN_LINE")

            if echo "$CLEAN_LINE" | grep -qi "Download task.*finished"; then
                TASK_NAME=$(echo "$CLEAN_LINE" | sed -n 's/.*\[\(.*\)\].*/\1/p')
                [ -z "$TASK_NAME" ] && TASK_NAME="Файл"
                MSG="📥 <b>Скачивание завершено:</b> $(html_escape "$TASK_NAME")"

            elif echo "$CLEAN_LINE" | grep -qi "package.*update"; then
                PKG_NAME=$(echo "$CLEAN_LINE" | sed -n 's/.*Package \[\([^]]*\)\].*/\1/p')
                [ -z "$PKG_NAME" ] && PKG_NAME="Приложение"
                MSG="📦 <b>Обновление:</b> Пакет $(html_escape "$PKG_NAME") успешно обновлен."

            elif echo "$CLEAN_LINE" | grep -qiE "backup.*success|backup.*finish"; then
                MSG="✅ <b>Резервное копирование:</b> Успешно завершено."

            elif echo "$CLEAN_LINE" | grep -qiE "backup.*fail|backup.*error"; then
                MSG="🔴 <b>Ошибка бэкапа:</b>"$'\n'"<code>$SAFE_LINE</code>"

            elif echo "$CLEAN_LINE" | grep -qiE "bad sector|I/O error|crashed|degrade"; then
                MSG="💀 <b>КРИТИЧЕСКАЯ ОШИБКА ДИСКА:</b>"$'\n'"<code>$SAFE_LINE</code>"

            elif echo "$CLEAN_LINE" | grep -qi "surveillance"; then
                EVENT_TEXT=$(echo "$CLEAN_LINE" | sed 's/.*Surveillance Station: //i')
                MSG="🚨 <b>SS:</b>"$'\n'"$(html_escape "$EVENT_TEXT")"

            else
                MSG="🔔 <b>Событие системы:</b>"$'\n'"<code>$SAFE_LINE</code>"
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
                find "$W_DIR" -type f -print0 2>/dev/null | xargs -0 stat -c "%s %n" 2>/dev/null | sort > /tmp/watch_dir.new

                if [ -f "/tmp/watch_dir.old" ]; then
                    CHANGES=$(diff /tmp/watch_dir.old /tmp/watch_dir.new)
                    if [ -n "$CHANGES" ]; then
                        ADDED=$(echo "$CHANGES" | grep "^> " | sed 's/^> [0-9]* //')
                        REMOVED=$(echo "$CHANGES" | grep "^< " | sed 's/^< [0-9]* //')

                        MSG="👁 <b>Радар папки:</b>"$'\n'"<code>$(html_escape "$W_DIR")</code>"
                        [ -n "$ADDED" ] && MSG="${MSG}"$'\n\n'"➕ <b>Новые / Измененные:</b>"$'\n'"<code>$(html_escape "$ADDED")</code>"
                        [ -n "$REMOVED" ] && MSG="${MSG}"$'\n\n'"➖ <b>Удаленные файлы:</b>"$'\n'"<code>$(html_escape "$REMOVED")</code>"

                        if [ ${#MSG} -gt 3500 ]; then
                            MSG="${MSG:0:3500}..."$'\n\n'"<i>(Список слишком большой, показана только часть)</i>"
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
        is_muted "pkg" && continue
        CLEAN_LINE=$(echo "$line" | awk '{$1=$2=""; print $0}' | sed 's/^[ \t]*//')
        PKG_NAME=$(html_escape "$(echo "$CLEAN_LINE" | awk '{print $2}' | tr -d ':')")

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
            send_msg "🔴 <b>Ошибка пакета $PKG_NAME:</b>"$'\n'"<code>$(html_escape "$CLEAN_LINE")</code>" ""
        fi
    done
}

watch_docker_logs() {
    command -v docker >/dev/null 2>&1 || return
    docker events --filter 'event=die' --filter 'event=start' --format '{{.Actor.Attributes.name}}|{{.Status}}' 2>/dev/null | while IFS='|' read -r name status; do
        is_muted "docker" && continue
        SAFE_NAME=$(html_escape "$name")
        if [ "$status" == "start" ]; then
            send_msg "🟢 <b>Docker:</b> Контейнер <b>$SAFE_NAME</b> запущен." ""
        elif [ "$status" == "die" ]; then
            send_msg "🔴 <b>Docker:</b> Контейнер <b>$SAFE_NAME</b> остановлен (или упал)!" ""
        fi
    done
}

watch_ssh_logs() {
    tail -n 0 -qF /var/log/auth.log 2>/dev/null | while read -r line; do
        is_muted "ssh" && continue
        if echo "$line" | grep -q "sshd.*session opened for user"; then
            USER=$(echo "$line" | sed -n 's/.*user \([^ ]*\).*/\1/p')
            send_msg "🟢 <b>Вход по SSH</b>"$'\n'"👤 Пользователь: <b>$(html_escape "$USER")</b>" ""
        elif echo "$line" | grep -q "sshd.*session closed for user"; then
            USER=$(echo "$line" | sed -n 's/.*user \([^ ]*\).*/\1/p')
            send_msg "⚪️ <b>Выход из SSH</b>"$'\n'"👤 Пользователь: <b>$(html_escape "$USER")</b>" ""
        fi
    done
}


watch_health_daemon() {
    local UPS_PREV=""
    local LAST_SSL_CHECK=0
    local LAST_WAN_CHECK=0
    local LAST_WAN_IP=""
    mkdir -p /tmp/syno_alerts

    while true; do
        if ! is_muted "health"; then
            # 1. Мониторинг ИБП (UPS)
            if command -v upsc >/dev/null 2>&1; then
                local ups_raw ups_st ups_ch ups_rt
                ups_raw=$(upsc ups@localhost 2>/dev/null)
                if [ -n "$ups_raw" ]; then
                    ups_st=$(echo "$ups_raw" | awk -F': ' '/^ups\.status:/ {print $2}')
                    ups_ch=$(echo "$ups_raw" | awk -F': ' '/^battery\.charge:/ {print $2}')
                    ups_rt=$(echo "$ups_raw" | awk -F': ' '/^battery\.runtime:/ {print int($2/60)}')
                    if [[ "$ups_st" == *"OB"* ]] && [[ "$UPS_PREV" != *"OB"* ]]; then
                        send_msg "🔴 <b>ИБП ПЕРЕШЕЛ НА БАТАРЕЮ!</b>"$'\n'"🔋 Заряд: <b>${ups_ch:-?}%</b> | Осталось: ~<b>${ups_rt:-?} мин</b>" ""
                    elif [[ "$ups_st" == *"OL"* ]] && [[ "$UPS_PREV" == *"OB"* ]]; then
                        send_msg "⚡ <b>Питание от сети восстановлено!</b>"$'\n'"🔋 Заряд ИБП: <b>${ups_ch:-?}%</b>" ""
                    fi
                    UPS_PREV="$ups_st"
                fi
            fi

            local NOW_TS=$(date +%s)

            # 2. Мониторинг температуры дисков (> 50°C, не чаще 1 раза в час на диск)
            for disk in /dev/sd[a-z] /dev/sata[0-9]* /dev/nvme[0-9]n[0-9]; do
                [ -e "$disk" ] || continue
                [[ "$disk" == *p[0-9]* ]] && continue
                local dname t_val flag_f last_t
                dname=$(basename "$disk")
                if [[ "$disk" == /dev/nvme* ]]; then
                    t_val=$(smartctl -A "$disk" 2>/dev/null | awk '/^Temperature:/ {print $2; exit}')
                else
                    t_val=$(smartctl -A -d sat "$disk" 2>/dev/null | grep -iE "Temperature_Celsius|Temperature_Internal|Airflow_Temperature_Cel" | awk '{print $10}' | head -n 1)
                fi
                if [[ "$t_val" =~ ^[0-9]+$ ]] && [ "$t_val" -ge 50 ]; then
                    flag_f="/tmp/syno_alerts/temp_${dname}"
                    last_t=$(cat "$flag_f" 2>/dev/null || echo 0)
                    if [ $((NOW_TS - last_t)) -ge 3600 ]; then
                        send_msg "🔥 <b>ПЕРЕГРЕВ ДИСКА $dname!</b>"$'\n'"🌡 Температура: <b>${t_val}°C</b>" ""
                        echo "$NOW_TS" > "$flag_f"
                    fi
                fi
            done

            # 3. Мониторинг свободного места на /volume* (>= 90%, не чаще 1 раза в 6 часов)
            while read -r line; do
                [ -z "$line" ] && continue
                local vol pct free_sp safe_vol flag_f last_t
                vol=$(echo "$line" | awk '{print $6}')
                pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
                free_sp=$(echo "$line" | awk '{print $4}')
                if [[ "$pct" =~ ^[0-9]+$ ]] && [ "$pct" -ge 90 ]; then
                    safe_vol=$(echo "$vol" | tr '/' '_')
                    flag_f="/tmp/syno_alerts/disk_${safe_vol}"
                    last_t=$(cat "$flag_f" 2>/dev/null || echo 0)
                    if [ $((NOW_TS - last_t)) -ge 21600 ]; then
                        send_msg "⚠️ <b>МАЛО МЕСТА НА $vol!</b>"$'\n'"💾 Занято: <b>${pct}%</b> (Свободно: <code>$free_sp</code>)" ""
                        echo "$NOW_TS" > "$flag_f"
                    fi
                fi
            done <<< "$(df -h | grep "^/dev/" | grep "/volume" | grep -vE "@|docker|snap")"

            # 4. Проверка SSL сертификатов раз в 24 часа (алерт если < 14 дней)
            if [ $((NOW_TS - LAST_SSL_CHECK)) -ge 86400 ]; then
                LAST_SSL_CHECK=$NOW_TS
                for cert in /usr/syno/etc/certificate/_archive/*/cert.pem /usr/syno/etc/certificate/system/default/cert.pem; do
                    [ -f "$cert" ] || continue
                    local end_date end_ts days_left subj
                    end_date=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
                    [ -z "$end_date" ] && continue
                    end_ts=$(date -d "$end_date" +%s 2>/dev/null)
                    [ -z "$end_ts" ] && continue
                    days_left=$(( (end_ts - NOW_TS) / 86400 ))
                    if [ "$days_left" -le 14 ]; then
                        subj=$(openssl x509 -subject -noout -in "$cert" 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
                        send_msg "🔐 <b>Истекает SSL-сертификат!</b>"$'\n'"🌐 Домен: <code>$(html_escape "${subj:-unknown}")</code>"$'\n'"⏳ Осталось дней: <b>$days_left</b>" ""
                    fi
                done
            fi

            # 5. Трекер смены WAN IP (раз в 5 минут)
            if [ $((NOW_TS - LAST_WAN_CHECK)) -ge 300 ]; then
                LAST_WAN_CHECK=$NOW_TS
                local cur_wan
                cur_wan=$(curl -s --connect-timeout 5 --max-time 10 -4 https://api.ipify.org)
                if [[ "$cur_wan" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    if [ -n "$LAST_WAN_IP" ] && [ "$cur_wan" != "$LAST_WAN_IP" ]; then
                        send_msg "🌍 <b>СМЕНА ВНЕШНЕГО IP (WAN)!</b>"$'\n'"Старый: <code>$LAST_WAN_IP</code>"$'\n'"Новый: <code>$cur_wan</code>" ""
                    fi
                    LAST_WAN_IP="$cur_wan"
                fi
            fi
        fi
        sleep 60
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
                LAST_ID=$log_id
                is_muted "web" && continue
                SAFE_U=$(html_escape "$log_user")
                SAFE_IP=$(html_escape "$log_ip")

                if echo "$log_msg" | grep -qi "signed in to \[DSM\] successfully"; then
                    send_msg "🟢 <b>Вход в DSM (Web)</b>"$'\n'"👤 Пользователь: <b>$SAFE_U</b>"$'\n'"🌐 IP: <code>$SAFE_IP</code>" ""
                elif echo "$log_msg" | grep -qiE "fail.*sign in|fail.*log in"; then
                    send_msg "🔴 <b>Ошибка входа в DSM</b>"$'\n'"👤 Пользователь: <b>$SAFE_U</b>"$'\n'"🌐 IP: <code>$SAFE_IP</code>" ""
                fi
            done <<< "$NEW_LOGS"
        fi
    done
}

# ==========================================
# 🔧 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================================

ds_login() {
    curl -s --connect-timeout 10 --max-time 20 -X POST "http://localhost:5000/webapi/entry.cgi" \
        -d "api=SYNO.API.Auth" \
        -d "version=6" \
        -d "method=login" \
        --data-urlencode "account=$NAS_USER" \
        --data-urlencode "passwd=$NAS_PASS" \
        -d "session=DownloadStation" \
        -d "format=sid"
}

ds_logout() {
    local sid="$1"
    curl -s --connect-timeout 5 --max-time 10 "http://localhost:5000/webapi/entry.cgi?api=SYNO.API.Auth&version=6&method=logout&session=DownloadStation&_sid=$sid" > /dev/null 2>&1
}

get_raid_summary() {
    [ ! -f /proc/mdstat ] && return
    local out=""
    local md_name=""
    while read -r line; do
        if [[ "$line" =~ ^(md[0-9]+)\ :\ (active|inactive)\ ([a-z0-9]+) ]]; then
            md_name="${BASH_REMATCH[1]} (${BASH_REMATCH[3]})"
        elif [[ -n "$md_name" && "$line" =~ \[([U_]+)\] ]]; then
            local state="${BASH_REMATCH[1]}"
            if [[ "$state" == *"_"* ]]; then
                out="${out}"$'\n'"🔴 <b>$md_name</b>: DEGRADED [$state]"
            else
                out="${out}"$'\n'"🟢 <b>$md_name</b>: OK [$state]"
            fi
            md_name=""
        fi
    done < /proc/mdstat
    echo "$out"
}

get_ups_info() {
    command -v upsc >/dev/null 2>&1 || return
    local ups_raw
    ups_raw=$(upsc ups@localhost 2>/dev/null)
    [ -z "$ups_raw" ] && return

    local charge status runtime
    charge=$(echo "$ups_raw" | awk -F': ' '/^battery\.charge:/ {print $2}')
    status=$(echo "$ups_raw" | awk -F': ' '/^ups\.status:/ {print $2}')
    runtime=$(echo "$ups_raw" | awk -F': ' '/^battery\.runtime:/ {print int($2/60)}')

    local icon="🔋"
    [[ "$status" == *"OL"* ]] && icon="⚡"
    [[ "$status" == *"OB"* ]] && icon="🔴"

    echo "$icon <b>UPS:</b> ${charge:-?}% | ${status:-?} (~${runtime:-?} мин)"
}

show_notify_menu() {
    local s_sys s_pkg s_doc s_ssh s_web s_hlt
    is_muted "sys"    && s_sys="🔕 ВЫКЛ (/mute_sys)"       || s_sys="🔔 ВКЛ (/mute_sys)"
    is_muted "pkg"    && s_pkg="🔕 ВЫКЛ (/mute_pkg)"       || s_pkg="🔔 ВКЛ (/mute_pkg)"
    is_muted "docker" && s_doc="🔕 ВЫКЛ (/mute_docker)"    || s_doc="🔔 ВКЛ (/mute_docker)"
    is_muted "ssh"    && s_ssh="🔕 ВЫКЛ (/mute_ssh)"       || s_ssh="🔔 ВКЛ (/mute_ssh)"
    is_muted "web"    && s_web="🔕 ВЫКЛ (/mute_web)"       || s_web="🔔 ВКЛ (/mute_web)"
    is_muted "health" && s_hlt="🔕 ВЫКЛ (/mute_health)"    || s_hlt="🔔 ВКЛ (/mute_health)"

    send_msg "🔔 <b>Управление уведомлениями:</b>

🖥 Системные логи / Бэкапы: $s_sys
📦 Пакеты Synology: $s_pkg
🐳 Docker события: $s_doc
🔌 Входы по SSH: $s_ssh
🌐 Входы в DSM (Web): $s_web
🔋 UPS / Диски / Темп / SSL: $s_hlt" "$KB_MAIN"
}


COMPOSE_LIST_FILE="/tmp/syno_compose_list.txt"

get_compose_cmd() {
    if docker compose version >/dev/null 2>&1; then
        echo "docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        echo "docker-compose"
    else
        echo ""
    fi
}

scan_compose_projects() {
    : > "$COMPOSE_LIST_FILE"
    command -v docker >/dev/null 2>&1 || return 1

    local idx=1
    while IFS='|' read -r proj wdir cfile; do
        [ -z "$proj" ] && continue
        [ -z "$wdir" ] && continue
        [ ! -d "$wdir" ] && continue
        echo "${idx}|${proj}|${wdir}|${cfile}" >> "$COMPOSE_LIST_FILE"
        idx=$((idx + 1))
    done < <(docker ps -a --format '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Label "com.docker.compose.project.config_files"}}' 2>/dev/null | sort -u)
}

run_compose_update() {
    local proj="$1"
    local wdir="$2"
    local cfile="$3"
    local cmd
    cmd=$(get_compose_cmd)
    if [ -z "$cmd" ]; then
        send_msg "❌ Не найден <code>docker compose</code> или <code>docker-compose</code>." "$KB_AUTO"
        return 1
    fi

    local out=""
    local rc=0
    if [ -n "$cfile" ] && [ -f "$cfile" ]; then
        out=$(cd "$wdir" && $cmd -f "$cfile" pull 2>&1 && $cmd -f "$cfile" up -d --remove-orphans 2>&1)
        rc=$?
    else
        out=$(cd "$wdir" && $cmd pull 2>&1 && $cmd up -d --remove-orphans 2>&1)
        rc=$?
    fi

    if [ ${#out} -gt 2800 ]; then
        out="...${out: -2800}"
    fi

    if [ "$rc" -eq 0 ]; then
        send_msg "✅ <b>Проект $(html_escape "$proj") обновлен!</b>"$'\n'"📁 <code>$(html_escape "$wdir")</code>"$'\n\n'"<code>$(html_escape "$out")</code>" "$KB_AUTO"
    else
        send_msg "🔴 <b>Ошибка обновления $(html_escape "$proj"):</b>"$'\n'"<code>$(html_escape "$out")</code>" "$KB_AUTO"
    fi
    return "$rc"
}


DS_TASK_MAP="/tmp/syno_ds_tasks.txt"

show_ds_queue() {
    local login_res sid list_res
    login_res=$(ds_login)
    sid=$(echo "$login_res" | jq -r '.data.sid // empty')
    if [ -z "$sid" ]; then
        send_msg "❌ Ошибка авторизации в Download Station." "$KB_AUTO"
        return 1
    fi

    list_res=$(curl -s --connect-timeout 10 --max-time 20 \
        "http://localhost:5000/webapi/DownloadStation/task.cgi?api=SYNO.DownloadStation.Task&version=1&method=list&additional=transfer&_sid=$sid")
    ds_logout "$sid"

    : > "$DS_TASK_MAP"
    local count
    count=$(echo "$list_res" | jq -r '.data.tasks | length // 0' 2>/dev/null)

    if [ "${count:-0}" -eq 0 ]; then
        send_msg "📥 <b>Download Station: очередь пуста.</b>"$'\n\n'"Отправьте мне <b>magnet-ссылку</b>, <b>URL</b> или <b>.torrent файл</b> для загрузки." "$KB_AUTO"
        return 0
    fi

    local msg="📥 <b>Очередь Download Station ($count):</b>"
    local idx=1
    while IFS=$'\t' read -r tid title status size dl_size speed; do
        [ -z "$tid" ] && continue
        echo "${idx}|${tid}|${title}" >> "$DS_TASK_MAP"
        local pct=0
        if [ "${size:-0}" -gt 0 ]; then
            pct=$(( ${dl_size:-0} * 100 / size ))
        fi
        local spd_kb=$(( ${speed:-0} / 1024 ))
        local st_icon="⏳"
        case "$status" in
            downloading) st_icon="⬇️" ;;
            seeding)     st_icon="⬆️" ;;
            finished)    st_icon="✅" ;;
            paused)      st_icon="⏸" ;;
            error)       st_icon="🔴" ;;
        esac
        local short_title="${title:0:45}"
        msg="${msg}"$'\n\n'"$st_icon <b>$(html_escape "$short_title")</b>"
        msg="${msg}"$'\n'"   ├ ${pct}% | ${spd_kb} KB/s | <i>$status</i>"
        if [ "$status" == "paused" ]; then
            msg="${msg}"$'\n'"   └ ▶️ /ds_resume_${idx} | 🗑 /ds_del_${idx}"
        else
            msg="${msg}"$'\n'"   └ ⏸ /ds_pause_${idx} | 🗑 /ds_del_${idx}"
        fi
        idx=$((idx + 1))
        [ "$idx" -gt 15 ] && break
    done < <(echo "$list_res" | jq -r '.data.tasks[] | [.id, .title, .status, (.size // 0), (.additional.transfer.size_downloaded // 0), (.additional.transfer.speed_download // 0)] | @tsv' 2>/dev/null)

    msg="${msg}"$'\n\n'"<i>Чтобы добавить задачу — просто отправьте ссылку или .torrent файл.</i>"
    send_msg "$msg" "$KB_AUTO"
}

ds_task_action() {
    local action="$1"
    local req_idx="$2"
    local line tid title
    line=$(grep "^${req_idx}|" "$DS_TASK_MAP" 2>/dev/null | head -n 1)
    if [ -z "$line" ]; then
        send_msg "❌ Задача #$req_idx не найдена. Откройте очередь заново." "$KB_AUTO"
        return 1
    fi
    IFS='|' read -r _ tid title <<< "$line"

    local login_res sid res
    login_res=$(ds_login)
    sid=$(echo "$login_res" | jq -r '.data.sid // empty')
    if [ -z "$sid" ]; then
        send_msg "❌ Ошибка авторизации в Download Station." "$KB_AUTO"
        return 1
    fi

    res=$(curl -s --connect-timeout 10 --max-time 20 -X POST "http://localhost:5000/webapi/DownloadStation/task.cgi" \
        -d "api=SYNO.DownloadStation.Task" \
        -d "version=1" \
        -d "method=$action" \
        -d "id=$tid" \
        -d "_sid=$sid")
    ds_logout "$sid"

    if echo "$res" | grep -q '"success":true'; then
        send_msg "✅ Действие <b>$action</b> выполнено для:"$'\n'"<code>$(html_escape "${title:0:60}")</code>" "$KB_AUTO"
    else
        send_msg "⚠️ Ошибка <b>$action</b>:"$'\n'"<code>$(html_escape "$res")</code>" "$KB_AUTO"
    fi
}

check_ssl_certs() {
    local now_ts=$(date +%s)
    local msg="🔐 <b>SSL-сертификаты DSM:</b>"
    local found=0
    local seen=""

    for cert in /usr/syno/etc/certificate/_archive/*/cert.pem /usr/syno/etc/certificate/system/default/cert.pem; do
        [ -f "$cert" ] || continue
        local end_date end_ts days_left subj icon
        subj=$(openssl x509 -subject -noout -in "$cert" 2>/dev/null | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p')
        [ -z "$subj" ] && subj="$(basename "$(dirname "$cert")")"
        [[ "$seen" == *"|$subj|"* ]] && continue
        seen="${seen}|${subj}|"

        end_date=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2)
        end_ts=$(date -d "$end_date" +%s 2>/dev/null)
        [ -z "$end_ts" ] && continue
        days_left=$(( (end_ts - now_ts) / 86400 ))

        if [ "$days_left" -le 7 ]; then icon="🔴"
        elif [ "$days_left" -le 14 ]; then icon="🟡"
        else icon="🟢"; fi

        msg="${msg}"$'\n'"$icon <b>$(html_escape "$subj")</b> — <b>${days_left} дн.</b> (до $(date -d "$end_date" '+%d.%m.%Y' 2>/dev/null))"
        found=1
    done

    [ "$found" -eq 0 ] && msg="${msg}"$'\n'"(Сертификаты не найдены)"
    send_msg "$msg" "$KB_SYSTEM"
}


HB_MAP_FILE="/tmp/syno_hb_tasks.txt"
SCHED_MAP_FILE="/tmp/syno_sched_tasks.txt"

show_hyper_backup() {
    local hb_conf="/usr/syno/etc/synobackup.conf"
    : > "$HB_MAP_FILE"
    if [ ! -f "$hb_conf" ]; then
        send_msg "⚠️ Конфигурация Hyper Backup (<code>$hb_conf</code>) не найдена." "$KB_AUTO"
        return 1
    fi

    local msg="📦 <b>Задачи Hyper Backup:</b>"
    local cur_id="" cur_name=""
    local found=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^\[task_([0-9]+)\] ]]; then
            cur_id="${BASH_REMATCH[1]}"
            cur_name=""
        elif [ -n "$cur_id" ] && [[ "$line" =~ ^name=\"(.*)\" ]]; then
            cur_name="${BASH_REMATCH[1]}"
            echo "${cur_id}|${cur_name}" >> "$HB_MAP_FILE"
            msg="${msg}"$'\n'"🔹 <b>$(html_escape "$cur_name")</b> (ID: $cur_id)"$'\n'"   └ ▶️ Запустить: /hb_run_${cur_id}"
            found=1
            cur_id=""
        fi
    done < "$hb_conf"

    if [ "$found" -eq 0 ]; then
        msg="${msg}"$'\n'"(Настроенные задачи не найдены)"
    fi
    send_msg "$msg" "$KB_AUTO"
}

show_scheduler_tasks() {
    : > "$SCHED_MAP_FILE"
    if ! command -v synoschedtask >/dev/null 2>&1; then
        send_msg "❌ Утилита <code>synoschedtask</code> не найдена." "$KB_AUTO"
        return 1
    fi

    local raw
    raw=$(synoschedtask --get 2>/dev/null)
    local msg="⏱ <b>Планировщик задач DSM:</b>"
    local cur_id="" cur_name="" cur_state=""
    local found=0

    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*ID:[[:space:]]*\[([0-9]+)\] ]]; then
            cur_id="${BASH_REMATCH[1]}"
            cur_name=""
            cur_state=""
        elif [[ "$line" =~ ^[[:space:]]*Name:[[:space:]]*\[(.*)\] ]]; then
            cur_name="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^[[:space:]]*State:[[:space:]]*\[(.*)\] ]]; then
            cur_state="${BASH_REMATCH[1]}"
            if [ -n "$cur_id" ] && [ -n "$cur_name" ]; then
                echo "${cur_id}|${cur_name}" >> "$SCHED_MAP_FILE"
                local st_ic="🟢"
                [[ "$cur_state" != "enabled" ]] && st_ic="⚪️"
                msg="${msg}"$'\n'"$st_ic <b>$(html_escape "$cur_name")</b> (ID: $cur_id)"$'\n'"   └ ▶️ Запустить: /sched_run_${cur_id}"
                found=1
            fi
            cur_id=""
        fi
    done <<< "$raw"

    if [ "$found" -eq 0 ]; then
        msg="${msg}"$'\n'"(Задачи не найдены)"
    elif [ ${#msg} -gt 3800 ]; then
        msg="${msg:0:3800}..."$'\n'"<i>(Список обрезан)</i>"
    fi
    send_msg "$msg" "$KB_AUTO"
}

# Запуск фоновых мониторов
watch_sys_logs &
watch_pkg_logs &
watch_docker_logs &
watch_ssh_logs &
watch_web_logs &
watch_folder_daemon &
watch_health_daemon &

echo "🚀 Бот запущен (PID: $$)..."
send_msg "✅ <b>SynoBot v2.3 запущен!</b>"$'\n'"Привет, Босс." "$KB_MAIN"

# ==========================================
# 🔁 ГЛАВНЫЙ ЦИКЛ ОПРОСА
# ==========================================
while true; do
    UPDATES=$(curl -s --connect-timeout 10 --max-time 40 "$URL/getUpdates?offset=$OFFSET&timeout=30")

    if [ -z "$UPDATES" ] || [ "$(echo "$UPDATES" | jq -r '.ok' 2>/dev/null)" != "true" ]; then
        sleep 5
        continue
    fi

    echo "$UPDATES" | jq -c '.result[]' | while read -r UPDATE; do
        CHAT_ID=$(echo "$UPDATE" | jq -r '.message.chat.id // empty')
        TEXT=$(echo "$UPDATE" | jq -r '.message.text // empty')
        DOC_ID=$(echo "$UPDATE" | jq -r '.message.document.file_id // empty')
        DOC_NAME=$(echo "$UPDATE" | jq -r '.message.document.file_name // empty')

        [ "$CHAT_ID" != "$ADMIN_ID" ] && continue

        # --- ПРИЕМ .TORRENT ФАЙЛОВ ---
        if [ -n "$DOC_ID" ] && [[ "$DOC_NAME" == *.torrent ]]; then
            send_action
            send_msg "⏳ Загружаю торрент <code>$(html_escape "$DOC_NAME")</code> в Download Station..." ""
            FILE_PATH=$(curl -s --connect-timeout 10 --max-time 20 "$URL/getFile?file_id=$DOC_ID" | jq -r '.result.file_path // empty')
            if [ -n "$FILE_PATH" ]; then
                TMP_TORRENT="/tmp/syno_bot_${RANDOM}.torrent"
                curl -s --connect-timeout 10 --max-time 30 "$FILE_URL/$FILE_PATH" -o "$TMP_TORRENT"
                LOGIN_RES=$(ds_login)
                SID=$(echo "$LOGIN_RES" | jq -r '.data.sid // empty')
                if [ -n "$SID" ]; then
                    TASK_RES=$(curl -s --connect-timeout 10 --max-time 30 -X POST "http://localhost:5000/webapi/DownloadStation/task.cgi?_sid=$SID" \
                        -F "api=SYNO.DownloadStation.Task" \
                        -F "version=3" \
                        -F "method=create" \
                        -F "destination=$DL_FOLDER" \
                        -F "file=@$TMP_TORRENT;filename=$DOC_NAME")
                    if echo "$TASK_RES" | grep -q '"success":true'; then
                        send_msg "✅ <b>Торрент добавлен!</b>"$'\n'"📄 <code>$(html_escape "$DOC_NAME")</code>"$'\n'"📁 Папка: <code>$DL_FOLDER</code>" "$KB_AUTO"
                    else
                        send_msg "⚠️ <b>Ошибка Download Station:</b>"$'\n'"<code>$(html_escape "$TASK_RES")</code>" "$KB_AUTO"
                    fi
                    ds_logout "$SID"
                else
                    send_msg "❌ <b>Ошибка авторизации в Download Station:</b>"$'\n'"<code>$(html_escape "$LOGIN_RES")</code>" "$KB_AUTO"
                fi
                rm -f "$TMP_TORRENT"
            else
                send_msg "❌ Не удалось получить файл из Telegram." "$KB_AUTO"
            fi
            continue
        fi

        [ -z "$TEXT" ] && continue

        # --- ПОДТВЕРЖДЕНИЕ ПЕРЕЗАГРУЗКИ ---
        if [ -f /tmp/syno_reboot.lock ]; then
            EXPECTED_CODE=$(cat /tmp/syno_reboot.lock)
            rm -f /tmp/syno_reboot.lock
            if [ "$TEXT" == "$EXPECTED_CODE" ]; then
                send_action
                send_msg "🔄 <b>Код $EXPECTED_CODE принят!</b> NAS уходит в перезагрузку..." "$KB_MAIN"
                sleep 3
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

            "🔔 Уведомления")
                show_notify_menu
                ;;

            /mute_*)
                M_KEY="${TEXT#"/mute_"}"
                case "$M_KEY" in
                    sys|pkg|docker|ssh|web|health)
                        if is_muted "$M_KEY"; then
                            rm -f "$MUTE_DIR/$M_KEY.muted"
                        else
                            touch "$MUTE_DIR/$M_KEY.muted"
                        fi
                        show_notify_menu
                        ;;
                esac
                ;;

            "/status" | "📊 Статус")
                send_action
                UPTIME=$(uptime -p 2>/dev/null | sed 's/up //' || uptime | awk -F'up ' '{print $2}' | awk -F',' '{print $1}')

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
                    [ -z "$line" ] && continue
                    VOL=$(echo "$line" | awk '{print $6}')
                    PERC=$(echo "$line" | awk '{print $5}')
                    FREE=$(echo "$line" | awk '{print $4}')
                    DISK_INFO="${DISK_INFO}"$'\n'"💾 <b>$VOL</b>: $PERC (Своб: $FREE)"
                done <<< "$(df -h | grep "^/dev/" | grep "/volume" | grep -vE "@|docker|snap")"

                HDD_TEMPS=""
                for disk in /dev/sd[a-z] /dev/sata[0-9]* /dev/nvme[0-9]n[0-9]; do
                    [ -e "$disk" ] || continue
                    [[ "$disk" == *p[0-9]* ]] && continue
                    DISK_NAME=$(basename "$disk")

                    if [[ "$disk" == /dev/nvme* ]]; then
                        TEMP_HDD=$(smartctl -A "$disk" 2>/dev/null | awk '/^Temperature:/ {print $2; exit}')
                    else
                        TEMP_HDD=$(smartctl -A -d sat "$disk" 2>/dev/null | grep -iE "Temperature_Celsius|Temperature_Internal|Airflow_Temperature_Cel" | awk '{print $10}' | head -n 1)
                    fi

                    if [ -n "$TEMP_HDD" ]; then
                        HDD_TEMPS="${HDD_TEMPS} $DISK_NAME:<b>${TEMP_HDD}°C</b> |"
                    else
                        HDD_TEMPS="${HDD_TEMPS} $DISK_NAME:<b>N/A</b> |"
                    fi
                done

                RAID_INFO=$(get_raid_summary)
                UPS_INFO=$(get_ups_info)

                STATUS_MSG="🖥 <b>System Info</b>
⏱ Up: <code>$UPTIME</code>
🌡 CPU: <code>$CPU_TEMP</code>
🧠 RAM: ${MEM_USED}MB / ${MEM_TOTAL}MB"
                [ -n "$UPS_INFO" ] && STATUS_MSG="${STATUS_MSG}"$'\n'"$UPS_INFO"
                STATUS_MSG="${STATUS_MSG}
------------------${DISK_INFO}
------------------
🌡 <b>Диски:</b>
${HDD_TEMPS%|}"
                [ -n "$RAID_INFO" ] && STATUS_MSG="${STATUS_MSG}"$'\n'"------------------"$'\n'"🛡 <b>RAID:</b>${RAID_INFO}"

                send_msg "$STATUS_MSG" "$KB_SYSTEM"
                ;;

            "🔄 Перезагрузка")
                REBOOT_CODE=$((RANDOM % 9000 + 1000))
                echo "$REBOOT_CODE" > /tmp/syno_reboot.lock
                send_action
                send_msg "⚠️ <b>ПОДТВЕРЖДЕНИЕ ПЕРЕЗАГРУЗКИ</b> ⚠️

Вы точно хотите перезагрузить NAS?
Если да, отправьте мне в ответ этот код:
<code>$REBOOT_CODE</code>

<i>(Для отмены просто нажмите любую кнопку в меню)</i>" "$KB_SYSTEM"
                ;;

            "/ip" | "🌐 Сеть")
                send_action
                EXT_IP=$(curl -s --connect-timeout 5 -4 https://api.ipify.org)

                DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | paste -sd ", " -)
                [ -z "$DNS_SERVERS" ] && DNS_SERVERS="Не задан"

                GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -n 1)
                [ -z "$GATEWAY" ] && GATEWAY="Не задан"

                IFACE_INFO=""
                while read -r line; do
                    [ -z "$line" ] && continue
                    IFNAME=$(echo "$line" | awk -F': ' '{print $2}' | cut -d'@' -f1)
                    STATE=$(echo "$line" | grep -o "state [A-Z]*" | awk '{print $2}')
                    IP_WITH_MASK=$(ip -4 addr show "$IFNAME" 2>/dev/null | grep -w "inet" | awk '{print $2}' | head -n 1)

                    if [ "$STATE" == "UP" ]; then ICON="🟢"
                    elif [ "$STATE" == "UNKNOWN" ]; then ICON="🟡"
                    else ICON="🔴"; fi

                    if [ -n "$IP_WITH_MASK" ]; then
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: <code>$IP_WITH_MASK</code>"
                    else
                        IFACE_INFO="${IFACE_INFO}"$'\n'"$ICON <b>$IFNAME</b>: (нет IP)"
                    fi
                done <<< "$(ip -o link show | grep -vE "lo|docker|veth|br-")"

                send_msg "🌐 <b>Сетевая информация:</b>
🌍 <b>WAN IP:</b> <code>${EXT_IP:-N/A}</code>
🧭 <b>Шлюз:</b> <code>$GATEWAY</code>
🗄 <b>DNS:</b> <code>$DNS_SERVERS</code>
$IFACE_INFO" "$KB_SYSTEM"
                ;;

            "🏥 S.M.A.R.T.")
                send_action
                MSG="🏥 <b>Выберите диск для проверки:</b>"
                for disk in /dev/sd[a-z] /dev/sata[0-9]* /dev/nvme[0-9]n[0-9]; do
                    [ -e "$disk" ] || continue
                    [[ "$disk" == *p[0-9]* ]] && continue
                    DISK_NAME=$(basename "$disk")
                    if [[ "$disk" == /dev/nvme* ]]; then
                        MSG="${MSG}"$'\n'"⚡ <b>$DISK_NAME</b> (NVMe) — /smart_$DISK_NAME"
                    else
                        MSG="${MSG}"$'\n'"💿 <b>$DISK_NAME</b> — /smart_$DISK_NAME"
                    fi
                done
                send_msg "$MSG" "$KB_SYSTEM"
                ;;

            /smart_*)
                DISK_DEV="/dev/${TEXT#"/smart_"}"
                if [ -e "$DISK_DEV" ]; then
                    send_action
                    send_msg "⏳ Считываю S.M.A.R.T. для <b>$DISK_DEV</b>..." ""

                    if [[ "$DISK_DEV" == /dev/nvme* ]]; then
                        SMART_ALL=$(smartctl -a "$DISK_DEV" 2>/dev/null)
                        HEALTH=$(echo "$SMART_ALL" | awk -F': ' '/SMART overall-health/ {print $2}')
                        MODEL=$(echo "$SMART_ALL" | awk -F': *' '/Model Number:/ {print $2}')
                        SERIAL=$(echo "$SMART_ALL" | awk -F': *' '/Serial Number:/ {print $2}')
                        TEMP=$(echo "$SMART_ALL" | awk '/^Temperature:/ {print $2; exit}')
                        WEAR=$(echo "$SMART_ALL" | awk -F': *' '/Percentage Used:/ {print $2}')
                        HOURS=$(echo "$SMART_ALL" | awk -F': *' '/Power On Hours:/ {print $2}')
                        MEDIA_ERR=$(echo "$SMART_ALL" | awk -F': *' '/Media and Data Integrity Errors:/ {print $2}')

                        send_msg "🏥 <b>NVMe Отчет $DISK_DEV</b>
🏷 <b>Модель:</b> $(html_escape "${MODEL:-N/A}")
🔢 <b>Серийный:</b> $(html_escape "${SERIAL:-N/A}")
Health Status: <b>${HEALTH:-N/A}</b>

🔥 Температура: <b>${TEMP:-N/A}°C</b>
⏳ Часы работы: <b>${HOURS:-N/A}ч</b>
📉 Износ: <b>${WEAR:-N/A}</b>
💀 Ошибки медиа: <b>${MEDIA_ERR:-0}</b>" "$KB_SYSTEM"
                    else
                        HEALTH=$(smartctl -H -d sat "$DISK_DEV" 2>/dev/null | grep "test result" | awk -F': ' '{print $2}')
                        MODEL=$(smartctl -i -d sat "$DISK_DEV" 2>/dev/null | grep "Device Model" | awk -F': ' '{print $2}')
                        SERIAL=$(smartctl -i -d sat "$DISK_DEV" 2>/dev/null | grep "Serial Number" | awk -F': ' '{print $2}')

                        ATTRS=$(smartctl -A -d sat "$DISK_DEV" 2>/dev/null)
                        BAD_SECTORS=$(echo "$ATTRS" | grep -w "5 Reallocated_Sector_Ct" | awk '{print $10}')
                        PENDING=$(echo "$ATTRS" | grep -w "197 Current_Pending_Sector" | awk '{print $10}')
                        HOURS=$(echo "$ATTRS" | grep -w "9 Power_On_Hours" | awk '{print $10}')
                        TEMP=$(echo "$ATTRS" | grep -iE "Temperature_Celsius|Temperature_Internal|Airflow_Temperature_Cel" | awk '{print $10}' | head -n 1)

                        send_msg "🏥 <b>Отчет $DISK_DEV</b>
🏷 <b>Модель:</b> $(html_escape "${MODEL:-N/A}")
🔢 <b>Серийный:</b> $(html_escape "${SERIAL:-N/A}")
Health Status: <b>${HEALTH:-N/A}</b>

🔥 Температура: <b>${TEMP:-N/A}°C</b>
⏳ Часы работы: <b>${HOURS:-N/A}ч</b>
💀 Битые сектора: <b>${BAD_SECTORS:-0}</b>
⚠️ Ожидают переназначения: <b>${PENDING:-0}</b>" "$KB_SYSTEM"
                    fi
                else
                    send_msg "❌ Диск не найден." "$KB_SYSTEM"
                fi
                ;;

            "/firewall_off" | "🔥 Firewall Off")
                synofirewall --disable && send_msg "🔥 Firewall OFF." "$KB_SYSTEM"
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
                if ! command -v docker >/dev/null 2>&1; then
                    send_msg "❌ Docker не установлен." "$KB_AUTO"
                    continue
                fi
                D_MSG="🐳 <b>Контейнеры:</b>"
                EXISTING=$(docker ps -a --format "{{.Names}}|{{.State}}")
                while IFS='|' read -r name state; do
                    [ -z "$name" ] && continue
                    if [ "$state" == "running" ]; then
                        D_MSG="${D_MSG}"$'\n'"🟢 <b>$(html_escape "$name")</b>"$'\n'"   └ /restart_$name | /stop_$name | /logs_$name"
                    else
                        D_MSG="${D_MSG}"$'\n'"🔴 <b>$(html_escape "$name")</b>"$'\n'"   └ /start_$name | /logs_$name"
                    fi
                done <<< "$EXISTING"
                D_MSG="${D_MSG}"$'\n\n'"🔄 Обновить Compose-проекты: /compose"$'\n'"🧹 Очистить неиспользуемые образы: /docker_prune"
                send_msg "$D_MSG" "$KB_AUTO"
                ;;

            "/docker_prune")
                send_action
                PRUNE_OUT=$(docker image prune -f 2>&1 | tail -n 5)
                send_msg "🧹 <b>Docker Prune выполнен:</b>"$'\n'"<code>$(html_escape "$PRUNE_OUT")</code>" "$KB_AUTO"
                ;;

            "/compose" | "🔄 Обновить Compose")
                send_action
                if ! command -v docker >/dev/null 2>&1; then
                    send_msg "❌ Docker не установлен." "$KB_AUTO"
                    continue
                fi
                scan_compose_projects
                if [ ! -s "$COMPOSE_LIST_FILE" ]; then
                    send_msg "⚠️ <b>Docker Compose проекты не найдены.</b>"$'\n'"<i>(Ищу проекты по меткам запущенных/остановленных контейнеров Container Manager / docker compose)</i>" "$KB_AUTO"
                else
                    C_MSG="🔄 <b>Найденные Docker Compose проекты:</b>"
                    while IFS='|' read -r idx proj wdir cfile; do
                        C_MSG="${C_MSG}"$'\n\n'"📦 <b>$(html_escape "$proj")</b>"$'\n'"   ├ <code>$(html_escape "$wdir")</code>"$'\n'"   └ Обновить: /cup_$idx"
                    done < "$COMPOSE_LIST_FILE"
                    C_MSG="${C_MSG}"$'\n\n'"🚀 <b>Обновить ВСЕ проекты сразу:</b> /cup_all"
                    send_msg "$C_MSG" "$KB_AUTO"
                fi
                ;;

            "/cup_all")
                send_action
                scan_compose_projects
                if [ ! -s "$COMPOSE_LIST_FILE" ]; then
                    send_msg "⚠️ Проекты Compose не найдены." "$KB_AUTO"
                else
                    send_msg "⏳ <b>Запускаю обновление всех Compose-проектов в фоне...</b>"$'\n'"По завершении каждого пришлю отчет." "$KB_AUTO"
                    (
                        while IFS='|' read -r idx proj wdir cfile; do
                            run_compose_update "$proj" "$wdir" "$cfile"
                        done < "$COMPOSE_LIST_FILE"
                        send_msg "🏁 <b>Обновление всех Compose-проектов завершено!</b>" "$KB_AUTO"
                    ) &
                fi
                ;;

            /cup_[0-9]*)
                send_action
                REQ_IDX="${TEXT#"/cup_"}"
                [ ! -s "$COMPOSE_LIST_FILE" ] && scan_compose_projects
                LINE=$(grep "^${REQ_IDX}|" "$COMPOSE_LIST_FILE" | head -n 1)
                if [ -z "$LINE" ]; then
                    send_msg "❌ Проект с номером <code>$REQ_IDX</code> не найден. Откройте «🔄 Обновить Compose» заново." "$KB_AUTO"
                else
                    IFS='|' read -r idx proj wdir cfile <<< "$LINE"
                    send_msg "⏳ <b>Обновляю проект $(html_escape "$proj")...</b>"$'\n'"Выполняю <code>docker compose pull && up -d</code> в фоне." "$KB_AUTO"
                    ( run_compose_update "$proj" "$wdir" "$cfile" ) &
                fi
                ;;


            /logs_*)
                send_action
                C_NAME="${TEXT#"/logs_"}"
                LOGS_OUT=$(docker logs --tail 25 "$C_NAME" 2>&1)
                [ -z "$LOGS_OUT" ] && LOGS_OUT="(логи пусты)"
                if [ ${#LOGS_OUT} -gt 3500 ]; then
                    LOGS_OUT="${LOGS_OUT: -3500}"
                fi
                send_msg "📜 <b>Логи $(html_escape "$C_NAME") (последние 25 строк):</b>"$'\n'"<code>$(html_escape "$LOGS_OUT")</code>" "$KB_AUTO"
                ;;

            /stop_*)
                send_action
                C_NAME="${TEXT#"/stop_"}"
                docker stop "$C_NAME" >/dev/null 2>&1 && send_msg "⏹ Контейнер <b>$(html_escape "$C_NAME")</b> остановлен." "$KB_AUTO" || send_msg "❌ Ошибка остановки $C_NAME" "$KB_AUTO"
                ;;

            /restart_*)
                send_action
                C_NAME="${TEXT#"/restart_"}"
                docker restart "$C_NAME" >/dev/null 2>&1 && send_msg "✅ Рестарт <b>$(html_escape "$C_NAME")</b> OK" "$KB_AUTO" || send_msg "❌ Ошибка рестарта $C_NAME" "$KB_AUTO"
                ;;

            /start_*)
                send_action
                C_NAME="${TEXT#"/start_"}"
                docker start "$C_NAME" >/dev/null 2>&1 && send_msg "🚀 Старт <b>$(html_escape "$C_NAME")</b> OK" "$KB_AUTO" || send_msg "❌ Ошибка старта $C_NAME" "$KB_AUTO"
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

            /pkgrestart_*)
                synopkg restart "${TEXT#"/pkgrestart_"}" >/dev/null && send_msg "✅ Пакет перезагружен" "$KB_AUTO"
                ;;

            /pkgstart_*)
                synopkg start "${TEXT#"/pkgstart_"}" >/dev/null && send_msg "🚀 Пакет запущен" "$KB_AUTO"
                ;;

            "📥 Загрузки (Download Station)" | "/ds")
                send_action
                show_ds_queue
                ;;

            /ds_pause_[0-9]*)
                send_action
                ds_task_action "pause" "${TEXT#"/ds_pause_"}"
                ;;

            /ds_resume_[0-9]*)
                send_action
                ds_task_action "resume" "${TEXT#"/ds_resume_"}"
                ;;

            /ds_del_[0-9]*)
                send_action
                ds_task_action "delete" "${TEXT#"/ds_del_"}"
                ;;

            "🔐 SSL" | "/ssl")
                send_action
                check_ssl_certs
                ;;

            "💾 Бэкап DSM" | "/dsm_backup")
                send_action
                send_msg "⏳ Экспортирую конфигурацию DSM (.dss)..." ""
                DSS_FILE="/tmp/DSM_Config_$(hostname)_$(date '+%Y-%m-%d_%H-%M').dss"
                if /usr/syno/bin/synoconfbkp export --filepath="$DSS_FILE" >/dev/null 2>&1 && [ -f "$DSS_FILE" ]; then
                    send_doc "$DSS_FILE" "💾 <b>Бэкап конфигурации DSM</b> ($(hostname))" "$KB_SYSTEM"
                    rm -f "$DSS_FILE"
                else
                    send_msg "❌ Не удалось экспортировать конфигурацию DSM." "$KB_SYSTEM"
                fi
                ;;

            "📂 Топ папок (/du)" | "/du")
                send_action
                send_msg "⏳ Сканирую <code>/volume1</code> (может занять 10–30 сек)..." ""
                DU_OUT=$(du -hx --max-depth=2 /volume1 2>/dev/null | sort -rh | head -n 12)
                [ -z "$DU_OUT" ] && DU_OUT="(нет данных)"
                send_msg "📂 <b>Топ-12 тяжелых папок (/volume1):</b>"$'\n'"<code>$(html_escape "$DU_OUT")</code>"$'\n\n'"<i>Можно указать любой путь:</i> <code>/du /volume1/docker</code>" "$KB_SYSTEM"
                ;;

            "/du "*)
                send_action
                DU_PATH="${TEXT#"/du "}"
                if [ -d "$DU_PATH" ]; then
                    send_msg "⏳ Сканирую <code>$(html_escape "$DU_PATH")</code>..." ""
                    DU_OUT=$(du -hx --max-depth=2 "$DU_PATH" 2>/dev/null | sort -rh | head -n 12)
                    [ -z "$DU_OUT" ] && DU_OUT="(нет данных)"
                    send_msg "📂 <b>Топ-12 папок ($(html_escape "$DU_PATH")):</b>"$'\n'"<code>$(html_escape "$DU_OUT")</code>" "$KB_SYSTEM"
                else
                    send_msg "❌ Папка <code>$(html_escape "$DU_PATH")</code> не найдена." "$KB_SYSTEM"
                fi
                ;;

            "📦 Hyper Backup" | "/hb")
                send_action
                show_hyper_backup
                ;;

            /hb_run_[0-9]*)
                send_action
                HB_ID="${TEXT#"/hb_run_"}"
                HB_BIN="/var/packages/HyperBackup/target/bin/dsmbackup"
                if [ -x "$HB_BIN" ]; then
                    "$HB_BIN" --backup "$HB_ID" >/dev/null 2>&1 &
                    send_msg "🚀 <b>Задача Hyper Backup #$HB_ID запущена!</b>"$'\n'"Уведомление о завершении придет автоматически." "$KB_AUTO"
                else
                    send_msg "❌ Бинарник Hyper Backup (<code>$HB_BIN</code>) не найден." "$KB_AUTO"
                fi
                ;;

            "⏱ Планировщик" | "/sched")
                send_action
                show_scheduler_tasks
                ;;

            /sched_run_[0-9]*)
                send_action
                SC_ID="${TEXT#"/sched_run_"}"
                synoschedtask --run id="$SC_ID" >/dev/null 2>&1 &
                send_msg "🚀 <b>Задача Планировщика #$SC_ID запущена в фоне!</b>" "$KB_AUTO"
                ;;


            "🗑 Корзины" | "/recycle")
                send_action
                R_MSG="🗑 <b>Сетевые корзины (#recycle):</b>"
                FOUND_R=0
                while read -r rdir; do
                    [ -z "$rdir" ] && continue
                    R_SIZE=$(du -sh "$rdir" 2>/dev/null | awk '{print $1}')
                    R_MSG="${R_MSG}"$'\n'"📁 <code>$(html_escape "$rdir")</code> — <b>${R_SIZE:-0}</b>"
                    FOUND_R=1
                done < <(find /volume* -maxdepth 2 -type d -name "#recycle" 2>/dev/null)
                if [ "$FOUND_R" -eq 0 ]; then
                    R_MSG="${R_MSG}"$'\n'"(Корзины не найдены)"
                else
                    R_MSG="${R_MSG}"$'\n\n'"🧹 Очистить все корзины: /recycle_clean"
                fi
                send_msg "$R_MSG" "$KB_SYSTEM"
                ;;

            "/recycle_clean")
                send_action
                send_msg "⏳ Очищаю сетевые корзины..." ""
                find /volume* -maxdepth 2 -type d -name "#recycle" 2>/dev/null | while read -r rdir; do
                    rm -rf "${rdir:?}"/* "${rdir:?}"/.[!.]* "${rdir:?}"/..?* 2>/dev/null
                done
                send_msg "✅ <b>Все сетевые корзины (#recycle) очищены!</b>" "$KB_SYSTEM"
                ;;

            "🤖 Бот")
                send_msg "🤖 <b>Управление SynoBot v2.3</b>

🔄 Перезапустить бота: /bot_restart
⬆️ Обновить с GitHub: /bot_update
🔗 Задать URL репозитория:
<code>/set_repo https://raw.githubusercontent.com/.../syno_bot.sh</code>

Текущий URL: <code>${BOT_REPO_URL:-не задан}</code>" "$KB_MAIN"
                ;;

            "/set_repo "*)
                NEW_URL="${TEXT#"/set_repo "}"
                sed -i '/^BOT_REPO_URL=/d' "$CONFIG_FILE"
                echo "BOT_REPO_URL=\"$NEW_URL\"" >> "$CONFIG_FILE"
                BOT_REPO_URL="$NEW_URL"
                send_msg "✅ URL обновления сохранен:"$'\n'"<code>$(html_escape "$BOT_REPO_URL")</code>" "$KB_MAIN"
                ;;

            "/bot_restart")
                send_msg "🔄 <b>Перезапускаю SynoBot...</b>" "$KB_MAIN"
                sleep 1
                exec "$SCRIPT_PATH"
                ;;

            "/bot_update")
                if [ -z "$BOT_REPO_URL" ]; then
                    send_msg "⚠️ Сначала задайте ссылку на скрипт командой:"$'\n'"<code>/set_repo https://raw.githubusercontent.com/.../syno_bot.sh</code>" "$KB_MAIN"
                else
                    send_action
                    TMP_UP="/tmp/synobot_update.sh"
                    if curl -fsSL --connect-timeout 10 --max-time 30 "$BOT_REPO_URL" -o "$TMP_UP"; then
                        sed -i 's/
$//' "$TMP_UP"
                        if bash -n "$TMP_UP" 2>/dev/null; then
                            cp "$TMP_UP" "$SCRIPT_PATH"
                            chmod +x "$SCRIPT_PATH"
                            rm -f "$TMP_UP"
                            send_msg "✅ <b>Скрипт обновлен!</b> Перезапускаюсь..." "$KB_MAIN"
                            sleep 1
                            exec "$SCRIPT_PATH"
                        else
                            rm -f "$TMP_UP"
                            send_msg "❌ Ошибка синтаксиса в скачанном файле. Обновление отменено." "$KB_MAIN"
                        fi
                    else
                        send_msg "❌ Не удалось скачать обновление по ссылке." "$KB_MAIN"
                    fi
                fi
                ;;

            "http"* | "magnet:"*)
                send_action
                send_msg "⏳ Отправляю ссылку на NAS..." ""
                LOGIN_RES=$(ds_login)
                SID=$(echo "$LOGIN_RES" | jq -r '.data.sid // empty')

                if [ -n "$SID" ]; then
                    TASK_RES=$(curl -s --connect-timeout 10 --max-time 20 -X POST "http://localhost:5000/webapi/DownloadStation/task.cgi" \
                        -d "api=SYNO.DownloadStation.Task" \
                        -d "version=3" \
                        -d "method=create" \
                        --data-urlencode "uri=$TEXT" \
                        --data-urlencode "destination=$DL_FOLDER" \
                        -d "_sid=$SID")

                    if echo "$TASK_RES" | grep -q '"success":true'; then
                        send_msg "✅ <b>ГОТОВО!</b> Ссылка добавлена в очередь NAS в папку: <code>$DL_FOLDER</code>." "$KB_AUTO"
                    else
                        send_msg "⚠️ <b>Ошибка Download Station:</b>"$'\n'"<code>$(html_escape "$TASK_RES")</code>"$'\n\n'"<i>Папка: $DL_FOLDER</i>" "$KB_AUTO"
                    fi
                    ds_logout "$SID"
                else
                    send_msg "❌ <b>Ошибка авторизации:</b>"$'\n'"<code>$(html_escape "$LOGIN_RES")</code>" "$KB_AUTO"
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
                send_msg "⏳ Сбрасываю 2FA для пользователя <b>$(html_escape "$TARGET_USER")</b>..." ""

                synowebapi -s --exec api=SYNO.Core.OTP.EnforcePolicy method=set version=1 enable_otp_enforcement=false otp_enforce_option=\"none\" >/dev/null 2>&1
                synowebapi -s --exec api=SYNO.SecureSignIn.AMFA.Policy method=set version=1 type=\"none\" >/dev/null 2>&1
                synowebapi -s --exec api=SYNO.SecureSignIn.Method.Admin method=reset version=1 account=\"$TARGET_USER\" keep_amfa_settings=true >/dev/null 2>&1

                PREF_FILE="/usr/syno/etc/packages/SecureSignIn/preference/${TARGET_USER}/method.config"
                [ -f "$PREF_FILE" ] && sed -i "s|status=on|status=off|g" "$PREF_FILE"

                CONF_FILE="/usr/syno/etc/packages/SecureSignIn/secure_signin.conf"
                [ -f "$CONF_FILE" ] && sed -i "s|list=.*$|list=|; s|type=.*$|type=none|" "$CONF_FILE"

                send_msg "✅ <b>Готово!</b>
Двухфакторная аутентификация для <b>$(html_escape "$TARGET_USER")</b> отключена.
Теперь вы можете войти в DSM только по паролю." "$KB_SYSTEM"
                ;;

            "🛡 Разбан IP")
                send_action
                if [ -f "/etc/synoautoblock.db" ]; then
                    BANNED_LIST=$(sqlite3 /etc/synoautoblock.db "SELECT IP FROM AutoBlockIP;" 2>/dev/null)
                    sqlite3 /etc/synoautoblock.db "DELETE FROM AutoBlockIP;" >/dev/null 2>&1
                    # Точечно удаляем только правила DROP для забаненных IP, не снося весь файрвол DSM
                    while read -r bip; do
                        [ -z "$bip" ] && continue
                        while iptables -D INPUT -s "$bip" -j DROP 2>/dev/null; do :; done
                    done <<< "$BANNED_LIST"

                    send_msg "✅ <b>Блокировки сняты безопасно!</b>

База AutoBlock очищена, точечные DROP-правила удалены (правила брандмауэра DSM сохранены)." "$KB_SYSTEM"
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
                LOAD_AVG=$(awk '{print $1", "$2", "$3}' /proc/loadavg)
                TOP_CPU=$(top -b -n 1 2>/dev/null | head -n 12 | tail -n 5)
                [ -z "$TOP_CPU" ] && TOP_CPU="Данные недоступны"

                send_msg "🔥 <b>Нагрузка системы:</b>

📈 <b>Load Average:</b> <code>$LOAD_AVG</code>

💀 <b>Топ-5 процессов (CPU):</b>
<code>$(html_escape "$TOP_CPU")</code>" "$KB_SYSTEM"
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
<code>$(html_escape "$TOP_RAM")</code>" "$KB_SYSTEM"
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
                    SSH_USERS="${SSH_USERS}"$'\n'"🔌 <b>$(html_escape "$USER")</b> (IP: $(html_escape "$IP"))"$'\n'"   └ $KICK_CMD"
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
                        SMB_USERS="${SMB_USERS}"$'\n'"📁 <b>$(html_escape "$USER")</b> (IP: $(html_escape "$IP"))"$'\n'"   └ 🔫 /kick_$PID"
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
                TARGET="${TEXT#"/kick_"}"
                if [[ "$TARGET" =~ ^[0-9]+$ ]]; then
                    ( sleep 1 && kill -9 "$TARGET" ) >/dev/null 2>&1 &
                    send_msg "🔫 SMB/процесс (PID: $TARGET) убит!" "$KB_SYSTEM"
                elif [[ "$TARGET" =~ ^pts_[0-9]+$ ]]; then
                    TTY_DEV="${TARGET//_//}"
                    pkill -9 -t "$TTY_DEV" >/dev/null 2>&1
                    send_msg "🔫 SSH-сессия (<code>$TTY_DEV</code>) разорвана!" "$KB_SYSTEM"
                else
                    send_msg "❌ Некорректный идентификатор сессии." "$KB_SYSTEM"
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
                send_msg "🚀 <b>Закрываю веб-сессию!</b>"$'\n'"ID: <code>$(html_escape "$TARGET_ID")</code>" "$KB_SYSTEM"
                ;;

            "⚡️ Ускорение DSM")
                send_action
                BOOT_TIME=$(tail -n 20 /var/log/synobootup.log 2>/dev/null | grep -iE "took.*second|finish" | tail -n 1 | sed -e 's/^[ \t]*//')
                [ -z "$BOOT_TIME" ] && BOOT_TIME="Данные не найдены"

                MSG="⚡️ <b>Оптимизация скорости DSM (RAID md0)</b>"$'\n'"⏱ <b>Последняя загрузка:</b>"$'\n'"<code>$(html_escape "$BOOT_TIME")</code>"$'\n\n'"💽 <b>Диски в системном разделе:</b>"
                MD_DEVS=$(ls -d /sys/block/md0/md/dev-* 2>/dev/null)
                for dev_path in $MD_DEVS; do
                    dev_name=$(basename "$dev_path" | sed 's/dev-//')
                    real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                    rot=$(cat "/sys/block/$real_dev/queue/rotational" 2>/dev/null)
                    if [ "$rot" == "1" ]; then D_TYPE="HDD 🧲"; elif [ "$rot" == "0" ]; then D_TYPE="SSD ⚡️"; else D_TYPE="???"; fi

                    state=$(cat "$dev_path/state" 2>/dev/null)
                    if echo "$state" | grep -q "write_mostly"; then
                        MSG="${MSG}"$'\n\n'"🐢 <b>$dev_name</b> ($D_TYPE)"$'\n'"   ├ Режим: <b>WriteMostly</b>"$'\n'"   └ Сделать основным: /wmoff_$dev_name"
                    else
                        MSG="${MSG}"$'\n\n'"🚀 <b>$dev_name</b> ($D_TYPE)"$'\n'"   ├ Режим: <b>Normal</b>"$'\n'"   └ Пометить медленным: /wmon_$dev_name"
                    fi
                done
                MSG="${MSG}"$'\n\n'"🤖 <b>Авто:</b>"$'\n'"└ Настроить всё автоматически (если есть SSD): /wmauto"
                send_msg "$MSG" "$KB_SYSTEM"
                ;;

            "/wmauto")
                send_action
                HAS_SSD=0
                MD_DEVS=$(ls -d /sys/block/md0/md/dev-* 2>/dev/null)
                for dev_path in $MD_DEVS; do
                    dev_name=$(basename "$dev_path" | sed 's/dev-//')
                    real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                    if [ "$(cat "/sys/block/$real_dev/queue/rotational" 2>/dev/null)" == "0" ]; then HAS_SSD=1; break; fi
                done

                if [ "$HAS_SSD" == "1" ]; then
                    MSG_LOG="🤖 <b>Авто-оптимизация выполнена!</b>"
                    for dev_path in $MD_DEVS; do
                        dev_name=$(basename "$dev_path" | sed 's/dev-//')
                        real_dev=$(echo "$dev_name" | sed -E 's/p?[0-9]+$//')
                        rot=$(cat "/sys/block/$real_dev/queue/rotational" 2>/dev/null)
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
                    send_msg "⚠️ <b>Авто-режим отменен.</b>"$'\n'"Я не нашел ни одного SSD. Выберите медленные диски вручную в меню." "$KB_SYSTEM"
                fi
                ;;

            /wmon_*)
                send_action
                TARGET_DEV="${TEXT#"/wmon_"}"
                echo writemostly > "/sys/block/md0/md/dev-${TARGET_DEV}/state" 2>/dev/null
                send_msg "✅ <b>Ускорение применено!</b>"$'\n'"Диск <code>$TARGET_DEV</code> помечен как медленный." "$KB_SYSTEM"
                ;;

            /wmoff_*)
                send_action
                TARGET_DEV="${TEXT#"/wmoff_"}"
                echo -writemostly > "/sys/block/md0/md/dev-${TARGET_DEV}/state" 2>/dev/null
                send_msg "🔄 <b>Метка снята.</b>"$'\n'"Диск <code>$TARGET_DEV</code> возвращен в нормальный режим." "$KB_SYSTEM"
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
Папка: <code>$(html_escape "$TARGET_DIR")</code>

Проверяю её каждые 30 секунд. Если появятся новые файлы или кто-то удалит старые — я пришлю отчет.
<i>(Для остановки нажми /watch_stop)</i>" "$KB_AUTO"
                else
                    send_msg "❌ <b>Ошибка:</b> Папки <code>$(html_escape "$TARGET_DIR")</code> не существует на NAS!" "$KB_AUTO"
                fi
                ;;

            "/watch stop" | "/watch_stop")
                send_action
                rm -f /etc/synobot_watch.conf /tmp/watch_dir.old
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

                send_msg "⏳ <b>Запускаю патч...</b>"$'\n'"Режим: <b>$MODE_NAME</b>. Это займет пару секунд." "$KB_AUTO"
                SCRIPT_URL="https://raw.githubusercontent.com/007revad/Synology_enable_Deduplication/main/syno_enable_dedupe.sh"
                curl -sL --connect-timeout 10 --max-time 30 "$SCRIPT_URL" -o /tmp/syno_enable_dedupe.sh

                if [ -f "/tmp/syno_enable_dedupe.sh" ]; then
                    chmod +x /tmp/syno_enable_dedupe.sh
                    OUTPUT=$(bash /tmp/syno_enable_dedupe.sh $FLAGS 2>&1)
                    rm -f /tmp/syno_enable_dedupe.sh

                    if [ ${#OUTPUT} -gt 3500 ]; then
                        OUTPUT="${OUTPUT:0:3500}..."$'\n'"[Лог обрезан]"
                    fi

                    send_msg "✅ <b>Патч успешно отработал!</b>

<b>Лог работы:</b>
<code>$(html_escape "$OUTPUT")</code>

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
                    send_msg "⚠️ <b>Отказ:</b> Банить системный адрес (<code>127.0.0.1</code>) категорически запрещено!" "$KB_SYSTEM"
                else
                    NOW=$(date +%s)
                    sqlite3 /etc/synoautoblock.db "REPLACE INTO AutoBlockIP (IP, RecordTime, ExpireTime, Deny, IPStd, Type, Meta) VALUES ('$BAN_IP', $NOW, 0, 1, '', 0, '');"
                    iptables -I INPUT 1 -s "$BAN_IP" -j DROP
                    send_msg "⛔️ <b>IP ЖЕСТКО ЗАБЛОКИРОВАН!</b>

Адрес <code>$BAN_IP</code> занесен в ЧС.
Ядро сбросило все активные соединения (iptables DROP)." "$KB_SYSTEM"
                fi
                ;;

            "🧠 Тюнинг Ядра")
                send_action
                SWAP_VAL=$(cat /proc/sys/vm/swappiness 2>/dev/null)
                MEM_COMP=$(grep '^mem_compress=' /etc/synoinfo.conf | cut -d'"' -f2)
                [ "$MEM_COMP" == "yes" ] || [ -z "$MEM_COMP" ] && MEM_TXT="🟢 Включено" || MEM_TXT="🔴 Выключено"
                if [ -f "$TUNE_FLAG" ]; then
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
                touch "$TUNE_FLAG"
                send_msg "🚀 <b>Авто включен!</b>"$'\n'"Теперь при каждом запуске бота я сам буду выставлять Swappiness=1." "$KB_AUTO"
                ;;

            "/autotune_off")
                send_action
                rm -f "$TUNE_FLAG"
                send_msg "⚪️ <b>Авто выключен.</b>"$'\n'"Больше не трогаю систему при старте." "$KB_AUTO"
                ;;

            /swap_*)
                send_action
                VAL="${TEXT#"/swap_"}"
                if [[ "$VAL" =~ ^[0-9]+$ ]]; then
                    sysctl -w vm.swappiness="$VAL" >/dev/null
                    send_msg "✅ <b>Swappiness установлен в $VAL!</b>"$'\n'"Ядро подхватило настройку без перезагрузки." "$KB_AUTO"
                fi
                ;;

            /memcomp_on)
                send_action
                synosetkeyvalue /etc/synoinfo.conf mem_compress yes
                synosetkeyvalue /etc.defaults/synoinfo.conf mem_compress yes
                send_msg "🔄 <b>Сжатие памяти ВКЛЮЧЕНО.</b>"$'\n'"⚠️ <b>Нужна перезагрузка NAS</b>, чтобы ядро подхватило настройку." "$KB_AUTO"
                ;;

            /memcomp_off)
                send_action
                synosetkeyvalue /etc/synoinfo.conf mem_compress no
                synosetkeyvalue /etc.defaults/synoinfo.conf mem_compress no
                send_msg "✅ <b>Сжатие памяти ОТКЛЮЧЕНО!</b>"$'\n'"⚠️ <b>Нужна перезагрузка</b> для выгрузки модуля ZRAM." "$KB_AUTO"
                ;;
        esac
    done

    LAST_ID=$(echo "$UPDATES" | jq -r '.result[-1].update_id // empty')
    [ -n "$LAST_ID" ] && OFFSET=$((LAST_ID + 1))
done

