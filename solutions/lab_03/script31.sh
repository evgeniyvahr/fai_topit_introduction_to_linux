if [ $# -ne 2 ]; then
    echo "Неверное число аргуметов"
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "Нужны права root"
    exit 1
fi

count=$1
start=$2
end=$((start + count - 1))

for n in $(seq $start $end); do
    username="u$n"
    password="DerParol$n"
    if id "$username" >/dev/null 2>&1; then
        echo "Пользователь $username уже существует"
        continue
    else
        adduser --disabled-password --gecos"" --quiet "$username"
        if [ $? -ne 0 ]; then  
            echo "Ошибка при создании пользователя"
            continue
        fi
        echo "${username}:${password}" | chpasswd
        if [ $? -ne 0 ]; then  
            echo "Ошибка при создании пользователя"
            continue
        else
            echo "Пользователь $username создан с паролем $password"
        fi
    fi
done

