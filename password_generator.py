# Защита информации
# ЛР №1
# Вариант 3
# 8 - символов пароля
# b1, b2, b3 - случайные цифры
# b4, b5 - случайные символы из множества {!, ", #, $, %, &, ', (,),*}
# b7 - случайная заглавная буква английского алфавита
# b8 - P - ая по счету малая буква английского алфавита, где
# P = N^2 mod 10 + N^3 mod 10 + 1

import random
import string


def password_generate(username):
    symbol_tuple = ('!', '"', '#', '$', '%', '&', "'", '(', ')', '*')
    n = len(username)
    password = []
    numbers_for_password = random.sample(range(0, 10), 3)
    password.extend(numbers_for_password)
    password.extend(random.choices(symbol_tuple, k=3))
    password.append(random.choice(string.ascii_uppercase))

    p = n ** 2 % 10 + n ** 3 % 10 + 1
    password.append(string.ascii_lowercase[p - 1])
    return ''.join(map(str, password))
