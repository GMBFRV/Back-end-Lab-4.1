FROM python:3.8

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# Копіюємо залежності в контейнер
COPY requirements.txt /app/

# Встановлюємо залежності
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Копіюємо вміст поточного каталогу в контейнер в /app
COPY . /app/

# Опреділяємо змінні середовища Flask
ENV FLASK_APP=project/app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Запускаємо додаток
CMD ["flask", "run"]
