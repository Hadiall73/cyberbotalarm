FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data
EXPOSE 2222 8080 9999 21 23 3306 6379
CMD ["python", "main.py"]
