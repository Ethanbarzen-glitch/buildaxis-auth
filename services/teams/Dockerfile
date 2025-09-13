FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# deps for this service
COPY services/teams/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
# shared auth lib
COPY lib/atlas_auth /app/atlas_auth
# service code
COPY services/teams/ .
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8000","--proxy-headers","--access-log"]
