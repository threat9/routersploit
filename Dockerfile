FROM python:3.9-bookworm

WORKDIR /routersploit

RUN useradd rts -U -m && \
    chown -R rts:rts /routersploit

USER rts
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

COPY routersploit routersploit
COPY rsf.py rsf.py

# Not actually needed since present in docker-compose already
CMD ["python", "rsf.py"]
