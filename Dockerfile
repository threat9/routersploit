FROM python:3.7-bookworm

WORKDIR /routersploit

RUN useradd rts -U -m && \
    chown -R rts:rts /routersploit

USER rts
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

COPY routersploit routersploit
COPY rsf.py rsf.py

CMD ["python", "rsf.py"]