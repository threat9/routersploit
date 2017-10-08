FROM python:2.7

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

WORKDIR /routersploit
COPY . .

CMD ["python", "rsf.py"]