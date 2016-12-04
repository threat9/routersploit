FROM python:2.7

WORKDIR /routersploit

RUN git clone https://github.com/reverse-shell/routersploit/ .
RUN pip install -r requirements.txt

CMD ["python", "rsf.py"]