FROM python:2.7

WORKDIR /rsf

COPY requirements.txt /rsf
RUN pip install -r requirements.txt

COPY rsf.py /rsf
COPY run_linter.sh /rsf
COPY run_tests.sh /rsf
COPY tox.ini /rsf
COPY ./routersploit /rsf/routersploit

CMD /rsf/rsf.py

