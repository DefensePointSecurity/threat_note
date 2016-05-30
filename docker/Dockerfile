# Dockerfile for threat_note development instance
# written by John D. Swanson on a framework provided by Kyle Maxwell
# build with the command:
#
# sudo docker build -t threat_note .
# sudo docker run -itd -p 8888:8888 threat_note
#
# then access http://localhost:8888 in your browser

FROM ubuntu:14.04
MAINTAINER John D. Swanson "swanson.john.d@gmail.com"
RUN apt-get update && \
  apt-get dist-upgrade -y
RUN apt-get install -y --no-install-recommends \
  python-pip  \
  python-dev \
  libxml2-dev \
  libxslt-dev \
  zlib1g-dev \
  build-essential \
  git && \

  groupadd -r threatnote && \
  useradd -r -g threatnote -d /home/threat_note -s /sbin/nologin -c "threatnote user" threatnote

WORKDIR /home
RUN git clone https://github.com/defpoint/threat_note.git && \
  chown -R threatnote:threatnote /home/threat_note && \
  cd threat_note && \
  pip install -r requirements.txt

USER threatnote
ENV HOME /home/threat_note
ENV USER threatnote
WORKDIR /home/threat_note
EXPOSE 8888
CMD ["python", "/home/threat_note/threat_note/threat_note.py", "-H 0.0.0.0", "-p 8888"]
