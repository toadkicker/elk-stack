#!/usr/bin/env bash
# This script configures amazon linux as a logstash client to the kinesis stream
# @@STREAM_NAME replace with your stream name
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch;
cat > /etc/yum.repos.d/logstash.repo << EOF
[logstash-2.2]
name=Logstash repository for 2.2.x packages
baseurl=http://packages.elastic.co/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
yum -y install logstash;
cat > /etc/logstash/conf.d/logstash-kinesis.conf << EOF
input {
    stdin { }
    tcp {
        port => 5000
        type => syslog
    }
    udp {
        port => 5000
        type => syslog
    }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}

output {
    kinesis {
        codec => json { }
        stream_name => "@@STREAM_NAME"
        region => "us-east-1"
    }
}
EOF
/opt/logstash/bin/plugin install logstash-output-kinesis
if $(service logstash configtest)
then service logstash start
fi