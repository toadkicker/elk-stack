#!/usr/bin/env bash
# This script configures amazon linux as a logstash client to the kinesis stream
# @@STREAM_NAME replace with your stream name

# IAM instance policies:
# You need these:
# {
#     "Effect": "Allow",
#     "Action": [
#         "cloudwatch:GetMetricStatistics",
#         "cloudwatch:ListMetrics",
#         "cloudwatch:PutMetricData",
#         "ec2:DescribeTags"
#     ],
#     "Resource": [
#         "*"
#  ]
# },
# {
#     "Action": [
#         "kinesis:PutRecord",
#         "kinesis:PutRecords",
#         "kinesis:DescribeStream"
#     ],
#     "Resource": "arn:aws:kinesis:region:accountid:stream/streamname*",
#     "Effect": "Allow"
# }

# Set up logstash repo
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch;

# Add configuration files
cat > /etc/profile.d/environment.sh << EOF
export ENVIRONMENT=development
EOF


cat > /etc/yum.repos.d/logstash.repo << EOF
[logstash-2.4]
name=Logstash repository for 2.4.x packages
baseurl=https://packages.elastic.co/logstash/2.4/centos
gpgcheck=1
gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
yum -y install logstash;
/opt/logstash/bin/plugin install logstash-input-cloudwatch logstash-output-kinesis;
cat > /etc/logstash/conf.d/logstash-syslog-filter.conf << EOF
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
EOF
cat > /etc/logstash/conf.d/logstash-input.conf << EOF
input {
    stdin { }
    cloudwatch {
        namespace => "AWS/EC2"
        metrics => [ "CPUUtilization" ]
        filters => { "tag:Environment" => "${ENVIRONMENT}" }
        region => "us-east-1"
    }
    file {
        path => ["/var/log/**/*.log", "/var/log/messages"]
    }
}
EOF

cat > /etc/logstash/conf.d/logstash-kinesis.conf << EOF
output {
    kinesis {
        codec => json { }
        stream_name => "ELK-Development-ElkKinesisStream-107R4L566PVEA"
        region => "us-east-1"
    }
}
EOF

cat > /etc/logstash/conf.d/logstash-tcp.conf << EOF
output {
    tcp {
        host => "logstash-${ENVIRONMENT}.intensity.internal"
        port => 6379
        codec => json_lines
    }
}
EOF


/etc/init.d/logstash start