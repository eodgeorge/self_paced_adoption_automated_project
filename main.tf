# create VPC
resource "aws_vpc" "acpt3_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "acpt3_vpc"
  }
}

# create subnet groups

#create public subnet 1
resource "aws_subnet" "acpt3_public_subnet_1" {

  vpc_id            = aws_vpc.acpt3_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-west-2a"

  tags = {
    Name = "acpt3_public_subnet_1"
  }
}

# create public subnet 2
resource "aws_subnet" "acpt3_public_subnet_2" {

  vpc_id            = aws_vpc.acpt3_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "eu-west-2b"


  tags = {
    Name = "acpt3_public_subnet_2"
  }
}

#create private subnet 1
resource "aws_subnet" "acpt3_private_subnet_1" {

  vpc_id            = aws_vpc.acpt3_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "eu-west-2a"

  tags = {
    Name = "acpt3_private_subnet_1"
  }
}

# create private subnet 2
resource "aws_subnet" "acpt3_private_subnet_2" {

  vpc_id            = aws_vpc.acpt3_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = "eu-west-2b"

  tags = {
    Name = "acpt3_private_subnet_2"
  }

}

# create an IGW

resource "aws_internet_gateway" "acpt3_igw" {
  vpc_id = aws_vpc.acpt3_vpc.id

  tags = {
    Name = "acpt3_igw"
  }


}

# creating the EIP
resource "aws_eip" "eip" {
  depends_on = [aws_internet_gateway.acpt3_igw]


}

# creating the NAT gateway

resource "aws_nat_gateway" "acpt3_nat_gw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.acpt3_public_subnet_1.id

  tags = {
    Name = "acpt3_nat_gw"
  }
}
# Create a Route table

#creating public Route Table
resource "aws_route_table" "pub_rt" {
  vpc_id = aws_vpc.acpt3_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.acpt3_igw.id
  }
  tags = {
    Name = "pub_rt"
  }

}


# Creating private Route Table
resource "aws_route_table" "prv_rt" {
  vpc_id = aws_vpc.acpt3_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.acpt3_nat_gw.id
  }
  tags = {
    Name = "prv_rt"
  }

}

# Create a route table association public subnet 1
resource "aws_route_table_association" "route_association_pub1" {
  subnet_id      = aws_subnet.acpt3_public_subnet_1.id
  route_table_id = aws_route_table.pub_rt.id

}


# Create a route table association public subnet 2
resource "aws_route_table_association" "route_association_pub2" {
  subnet_id      = aws_subnet.acpt3_public_subnet_2.id
  route_table_id = aws_route_table.pub_rt.id

}

# Create a route table association private subnet 1
resource "aws_route_table_association" "route_association_prv1" {
  subnet_id      = aws_subnet.acpt3_private_subnet_1.id
  route_table_id = aws_route_table.prv_rt.id

}

# Create a route table association private subnet 2
resource "aws_route_table_association" "route_association_prv2" {
  subnet_id      = aws_subnet.acpt3_private_subnet_2.id
  route_table_id = aws_route_table.prv_rt.id

}

#Create Security Groups for the ACPT3 Project - FrontEnd

resource "aws_security_group" "acpt3-sg-frontend" {
  name        = "acpt3-sg-frontend"
  description = "frontend"
  vpc_id      = aws_vpc.acpt3_vpc.id

  ingress {

    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]

  }

  tags = {
    Name = "acpt3-sg-frontend"
  }
}

#Create Security Groups for the ACPT3 Project - Backend

resource "aws_security_group" "acpt3-sg-backend" {
  name        = "acpt3-sg-backend"
  description = "backend"
  vpc_id      = aws_vpc.acpt3_vpc.id

  ingress {

    description = "mySql Access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]


  }

  tags = {
    Name = "acpt3-sg-backend"
  }
}


# Create S3 Buckets 

# Create S3 media bucket
resource "aws_s3_bucket" "acpt-media" {
  bucket = "acpt-media"

  tags = {
    Name = "acpt-media"
  }
}
resource "aws_s3_bucket_acl" "acpt-media" {
  bucket = aws_s3_bucket.acpt-media.id
  acl    = "public-read"
}

# Create S3 Code bucket

resource "aws_s3_bucket" "acpt3-code" {
  bucket = "acpt3-code"

  tags = {
    Name = "acpt3-code"
  }
}
resource "aws_s3_bucket_acl" "acpt3-code" {
  bucket = aws_s3_bucket.acpt3-code.id
  acl    = "private"
}



# Create S3 media bucket public access
resource "aws_s3_account_public_access_block" "acpt-media" {
  block_public_acls   = false
  block_public_policy = false
}

# Create Media Bucket Policy
resource "aws_s3_bucket_policy" "media-bucketpolicy" {
  bucket = aws_s3_bucket.acpt-media.id



  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "PublicReadGetObject",
        "Effect" : "Allow",
        "Principal" : "*",
        "Action" : [
          "s3:GetObject"
        ],
        "Resource" : [
          "arn:aws:s3:::acpt-media/*"
        ]

      }
    ]
  })
}

resource "aws_iam_role" "actp3_s3_role" {
  name = "actp3_s3_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "actp3_s3_role"
  }
}


#instance profile
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.actp3_s3_role.name
}

#Adding IAM Policies to give full access to S3 bucket
resource "aws_iam_role_policy" "iam_policy" {
  name = "iam_policy"
  role = aws_iam_role.actp3_s3_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}

#Create DB Subnet Group
resource "aws_db_subnet_group" "acpt3_db_sg" {
  name        = "acpt3_db_sg"
  description = "acpt3_db_subnet_group"
  subnet_ids  = [aws_subnet.acpt3_private_subnet_1.id, aws_subnet.acpt3_private_subnet_2.id]

  tags = {
    Name = "acpt3_db_sg"
  }
}

#Create the DB
resource "aws_db_instance" "acpt3db" {

  engine                 = "mysql"
  engine_version         = "8.0"
  identifier             = "acpt3database"
  username               = "Admin"
  password               = "Admin123"
  instance_class         = "db.t2.micro"
  db_subnet_group_name   = aws_db_subnet_group.acpt3_db_sg.id
  vpc_security_group_ids = [aws_security_group.acpt3-sg-backend.id]
  name                   = "acpt3db"
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  allocated_storage      = 20
  storage_type           = "gp2"
  max_allocated_storage  = 1000
  multi_az               = true


}


#creating key pair 
resource "aws_key_pair" "acpt3_keypair" {
  key_name = "acpt3-keypair"

  public_key = file("/Users/nwabuko/Desktop/automated-capstone-project-team-3/Keypair.pub")

}



#configure wordpress

resource "aws_instance" "acpt3_webserver" {
  ami                         = "ami-0ad8ecac8af5fc52b"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.acpt3_public_subnet_1.id
  security_groups             = ["${aws_security_group.acpt3-sg-frontend.id}"]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  key_name                    = "acpt3-keypair"
  user_data = <<-EOF
#! /bin/bash
sudo yum upgrade -y 
sudo yum install php-mysqlnd php-fpm mariadb-server httpd -y
sudo systemctl start httpd
cd /var/www/html
sudo touch TestIndex.html
sudo echo "This is a test file" >> TestIndex.html
sudo yum install wget -y
sudo wget https://wordpress.org/wordpress-5.1.1.tar.gz
sudo tar -xzf wordpress-5.1.1.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo rm -rf wordpress
sudo rm -rf wordpress-5.1.1.tar.gz
sudo chmod -R 755 wp-content
sudo chown -R apache:apache wp-content
sudo wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
sudo mv htaccess.txt .htaccess
cd /var/www/html && sudo mv wp-config-sample.php wp-config.php
sudo sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'acpt3db' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'Admin' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Admin123' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST','acpt3database.cjjdmi1woemg.eu-west-2.rds.amazonaws.com' )@g" /var/www/html/wp-config.php
sudo setenforce 0
sudo systemctl restart httpd
EOF
  root_block_device {

    volume_size = "10"
    volume_type = "gp2"
  }


  tags = {
    Name = "acpt3_webserver"
  }
}

# #aws instance AMI
resource "aws_ami_from_instance" "acpt3_webserver_instance_image" {
  name               = "acpt3_webserver_instance_image"
  source_instance_id = aws_instance.acpt3_webserver.id

  depends_on = [
    aws_instance.acpt3_webserver
  ]
}
# Create Launch Configuration for webserver ASG
resource "aws_launch_configuration" "acpt3LC" {
  name                        = "acpt3LC"
  image_id                    = "ami-0ad8ecac8af5fc52b" #aws_ami_from_instance.acpt3_webserver_instance_image.id
  key_name                    = "acpt3-keypair"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  security_groups             = [aws_security_group.acpt3-sg-frontend.id]
  # depends_on = [
  #   aws_ami_from_instance.acpt3_webserver_instance_image
  # ]

user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y 
sudo yum install php-mysqlnd php-fpm mariadb-server httpd -y
sudo systemctl start httpd
cd /var/www/html
sudo touch TestIndex.html
sudo echo "This is a test file" >> TestIndex.html
sudo yum install wget -y
sudo wget https://wordpress.org/wordpress-5.1.1.tar.gz
sudo tar -xzf wordpress-5.1.1.tar.gz
sudo cp -r wordpress/* /var/www/html/
sudo rm -rf wordpress
sudo rm -rf wordpress-5.1.1.tar.gz
sudo chmod -R 755 wp-content
sudo chown -R apache:apache wp-content
sudo wget https://s3.amazonaws.com/bucketforwordpresslab-donotdelete/htaccess.txt
sudo mv htaccess.txt .htaccess
cd /var/www/html && sudo mv wp-config-sample.php wp-config.php
sudo sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', 'acpt3db' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', 'Admin' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', 'Admin123' )@g" /var/www/html/wp-config.php
sudo sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST','acpt3database.chrirzobdcnc.eu-west-2.rds.amazonaws.com' )@g" /var/www/html/wp-config.php
sudo setenforce 0
sudo systemctl restart httpd
EOF
  lifecycle {
    create_before_destroy = false
  }
}

# creation of load balancer Target-group
resource "aws_lb_target_group" "acpt3TG" {
  name        = "acpt3TG"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.acpt3_vpc.id
  target_type = "instance"

  health_check {
    path                = "/TestIndex.html"
    port                = 80
    protocol            = "HTTP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 60
    interval            = 90
    matcher             = "200"
  }
}
# attaching the targeted instance to the above Target group
resource "aws_lb_target_group_attachment" "acpt3TG" {
  target_group_arn = aws_lb_target_group.acpt3TG.arn
  target_id        = aws_instance.acpt3_webserver.id
  port             = 80
  depends_on       = [aws_instance.acpt3_webserver]

}
resource "aws_security_group" "acpt3_ELB_SG" {
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.acpt3_vpc.id

  ingress {
    description = "http rule"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }


  ingress {
    description = "SSH Access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "https rule"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "acpt3_ELB_SG"
  }
}

# creation of Load balancer
resource "aws_lb" "acpt3LB" {
  name               = "acpt3LB"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.acpt3-sg-frontend.id]
  subnets            = [aws_subnet.acpt3_public_subnet_1.id, aws_subnet.acpt3_public_subnet_2.id]

}

resource "aws_lb_listener" "acpt3LB" {
  load_balancer_arn = aws_lb.acpt3LB.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.acpt3TG.arn

  }
}

#creation of auto-scalling group 
resource "aws_autoscaling_group" "acpt3ASG" {
  name                      = "acpt3ASG"
  launch_configuration      = aws_launch_configuration.acpt3LC.id
  vpc_zone_identifier       = [aws_subnet.acpt3_public_subnet_1.id, aws_subnet.acpt3_public_subnet_2.id]
  target_group_arns         = [aws_lb_target_group.acpt3TG.arn]
  health_check_type         = "ELB"
  health_check_grace_period = 1200
  desired_capacity          = 2
  max_size                  = 2
  min_size                  = 1
  default_cooldown          = 60
  force_delete              = true
  lifecycle {
    create_before_destroy = false
  }
}
#aws autoscaling policy
resource "aws_autoscaling_policy" "acpt3ASG_policy" {
  name = "acpt3ASG-policy"
  #scaling_adjustment     = 3
  policy_type     = "TargetTrackingScaling"
  adjustment_type = "ChangeInCapacity"
  #cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.acpt3ASG.name

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60.0
  }
}


# Create a domain name using route53 
resource "aws_route53_zone" "acpt3_route53_zone" {
  name = "danielodavid.com"


  tags = {

    Environmet = "dev_acpt3"
  }
}

resource "aws_route53_record" "acpt3_A_record" {
  zone_id = aws_route53_zone.acpt3_route53_zone.id
  name    = "danielodavid.com"
  type    = "A"

  alias {
    name                   = aws_lb.acpt3LB.dns_name
    zone_id                = aws_lb.acpt3LB.zone_id
    evaluate_target_health = false
  }
}


#Creating CloudFront use media bucket as origin

locals {
  s3_origin_id = "acpt-media"
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "acpt-media"
}


#create dashboard metric
resource "aws_cloudwatch_dashboard" "acpt_Team3_Web_Server_dashboard" {
  dashboard_name = "acpt_Team3_Web_Server_dashboard_1"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.acpt3_webserver.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "InstanceId",
            "${aws_instance.acpt3_webserver.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Network In"
      }
    }
  ]
 }
EOF
}

#Cloudwatch monitoring Policy
resource "aws_sns_topic" "alarm" {

  name = "acpt_Team3-alarms-topic"

  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
  provisioner "local-exec" {

    command = "aws sns subscribe --topic-arn arn:aws:sns:eu-west-2:803077056902:acpt_Team3-alarms-topic --protocol email --notification-endpoint vnwabuko@cloudhight.com"

  }
}
# Creating Cloud watch Metric Alarm for Webserver
resource "aws_cloudwatch_metric_alarm" "acpt_Team3_WEB_CW_Metric_Alarm" {
  alarm_name          = "acpt_Team3_WEB_CW_Metric_Alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80" # when the cpu utilization reaches 80%
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.acpt3ASG.name
  }
  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.acpt3ASG_policy.arn]
}

# Creating Cloudwatch metric alarm for webserver health status (checking to see if the server is accessible)
resource "aws_cloudwatch_metric_alarm" "acpt_Team3-web-health-alarm" {
  alarm_name          = "acpt_Team3-web-health-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors ec2 health status"
  alarm_actions       = [aws_autoscaling_policy.acpt3ASG_policy.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.acpt3ASG.name
  }
}


