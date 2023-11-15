"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws
import ipaddress
from pulumi_aws import ec2
import textwrap
from pulumi_aws import route53, Provider
import json
import base64


def calculate_subnets(vpc_cidr, num_subnets):
    try:
        vpc_network = ipaddress.IPv4Network(vpc_cidr)
    except ValueError:
        print("Invalid VPC CIDR format. Example format: 10.0.0.0/16")
        return []

    subnet_bits = vpc_network.max_prefixlen - num_subnets

    subnets = list(vpc_network.subnets(new_prefix=subnet_bits))
    
    return subnets

# Load Pulumi config
config = pulumi.Config()
vpc_cidr = config.require("vpc_cidr")
aws_config = pulumi.Config("aws")
region = aws_config.get("region")
vpc_name = config.require("vpc_name")
internet_gateway_name = config.require("internet_gateway_name")
subnet_name = config.require("subnet_name")
route_table_name = config.require("route_table_name")
ipv4_cidr_block = config.require("ipv4_cidr_block")
ipv6_cidr_block = config.require("ipv6_cidr_block")
ami_id = config.require("ami_id")
key_name = config.require("key_name")
webapp = config.require_object("webapp")
rds_config = config.require_object("rds")
properties_file=config.require("properties_file")
route53_config = config.require_object("route53")
dbsecrets = config.require_secret_object("dbsecrets")
autoscale_config = config.require_object("autoscalling")
launch_template_name = config.require("launch_template_name")
environment = config.require("environment")

# Create VPC
vpc = aws.ec2.Vpc(vpc_name,
    cidr_block=vpc_cidr,
    instance_tenancy="default",
    enable_dns_hostnames=True,
    tags={
        "Name": vpc_name,
    })

# Create Internet Gateway
ig = aws.ec2.InternetGateway(internet_gateway_name,
    vpc_id=vpc.id,
    tags={
        "Name": internet_gateway_name,
    })

# Get the number of availability zones in the region
zones = aws.get_availability_zones(state="available")

# Determining the number of subnets to create
no_of_subnets = min(3, len(zones.names)) * 2

subnet_cidrs = calculate_subnets(vpc_cidr, no_of_subnets)
subnet_ids = []
private_subnets = []
public_subnets = []
for i in range(no_of_subnets):
    # Determining subnet type
    subnet_type = "public" if i < no_of_subnets // 2 else "private"

    # Create subnet
    subnet = aws.ec2.Subnet(f"{subnet_name}_{subnet_type}_{i}",
        vpc_id=vpc.id,
        cidr_block=str(subnet_cidrs[i]),
        availability_zone=zones.names[i % (no_of_subnets // 2)],
        map_public_ip_on_launch=i < no_of_subnets // 2,
        tags={
        "Name": f"{subnet_name}_{subnet_type}_{i}",
    })  # map public IP if public subnet
    subnet_ids.append((subnet.id, subnet_type))

public_subnets = [subnet_id for subnet_id, subnet_type in subnet_ids if subnet_type == "public"]
private_subnets = [subnet_id for subnet_id, subnet_type in subnet_ids if subnet_type == "private"]


# Create public and private route tables
public_rt = aws.ec2.RouteTable(f"{route_table_name}_public",
    vpc_id=vpc.id,
    routes=[
        aws.ec2.RouteTableRouteArgs(
            cidr_block="0.0.0.0/0",
            gateway_id=ig.id,
        ),
    ],
    tags={
        "Name": f"{route_table_name}_public",
    })
private_rt = aws.ec2.RouteTable(f"{route_table_name}_private", 
                                vpc_id=vpc.id,
                                tags={
                                    "Name": f"{route_table_name}_private",
                                })

# Associate subnets with applicable route tables
for i, (subnet_id, subnet_type) in enumerate(subnet_ids):
    rt_id = public_rt.id if subnet_type == "public" else private_rt.id
    aws.ec2.RouteTableAssociation(f"rta_{i}",
        route_table_id=rt_id,
        subnet_id=subnet_id)


# LoadBalancer Security Group
loadbalancer_security_group = ec2.SecurityGroup("loadbalancerSecurityGroup",
    description="Security group for the Load Balancer",
    vpc_id = vpc.id,
    tags={
        "Name": "loadbalancerSecurityGroup"
    },
    ingress=[
        # HTTP
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=80,
            to_port=80,
            cidr_blocks=[
                ipv4_cidr_block
            ],
            ipv6_cidr_blocks=[
                ipv6_cidr_block
            ]
        ),
        # HTTPS
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=443,
            to_port=443,
            cidr_blocks=[
                ipv4_cidr_block
            ],
            ipv6_cidr_blocks=[
                ipv6_cidr_block
            ]
        )
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        ipv6_cidr_blocks=["::/0"],
    )]
    )

# App Security Group
app_security_group = ec2.SecurityGroup("appSecurityGroup",
    description="Security group for the application",
    vpc_id = vpc.id,
    tags={
        "Name": "application security group"
    },
    ingress=[
        # SSH
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=22,
            to_port=22,
            cidr_blocks=[
                 ipv4_cidr_block
            ],
            ipv6_cidr_blocks=[
                ipv6_cidr_block
            ]
        ),
        # Application port
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=8080,
            to_port=8080,
            security_groups=[
                loadbalancer_security_group.id
            ]
        ),
    ],
    egress=[aws.ec2.SecurityGroupEgressArgs(
        from_port=0,
        to_port=0,
        protocol="-1",
        cidr_blocks=["0.0.0.0/0"],
        ipv6_cidr_blocks=["::/0"],
    )]
    )


rds_security_group = ec2.SecurityGroup("RDS Security Group",
    description="Security group for the RDS instance",
    vpc_id = vpc.id,
    tags={
        "Name": "RDS Security Group"
    },
    ingress=[
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=3306,
            to_port=3306,
            security_groups=[
                app_security_group.id
            ],
        ),
    ])

rds_parameter_group = aws.rds.ParameterGroup("rds-parameter-group",
    family="mariadb10.6",
    description="Parameter group for the RDS instance",
    )

private_subnet_group = aws.rds.SubnetGroup("private_subnet_group",
    subnet_ids=private_subnets,
    tags={
        "Name": "Private_Subnet_Group",
    })

rds_instance = aws.rds.Instance(rds_config.get("name"),
    allocated_storage=rds_config.get("allocated_storage"),
    db_name=rds_config.get("db_name"),
    engine=rds_config.get("engine"),
    engine_version=rds_config.get("engine_version"),
    instance_class=rds_config.get("instance_class"),
    parameter_group_name=rds_parameter_group.name,
    db_subnet_group_name=private_subnet_group.name,
    vpc_security_group_ids=[rds_security_group.id],
    max_allocated_storage=0,
    publicly_accessible=False,
    password=dbsecrets.apply(lambda x: x.get("password")),
    skip_final_snapshot=True,
    username=dbsecrets.apply(lambda x: x.get("username")),
    tags={
        "Name": rds_config.get("name"),
    },
    )

with open(properties_file, "r") as file:
    base_properties = file.read()

PROPERTIES_FILE='/tmp/application.properties'

rds_instance_address = url = pulumi.Output.concat("jdbc:mariadb://", rds_instance.address, ":3306/", rds_config.get("db_name"))

username = dbsecrets.apply(lambda x: x.get("username"))
password = dbsecrets.apply(lambda x: x.get("password"))

user_data = ["#!/bin/bash",
             f"echo '{base_properties}' >> {PROPERTIES_FILE}",
            #  f"echo 'spring.datasource.username={username}' >> {PROPERTIES_FILE}",
            #  f"echo 'spring.datasource.password={password}' >> {PROPERTIES_FILE}",
             f"echo 'application.config.users-csv-path=/opt/csye6225/users.csv' >> {PROPERTIES_FILE}",
             ]


user_data = pulumi.Output.concat("\n".join(user_data),"\n", rds_instance_address.apply(lambda x: f"echo 'spring.datasource.url={x}' >> {PROPERTIES_FILE}"),"\n")

user_data = pulumi.Output.concat(user_data, "echo 'spring.datasource.username=", username, f"' >> {PROPERTIES_FILE}", "\n")
user_data = pulumi.Output.concat(user_data, "echo 'spring.datasource.password=", password, f"' >> {PROPERTIES_FILE}", "\n")

user_data = pulumi.Output.concat(user_data, f"sudo mv {PROPERTIES_FILE} /opt/csye6225/application.properties", "\n",
                                 "sudo chown -R csye6225:csye6225 /opt/csye6225/", "\n",
                                 "sudo chmod -R 740 /opt/csye6225/", "\n")

cw_commands = [
               "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/cloudwatch-config.json \
    -s",
               "sudo systemctl restart amazon-cloudwatch-agent.service"
]

user_data = pulumi.Output.concat(user_data, "\n".join(cw_commands), "\n")

cloud_watch_role = aws.iam.Role("CWAgentRole",
    name="CWAgentRole",
    description="Allows EC2 instances to call AWS services on your behalf.",
    assume_role_policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Action": "sts:AssumeRole",
            "Effect": "Allow",
            "Principal": {
                "Service": "ec2.amazonaws.com",
            },
        }],
    }),
    tags={
        "name": "CWAgentRole",
    })

policy_attachment = aws.iam.RolePolicyAttachment("cloudwatchRolePolicyAttachment",
    role=cloud_watch_role.name,
    policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy")

instance_profile = aws.iam.InstanceProfile('myInstanceProfile',
                                           role = cloud_watch_role.name
                                           )

# ec2_instance = ec2.Instance('ec2_instance',
#                             ami=ami_id,  
#                             instance_type=webapp.get("instance_type"),  
#                             subnet_id=public_subnets[0],  
#                             key_name=key_name,  
#                             vpc_security_group_ids=[app_security_group.id],  
#                             root_block_device=ec2.InstanceRootBlockDeviceArgs(
#                                 volume_type=webapp.get("root_volume_type"),  
#                                 volume_size=webapp.get("root_volume_size"),  
#                                 delete_on_termination=True  
#                             ),
#                             disable_api_termination=False,
#                             tags= {
#                                 "Name": webapp.get("name")
#                             },
#                             user_data=user_data,
#                             iam_instance_profile=instance_profile.name
#                             )

user_data = user_data.apply(lambda x: base64.b64encode(x.encode("ascii")).decode("ascii"))

# Create a launch template
launch_template = aws.ec2.LaunchTemplate(resource_name=launch_template_name,
    name=launch_template_name,
    image_id=ami_id,  # Amazon Machine Image ID
    instance_type=webapp.get("instance_type"), 
    network_interfaces=[aws.ec2.LaunchTemplateNetworkInterfaceArgs(
        associate_public_ip_address="true",
        subnet_id=public_subnets[0],
        security_groups=[app_security_group.id]
    )], 
    key_name=key_name,  # SSH key name
    block_device_mappings=[{  # Array of mappings
        "device_name": "/dev/xvda",  # Device name
        "ebs": {
            "volume_size": webapp.get("root_volume_size"),   # Volume Size
            "volume_type": webapp.get("root_volume_type"),  # Volume Type
            "delete_on_termination": True  # Terminate EBS volume on instance termination
        },
    }],
    disable_api_termination=False,  # Instance can be terminated using the Amazon EC2 console, CLI, and API
    tags= { 
        "Name": webapp.get("name"),
    },
    user_data=user_data,
    iam_instance_profile={
        "name": instance_profile.name,
    },
    tag_specifications = [ec2.LaunchTemplateTagSpecificationArgs(
        resource_type="instance",
        tags={
            "Name":webapp.get("name")
        }
    )]
)

# # Application Loadbalancer
app_load_balancer = aws.lb.LoadBalancer("AppLoadBalancer",
    internal=False,
    load_balancer_type="application",
    security_groups=[loadbalancer_security_group.id],
    subnets=public_subnets,
    enable_deletion_protection=False,
    tags={
        "Name": "AppLoadBalancer",
        "Environment": environment,
    })

# # Target Group
target_group = aws.lb.TargetGroup("AppTargetGroup",
    target_type="instance",
    port=autoscale_config["target_group"]["port"],
    protocol=autoscale_config["target_group"]["protocol"],
    slow_start=30,
    vpc_id=vpc.id,
    health_check= aws.lb.TargetGroupHealthCheckArgs(
        port=autoscale_config["target_group"]["port"],
        protocol="HTTP",
        matcher=autoscale_config["target_group"]["healthy_status_code"],
        path=autoscale_config["target_group"]["health_check_path"],
        interval=autoscale_config["target_group"]["health_check_interval_seconds"],
        healthy_threshold=2,
    ),
    ) 

pulumi.export("target_group_arn", target_group.arn)

# # Listner
listener = aws.lb.Listener('app-listener',
    load_balancer_arn=app_load_balancer.arn,
    port=autoscale_config["listner"]["port"],
    default_actions=[
        aws.lb.ListenerDefaultActionArgs(
            type='forward',
            target_group_arn=target_group.arn,
        ),
    ],
)

pulumi.export("listener_arn", listener.arn)

# # AutoScalling Group
autoscalling_group = aws.autoscaling.Group("AppAutoScalingGroup",
    desired_capacity=1,
    default_cooldown=autoscale_config.get("default_cooldown"),
    max_size=autoscale_config.get("max_size"),
    min_size=autoscale_config.get("min_size"),
    health_check_grace_period=autoscale_config.get("health_check_grace_period"),
    health_check_type="ELB",
    target_group_arns=[target_group.arn],
    launch_template=aws.autoscaling.GroupLaunchTemplateArgs(
        id=launch_template.id,
        version="$Latest",
    ))

name_tag = aws.autoscaling.Tag(resource_name="Name_tag",
    autoscaling_group_name=autoscalling_group.name,
    tag=aws.autoscaling.TagTagArgs(
        key="Name",
        value=webapp.get("name"),
        propagate_at_launch=True,
        )
    )

environment_tag = aws.autoscaling.Tag(resource_name="Environment_tag",
    autoscaling_group_name=autoscalling_group.name,
    tag=aws.autoscaling.TagTagArgs(
        key="Environment",
        value=environment,
        propagate_at_launch=True,
        )
    )

# Scale up policy
scale_up = aws.autoscaling.Policy("scale_up",
    adjustment_type="ChangeInCapacity",
    autoscaling_group_name=autoscalling_group.name,
    enabled=True,
    policy_type="SimpleScaling",
    scaling_adjustment=1,
    metric_aggregation_type="Average",
)
pulumi.export("scale_up_policy_arn", scale_up.arn)

# Scale Down policy
scale_down = aws.autoscaling.Policy("scale_down",
    adjustment_type="ChangeInCapacity",
    autoscaling_group_name=autoscalling_group.name,
    enabled=True,
    policy_type="SimpleScaling",
    scaling_adjustment=-1,
    metric_aggregation_type="Average",
)
pulumi.export("scale_up_policy_arn", scale_up.arn)

# CloudWatch Metric Alarm resource that triggers the Scale Up Policy
cpu_utilization_high_alarm = aws.cloudwatch.MetricAlarm("cpuUtilizationHigh",
    comparison_operator="GreaterThanOrEqualToThreshold",
    evaluation_periods=autoscale_config.get("evaluation_periods"),
    metric_name=autoscale_config.get("metric_type"),
    namespace="AWS/EC2",
    period=autoscale_config.get("period"),
    statistic="Average",
    threshold=autoscale_config.get("scale_up_threshold"),
    alarm_actions=[scale_up.arn],
    dimensions={
        "AutoScalingGroupName": autoscalling_group.name,
    },
)

# CloudWatch Metric Alarm resource that triggers the Scale Down Policy
cpu_utilization_high_alarm = aws.cloudwatch.MetricAlarm("cpuUtilizationLow",
    comparison_operator="LessThanOrEqualToThreshold",
    evaluation_periods=autoscale_config.get("evaluation_periods"),
    metric_name=autoscale_config.get("metric_type"),
    namespace="AWS/EC2",
    period=autoscale_config.get("period"),
    statistic="Average",
    threshold=autoscale_config.get("scale_down_threshold"),
    alarm_actions=[scale_down.arn],
    dimensions={
        "AutoScalingGroupName": autoscalling_group.name,
    },
)

# DNS Alias
record = route53.Record(route53_config.get("domain_name"),
    name=route53_config.get("domain_name"),
    type="A", 
    aliases=[route53.RecordAliasArgs(
        name=app_load_balancer.dns_name,
        zone_id=app_load_balancer.zone_id,
        evaluate_target_health=True
    )], 
    zone_id=route53_config.get("hosted_zone_id")) 

# # ec2_ip = pulumi.Output.concat("", ec2_instance.public_ip)

#Export
# pulumi.export('ec2_instance_name', ec2_instance.id)
pulumi.export("vpcId", vpc.id)
pulumi.export("igId", ig.id)
pulumi.export("publicRTId", public_rt.id)
pulumi.export("privateRTId", private_rt.id)
pulumi.export("subnets", subnet_ids)
pulumi.export("privateSubnetGroup", private_subnet_group.id)
pulumi.export("appSecurityGroupId", app_security_group.id)
pulumi.export("rdsSecurityGroup", rds_security_group.id)
pulumi.export("rdsParameterGroup", rds_parameter_group.id)
pulumi.export("rdsInstance", rds_instance.id)