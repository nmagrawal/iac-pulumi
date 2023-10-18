"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws
import ipaddress
from pulumi_aws import ec2


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

# Get region and CIDR block from config
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

# Create VPC
vpc = aws.ec2.Vpc(vpc_name,
    cidr_block=vpc_cidr,
    instance_tenancy="default",
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

# Create a new security group
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
        ),
        # Application port
        ec2.SecurityGroupIngressArgs(
            protocol="tcp",
            from_port=8080,
            to_port=8080,
            cidr_blocks=[
                ipv4_cidr_block
            ],
            ipv6_cidr_blocks=[
                ipv6_cidr_block
            ]
        ),
    ])

ec2_instance = ec2.Instance('ec2_instance',
                            ami=ami_id,  # Amazon Machine Image
                            instance_type=webapp.get("instance_type"),  # Default instance type
                            subnet_id=public_subnets[0],  # Subnet ID
                            key_name=key_name,  # SSH key name
                            vpc_security_group_ids=[app_security_group.id],  # Security Group
                            root_block_device=ec2.InstanceRootBlockDeviceArgs(
                                volume_type=webapp.get("root_volume_type"),  
                                volume_size=webapp.get("root_volume_size"),  
                                delete_on_termination=True  # Terminate EBS volume on instance termination
                            ),
                            disable_api_termination=False,
                            tags= {
                                "Name": webapp.get("name")
                            }
                            )

# Export the name of the EC2 instance
pulumi.export('ec2_instance_name', ec2_instance.id)
# Export
pulumi.export("vpcId", vpc.id)
pulumi.export("igId", ig.id)
pulumi.export("publicRTId", public_rt.id)
pulumi.export("privateRTId", private_rt.id)
pulumi.export("subnets", subnet_ids)
pulumi.export("appSecurityGroupId", app_security_group.id)
