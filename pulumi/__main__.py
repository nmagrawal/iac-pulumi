"""An AWS Python Pulumi program"""

import pulumi
import pulumi_aws as aws

# Load Pulumi config
config = pulumi.Config()

# Get region and CIDR block from config
vpc_cidr = config.require("cidr")
aws_config = pulumi.Config("aws")
region = aws_config.get("region")
vpc_name = config.require("vpc_name")
internet_gateway_name = config.require("internet_gateway_name")
subnet_name = config.require("subnet_name")
route_table_name = config.require("route_table_name")

# Create VPC
vpc = aws.ec2.Vpc(vpc_name,
    cidr_block="10.0.0.0/16",
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

subnet_ids = []
for i in range(no_of_subnets):
    # Determining subnet type
    subnet_type = "public" if i < no_of_subnets // 2 else "private"
    
    # Create subnet
    subnet = aws.ec2.Subnet(f"{subnet_name}_{subnet_type}_{i}",
        vpc_id=vpc.id,
        cidr_block=f"10.0.{i}.0/24",
        availability_zone=zones.names[i % (no_of_subnets // 2)],
        map_public_ip_on_launch=i < no_of_subnets // 2,
        tags={
        "Name": f"{subnet_name}_{subnet_type}_{i}",
    })  # map public IP if public subnet
    subnet_ids.append((subnet.id, subnet_type))

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

pulumi.export("vpcId", vpc.id)
pulumi.export("igId", ig.id)
pulumi.export("publicRTId", public_rt.id)
pulumi.export("privateRTId", private_rt.id)
