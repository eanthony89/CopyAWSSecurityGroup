#!/usr/bin/python

#
#Currently AWS console does not provide an option to copy a security group in one region to a security group in a DIFFERENT region.
#This script is created to achieve this.
#
# author : Eric Anthony
#
# Date : Jan-7-2018

import boto3
from botocore.exceptions import ClientError
import os, sys

os.system('clear')

sg_old_id = raw_input("Enter security group id from which the rules are to be copied(e.x: sg-12345678): ")
old_region = raw_input("Enter the region in which the security group exists (i.e: us-east-1): ")
new_region = raw_input("Enter the region in which the new security group has be to be created (i.e: us-east-1): ")
new_vpc = raw_input("Enter the VPC ID to create in which the new group will be created: " )
newgroup_name = raw_input ("Enter name of the new security group that will be created:")
role = raw_input("Please insert the FULL Role ARN (i.e: arn:aws:iam::1234567890:role/name-of-role): ")

print "Assuming Roles under Different Accounts"
print 30 * "-"
print ""

try:
    sts_client = boto3.client('sts')
    assumedRoleObject = sts_client.assume_role(RoleArn=role, RoleSessionName="AssumeRoleSession")
    credentials = assumedRoleObject['Credentials']
except ClientError as error:
    print "Role " + role + " doesn't exists. Please check the name again."
    print "Original error: " + error.response['Error']['Message']    
    

try:
     ec2 = boto3.resource('ec2', region_name=old_region, aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
except NameError:
     ec2 = boto3.resource('ec2', region_name=old_Region)

try:     
    sg_rules_ingress = ec2.SecurityGroup(sg_old_id).ip_permissions
    sg_rules_egress = ec2.SecurityGroup(sg_old_id).ip_permissions_egress
except ClientError as error:
    print "Original error: " + error.response['Error']['Message']

try:
     ec2_new = boto3.resource('ec2', region_name=new_region, aws_access_key_id=credentials['AccessKeyId'], aws_secret_access_key=credentials['SecretAccessKey'], aws_session_token=credentials['SessionToken'])
except NameError:
     ec2_new = boto3.resource('ec2', region_name=new_Region)

try:
    response = client.create_security_group(Description=newgroup_name,GroupName=newgroup_name,VpcId=new_vpc)
    sg_new_id = ec2_new.describe_security_groups.GroupId
    security_group = ec2_new.SecurityGroup(response)
    response = security_group.authorize_ingress(GroupId = sg_new_id,IpPermissions = sg_rules_ingress) 
    response = security_group.authorize_egress(GroupId = sg_new_id,IpPermissions = sg_rules_egress) 
    print ("All done")
except ClientError as p:
    print (p)
    print "Ops!!! Something went wrong. Please try again."



