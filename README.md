# CopyAWSSecurityGroup
AWS console provides an option to copy security groups only within a region. This script is aimed at increasing a admins productivity when the same security group rules need to be replicated in other AWS regions.


To use this script you need to create a IAM rule with the permissions to invoke at least the following API calls:

    AuthorizeSecurityGroupEgress
    AuthorizeSecurityGroupIngress
    CreateSecurityGroup
    RevokeSecurityGroupEgress
    DescribeSecurityGroups


Usage:


 Install Boto3

$ pip install boto3

You can download the script in the attachments. After that, you should make this script executable by changing the permission with the following command:

$ chmod +x sg-copy.py

Run the script to start the process:

./sg-copy.py

Once the script executes , it prompts the user to enter the following details and creates a new security group.

Enter security group id from which the rules are to be copied(e.x: sg-12345678): 

Enter the region in which the security group exists (i.e: us-east-1): 

Enter the region in which the new security group has be to be created (i.e: us-east-1): 

Enter the VPC ID to create in which the new group will be created: 

Enter name of the new security group that will be created:

Please insert the FULL Role ARN (i.e: arn:aws:iam::1234567890:role/name-of-role): 
