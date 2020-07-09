# Summary

This is a script to onboard AWS account to PrismaCloud

# Requirements

1. Python 3.5 or greater

2. Pip

3. Boto3

Follow directions [here](https://pypi.org/project/boto3/) and setup credentials for the AWS account you want to onboard.

4. Requests
`pip install requests`


# Environment Variables (must be set for script to work properly)

This script doesn't take any command line arguments. Instead, credentials and information are taken through environment variables. The following are used by this script:

PRISMA_USER_NAME: Your Prisma Cloud Access Key 

PRISMA_PASSWORD: Your Prisma Cloud Secret Key
Re	
PRISMA_CUSTOMER_NAME: The name of your tenant within Prisma Cloud

PRISMA_ACCOUNT_NAME: The name you want to give the onboarded account within Prisma

PRISMA_ACCOUNT_GROUP: Account Group you would like the account added to -- default is Default Account Group

PRISMA_ACCOUNT: either true or false - true will onboard account as new, false will only update the account

PRISMA_VPC: either true or false - true will iterate through all your VPCs and enable flowlogs if there isn't one already available

PRISMA_CLOUDTRAIL: either true or false, currently does nothing. Prisma does not require creation of a CT any longer as we pull from the CT API and this is
enabled by default for all AWS accounts. There is currently a known issue within the product that will provide a Yellow warning stating that we can't find a CT for the account but this can be ignored. Event ingestion will work without it.

CF_REGION: AWS region - e.g. us-east-1 

PRISMA_TENANT: The url you use to access Prisma Cloud - e.g. app.prismacloud.io, app2.prismacloud.io, app.eu.prismacloud.io

EXTERNAL_ID: Unique ID for Cross account role access, e.g. 82ns53h8ag24dnhw2hn3nlks8
[Reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)

CF_STACK_NAME: Optional, name of CloudFormation stack, can be set to anything. If updating already created CloudFormation stack, name must match current AWS stack name.



