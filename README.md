# iac-pulumi

This README provides instructions on how to run this [Plumi](https://plumi.org/) project sharing platform on Amazon Web Services (AWS).

## Prerequisites

Before running plumi make sure you have:

1. **AWS Account**: You need an AWS account. If you don't have one, you can create an account [here](https://aws.amazon.com/).

2. **IAM User and Access Keys**: Create an IAM user in AWS and generate access keys. Follow the instructions [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html) to create an IAM user and generate access keys. You will need these access keys to configure AWS access in Plumi.

3. **AWS CLI**: Install and configure the AWS Command Line Interface (CLI) on your local machine. You can find installation instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html).
4. Install pulumi, follow instructions [here](https://www.pulumi.com/docs/install/)

## Running iac pulumi

Follow these steps to deploy Plumi on AWS:

1. **Clone the Plumi Repository**:
2. go to plumi project
   ```bash
   cd iac-pulumi/pulumi
   ```
3. to create resources
   ```bash
   pulumi up
   ```
4. to destroy resources
   ```bash
   pulumi destroy
   ```

## Configuration

aws and other config settings can be changed from pulumi.dev.yaml file

## SSL Certificate

To import SSL certificate in aws certificate manager use the following command

```bash
aws acm import-certificate --profile <aws profile> \
  --certificate fileb://<certificate file> \
  --private-key fileb://<private key file>
```

## Maintenance and Customization

For ongoing maintenance and customization of your Plumi AWS deployment, please refer to the [Plumi documentation](https://plumi.readthedocs.io/en/latest/).

hello makrand
How are you??
okay
