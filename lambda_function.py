import jwt
import boto3
from botocore.exceptions import ClientError

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
table_name = "Client"


def lambda_handler(event, context):
    token = event['authorizationToken']
    method_arn = event['methodArn']

    # Decode the JWT token
    try:
        decoded_token = jwt.decode(token, 'D9texL9_fknC5cb0h-ik2INJyzdona14ZlHoLuOA8nE=', algorithms=['HS256'])
        document = decoded_token['document']
    except jwt.ExpiredSignatureError as e:
        print(f"ExpiredSignatureError: {e}")
        return generate_policy('unauthorized', 'Deny', method_arn)
    except jwt.InvalidTokenError as e:
        print(f"InvalidTokenError: {e}")
        return generate_policy('unauthorized', 'Deny', method_arn)

    # Check if user exists in DynamoDB
    table = dynamodb.Table(table_name)
    try:
        response = table.get_item(Key={'document': document})
        if 'Item' not in response:
            return generate_policy('unauthorized', 'Deny', method_arn)
    except ClientError as e:
        print(f"Error fetching user from DynamoDB: {e}")
        return generate_policy('unauthorized', 'Deny', method_arn)

    return generate_policy(document, 'Allow', method_arn)


def generate_policy(principal_id, effect, resource):
    auth_response = {'principalId': principal_id}
    if effect and resource:
        policy_document = {'Version': '2012-10-17', 'Statement': []}
        statement = {'Action': 'execute-api:Invoke', 'Effect': effect, 'Resource': resource}
        policy_document['Statement'].append(statement)
        auth_response['policyDocument'] = policy_document
    return auth_response
