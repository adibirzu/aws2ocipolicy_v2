from translator import translate_simple_policy

result = translate_simple_policy('{"Statement": [{"Effect": "Allow", "Action": ["ec2:RunInstances", "ec2:DescribeInstances"], "Resource": ["*"]}]}', 'Administrators')
print(f"Policy output:\n{result}")
