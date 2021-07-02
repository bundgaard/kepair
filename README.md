# WHAT IS IT?
Kepair is an AWS EC2 SSH Key creation CLI.
The idea is not to do anything UI related and works entirely using the AWS SDK with AWS Access Token.

The process is very simple:
1. Create SSH key in memory, default bitsize 4096
2. Import key to EC2
3. Save key to Secrets manager
4. Done

If any error happens it will try to remove the key from EC2.

Have fun

Thanks

