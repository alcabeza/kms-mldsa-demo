#!/usr/bin/env python3
"""Rebuild template.yaml: embeds src/main/java/demo/KmsMlDsaDemo.java, pom.xml (plain text) and
ec2-scripts/*.sh (gzip'ed tar, base64) into the CloudFormation template skeleton below.
Usage: python3 build-template.py   (run from anywhere)"""
import base64, gzip, io, pathlib, tarfile
root = pathlib.Path(__file__).resolve().parent
java = (root/"src/main/java/demo/KmsMlDsaDemo.java").read_text()
pom = (root/"pom.xml").read_text()

run_sh = """#!/bin/bash
# Runs the demo on the instance. Re-runnable: sudo /opt/kms-mldsa-demo/run-demo.sh
set -a; . /opt/kms-mldsa-demo/demo.env; set +a
export JAVA_HOME=/usr/lib/jvm/java-25-amazon-corretto
export PATH=$JAVA_HOME/bin:/opt/apache-maven/bin:$PATH
cd /opt/kms-mldsa-demo
java -version 2>&1 | head -1
mvn -q -B exec:java
"""

def build_tgz():
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for p in sorted((root / "ec2-scripts").glob("*.sh")):
                data = p.read_bytes()
                ti = tarfile.TarInfo(p.name)
                ti.size, ti.mode, ti.mtime = len(data), 0o755, 0
                ti.uid = ti.gid = 0
                ti.uname = ti.gname = "root"
                tar.addfile(ti, io.BytesIO(data))
    b64 = base64.b64encode(buf.getvalue()).decode()
    return "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))

def ind(s, n):
    pad = " " * n
    return "\n".join((pad + l) if l.strip() else "" for l in s.rstrip("\n").split("\n"))

tpl = r'''AWSTemplateFormatVersion: "2010-09-09"
Description: >-
  Self-contained demo of AWS KMS post-quantum signatures (ML-DSA, FIPS 204).
  Creates an ML-DSA KMS key, an ECDSA P-256 baseline key, a small VPC, and an EC2 instance
  (Amazon Linux 2023, no inbound ports, SSM access) that installs JDK 25 + Maven, builds the
  embedded Java demo, runs it and records results. The verification and benchmark scripts are
  embedded too (/opt/kms-mldsa-demo/scripts). Delete the stack to remove everything.

Parameters:
  MlDsaKeySpec:
    Type: String
    Default: ML_DSA_65
    AllowedValues: [ML_DSA_44, ML_DSA_65, ML_DSA_87]
    Description: ML-DSA parameter set (NIST level 2 / 3 / 5). Cannot be changed after creation.
  InstanceType:
    Type: String
    Default: t3.medium
    AllowedValues: [t3.small, t3.medium, t3.large, m6i.large, c6i.large]
    Description: x86_64 instance type used to build and run the demo.
  AmiId:
    Type: AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>
    Default: /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64
    Description: Latest Amazon Linux 2023 x86_64 AMI (resolved at deploy time).
  Iterations:
    Type: Number
    Default: 200
    MinValue: 20
    MaxValue: 5000
    Description: Measured calls per operation in the latency benchmark.
  Warmup:
    Type: Number
    Default: 20
    MinValue: 0
    MaxValue: 500
    Description: Warm-up calls per operation (not measured).
  KeyDeletionWindowDays:
    Type: Number
    Default: 7
    MinValue: 7
    MaxValue: 30
    Description: Waiting period before the KMS keys are deleted when the stack is deleted.

Resources:
  # ---------------------------------------------------------------- KMS keys
  MlDsaKey:
    Type: AWS::KMS::Key
    DeletionPolicy: Delete
    UpdateReplacePolicy: Delete
    Properties:
      Description: !Sub "${AWS::StackName} - ML-DSA signing key (post-quantum demo)"
      KeySpec: !Ref MlDsaKeySpec
      KeyUsage: SIGN_VERIFY
      PendingWindowInDays: !Ref KeyDeletionWindowDays
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableIamPolicies
            Effect: Allow
            Principal:
              AWS: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"
      Tags:
        - Key: purpose
          Value: pq-signature-demo

  MlDsaKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub "alias/${AWS::StackName}-mldsa"
      TargetKeyId: !Ref MlDsaKey

  EcdsaKey:
    Type: AWS::KMS::Key
    DeletionPolicy: Delete
    UpdateReplacePolicy: Delete
    Properties:
      Description: !Sub "${AWS::StackName} - ECDSA P-256 baseline key (classical, quantum-vulnerable)"
      KeySpec: ECC_NIST_P256
      KeyUsage: SIGN_VERIFY
      PendingWindowInDays: !Ref KeyDeletionWindowDays
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableIamPolicies
            Effect: Allow
            Principal:
              AWS: !Sub "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"
      Tags:
        - Key: purpose
          Value: pq-signature-demo-baseline

  EcdsaKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Sub "alias/${AWS::StackName}-ecdsa-p256"
      TargetKeyId: !Ref EcdsaKey

  # ---------------------------------------------------------------- IAM
  DemoPolicy:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      Description: Least-privilege access for the KMS ML-DSA demo (sign, verify, read public key).
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: SignVerifyDemoKeysOnly
            Effect: Allow
            Action:
              - kms:Sign
              - kms:Verify
              - kms:GetPublicKey
              - kms:DescribeKey
            Resource:
              - !GetAtt MlDsaKey.Arn
              - !GetAtt EcdsaKey.Arn

  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - !Ref DemoPolicy
        - !Sub "arn:${AWS::Partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
      Policies:
        - PolicyName: cfn-init-and-signal
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - cloudformation:DescribeStackResource
                  - cloudformation:SignalResource
                Resource: !Ref AWS::StackId

  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref InstanceRole

  # ---------------------------------------------------------------- Network (outbound only)
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.77.0.0/24
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-vpc"

  InternetGateway:
    Type: AWS::EC2::InternetGateway

  GatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref Vpc
      InternetGatewayId: !Ref InternetGateway

  PublicSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.77.0.0/25
      AvailabilityZone: !Select [0, !GetAZs ""]
      MapPublicIpOnLaunch: true

  RouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref Vpc

  DefaultRoute:
    Type: AWS::EC2::Route
    DependsOn: GatewayAttachment
    Properties:
      RouteTableId: !Ref RouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref InternetGateway

  SubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref PublicSubnet
      RouteTableId: !Ref RouteTable

  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: No inbound access. Outbound HTTPS/HTTP only (package downloads, KMS, SSM).
      VpcId: !Ref Vpc
      SecurityGroupEgress:
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0

  # ---------------------------------------------------------------- EC2
  DemoLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        MetadataOptions:
          HttpTokens: required
          HttpEndpoint: enabled
          HttpPutResponseHopLimit: 1

  DemoInstance:
    Type: AWS::EC2::Instance
    DependsOn:
      - DefaultRoute
      - SubnetRouteTableAssociation
    CreationPolicy:
      ResourceSignal:
        Count: 1
        Timeout: PT30M
    Metadata:
      AWS::CloudFormation::Init:
        config:
          files:
            /opt/kms-mldsa-demo/demo.env:
              mode: "000644"
              owner: root
              group: root
              content: !Sub |
                AWS_REGION=${AWS::Region}
                AWS_DEFAULT_REGION=${AWS::Region}
                ML_DSA_KEY_ID=${MlDsaKey}
                ECDSA_KEY_ID=${EcdsaKey}
                ITERATIONS=${Iterations}
                WARMUP=${Warmup}
            /opt/kms-mldsa-demo/run-demo.sh:
              mode: "000755"
              owner: root
              group: root
              content: |
__RUN__
            /opt/kms-mldsa-demo/pom.xml:
              mode: "000644"
              owner: root
              group: root
              content: |
__POM__
            /opt/kms-mldsa-demo/src/main/java/demo/KmsMlDsaDemo.java:
              mode: "000644"
              owner: root
              group: root
              content: |
__JAVA__
            /opt/kms-mldsa-demo/scripts.tgz:
              encoding: base64
              mode: "000644"
              owner: root
              group: root
              content: |
__TGZ__
          commands:
            10-extract-scripts:
              command: >-
                mkdir -p /opt/kms-mldsa-demo/scripts &&
                tar -xzf /opt/kms-mldsa-demo/scripts.tgz -C /opt/kms-mldsa-demo/scripts &&
                chmod 755 /opt/kms-mldsa-demo/scripts/*.sh
    Properties:
      ImageId: !Ref AmiId
      InstanceType: !Ref InstanceType
      IamInstanceProfile: !Ref InstanceProfile
      LaunchTemplate:
        LaunchTemplateId: !Ref DemoLaunchTemplate
        Version: !GetAtt DemoLaunchTemplate.LatestVersionNumber
      SubnetId: !Ref PublicSubnet
      SecurityGroupIds:
        - !Ref InstanceSecurityGroup
      BlockDeviceMappings:
        - DeviceName: /dev/xvda
          Ebs:
            VolumeSize: 16
            VolumeType: gp3
            Encrypted: true
      Tags:
        - Key: Name
          Value: !Sub "${AWS::StackName}-demo"
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          exec > >(tee /var/log/kms-mldsa-userdata.log | tee /dev/console) 2>&1
          set -u
          rc=0

          echo "== setup: JDK 25 + Maven + cfn-bootstrap"
          dnf -y --releasever=latest install java-25-amazon-corretto-devel aws-cfn-bootstrap tar gzip || rc=1
          if [ ! -x /usr/lib/jvm/java-25-amazon-corretto/bin/javac ]; then
            rpm --import https://yum.corretto.aws/corretto.key
            curl -fsSL -o /etc/yum.repos.d/corretto.repo https://yum.corretto.aws/corretto.repo
            dnf -y install java-25-amazon-corretto-devel && rc=0 || rc=1
          fi
          curl -fsSL https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz \
            | tar -xz -C /opt || rc=1
          ln -sfn /opt/apache-maven-3.9.9 /opt/apache-maven

          echo "== cfn-init (writes the embedded demo sources)"
          /opt/aws/bin/cfn-init -v --stack ${AWS::StackName} --resource DemoInstance --region ${AWS::Region} || rc=1

          if [ $rc -eq 0 ]; then
            echo "== build + run demo (log: /var/log/kms-mldsa-demo.log)"
            bash -c '. /opt/kms-mldsa-demo/demo.env; export JAVA_HOME=/usr/lib/jvm/java-25-amazon-corretto; export PATH=$JAVA_HOME/bin:/opt/apache-maven/bin:$PATH; cd /opt/kms-mldsa-demo && mvn -q -B compile' || rc=1
          fi
          if [ $rc -eq 0 ]; then
            /opt/kms-mldsa-demo/run-demo.sh 2>&1 | tee /var/log/kms-mldsa-demo.log | tee /dev/console
            echo "demo exit code: ${!PIPESTATUS[0]}" | tee -a /var/log/kms-mldsa-demo.log
          fi
          touch /var/log/kms-mldsa-demo.done

          /opt/aws/bin/cfn-signal -e $rc --stack ${AWS::StackName} --resource DemoInstance --region ${AWS::Region} \
            --reason "setup rc=$rc (demo results: /var/log/kms-mldsa-demo.log)"

Outputs:
  InstanceId:
    Value: !Ref DemoInstance
  MlDsaKeyId:
    Description: ML-DSA key ID
    Value: !Ref MlDsaKey
  EcdsaKeyId:
    Description: ECDSA P-256 baseline key ID
    Value: !Ref EcdsaKey
  DemoPolicyArn:
    Description: Policy granting sign/verify/get-public-key on both keys (attach to other identities if needed).
    Value: !Ref DemoPolicy
  ScriptsDirectory:
    Description: Verification, test and benchmark scripts on the instance (01 install, 02 KMS deployment, 03 benchmark, 04 functional tests).
    Value: /opt/kms-mldsa-demo/scripts
  ShowResultsCommand:
    Description: Print the demo results from the instance via SSM Run Command (no SSH needed).
    Value: !Sub >-
      aws ssm send-command --region ${AWS::Region} --instance-ids ${DemoInstance}
      --document-name AWS-RunShellScript --parameters 'commands=["cat /var/log/kms-mldsa-demo.log"]'
      --query Command.CommandId --output text
  ConsoleOutputCommand:
    Description: Alternative - read the demo output from the EC2 console log.
    Value: !Sub "aws ec2 get-console-output --region ${AWS::Region} --instance-id ${DemoInstance} --latest --output text"
  SessionCommand:
    Description: Open a shell on the instance (needs the Session Manager plugin).
    Value: !Sub "aws ssm start-session --region ${AWS::Region} --target ${DemoInstance}"
'''
out = (tpl.replace("__RUN__", ind(run_sh, 16)).replace("__POM__", ind(pom, 16))
       .replace("__JAVA__", ind(java, 16)).replace("__TGZ__", ind(build_tgz(), 16)))
(root/"template.yaml").write_text(out)
print(f"template.yaml: {len(out.encode())} bytes (limit 51200 for direct upload)")
