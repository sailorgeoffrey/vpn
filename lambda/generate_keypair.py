import os,base64,json,boto3,urllib.request
P=2**255-19
def _kp():
 k=bytearray(os.urandom(32));k[0]&=248;k[31]&=127;k[31]|=64
 x1=9;x2=1;z2=0;x3=9;z3=1;sw=0
 for t in range(254,-1,-1):
  b=(k[t>>3]>>(t&7))&1;sw^=b
  if sw:x2,x3=x3,x2;z2,z3=z3,z2
  sw=b
  A=(x2+z2)%P;AA=A*A%P;B=(x2-z2)%P;BB=B*B%P;E=(AA-BB)%P
  C=(x3+z3)%P;D=(x3-z3)%P;DA=D*A%P;CB=C*B%P
  x3=pow(DA+CB,2,P);z3=x1*pow(DA-CB,2,P)%P
  x2=AA*BB%P;z2=E*(AA+121665*E)%P
 if sw:x2,x3=x3,x2;z2,z3=z3,z2
 pub=(x2*pow(z2,P-2,P)%P).to_bytes(32,'little')
 return base64.b64encode(bytes(k)).decode(),base64.b64encode(pub).decode()
def _resp(event,status,reason=''):
 body=json.dumps({'Status':status,'Reason':reason,'PhysicalResourceId':event.get('PhysicalResourceId','kp'),'StackId':event['StackId'],'RequestId':event['RequestId'],'LogicalResourceId':event['LogicalResourceId'],'Data':{}})
 r=urllib.request.Request(event['ResponseURL'],data=body.encode(),method='PUT');r.add_header('Content-Type','')
 urllib.request.urlopen(r)
def handler(event,context):
 region=os.environ['REGION'];alias=os.environ['REGION_ALIAS'];kms=os.environ['KMS_KEY_ARN']
 pp=f'/wireguard/{alias}/client/private-key';pub=f'/wireguard/{alias}/client/public-key'
 ssm=boto3.client('ssm',region_name=region)
 try:
  rt=event['RequestType']
  if rt in('Create','Update'):
   gen=rt=='Create'
   if not gen:gen=(event.get('OldResourceProperties')or{}).get('Version','')!=(event.get('ResourceProperties')or{}).get('Version','')
   if gen:
    priv,pubk=_kp()
    for n,v in((pp,priv),(pub,pubk)):ssm.put_parameter(Name=n,Value=v,Type='SecureString',KeyId=kms,Overwrite=True)
  elif rt=='Delete':
   for n in(pp,pub):
    try:ssm.delete_parameter(Name=n)
    except:pass
  _resp(event,'SUCCESS')
 except Exception as e:_resp(event,'FAILED',str(e));raise
