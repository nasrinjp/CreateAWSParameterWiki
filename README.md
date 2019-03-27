AWSパラメータシートをBacklog Wikiに作成する
====

## 事前準備
更新対象のBacklog wikiはあらかじめ作成しておいてください。  
このスクリプトではwikiの更新のみで、作成はしません。  
Wikiのidは、短縮URLの末尾の数字になります。  
BacklogのAPIキーも、取得しておきましょう。


## Install

AWS Lambdaでlambda_function.pyをアップロードするだけです。  
ランタイムは Python 3.7 で動作確認しています。  
必要に応じて基本設定のタイムアウトを伸ばしてください。

### 必要なLambda Layer
テストしたARNは下記の通りです。

|LayerName|VersionARN|
|-|-|
|backlog|arn:aws:lambda:ap-northeast-1:593649893041:layer:backlog:2|
|aws_security|arn:aws:lambda:ap-northeast-1:593649893041:layer:aws_security:1|

### Lambda環境変数
Lambda環境変数で下記を設定します。  
トークンをプレーンテキストで保存しないよう、KMSのキーを使って暗号化してください。

backlog_spaceid：BacklogのスペースIDです。  
backlog_apikey：BacklogのWikiに書き込むためのBacklogのapikeyです。  
ec2_backlog_wikiid：EC2パラメータシートのWikiIDです。  

### IAMロール
下記のポリシーを付与したIAMロールを使用してください。  
AWSLambdaBasicExecutionRoleポリシー  
ReadOnlyAccessポリシー  
kms:Decrypt アクションを許可したポリシー
