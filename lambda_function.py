#coding:utf-8

from __future__ import print_function

import json
import os
from sys import argv

import boto3
import aws_security
import backlog

ec2 = boto3.resource('ec2')

def parse_ec2_instances_markdown():
    content = ['# EC2インスタンス\n']
    content.append('|Nameタグ|インスタンスID|インスタンスタイプ|プライベートIP|EBSボリューム|SG|')
    content.append('|-|-|-|-|-|-|')
    for instance in ec2.instances.all():
        # If instance status is terminated then skip.
        if instance.state.get('Code') == 48:
            continue
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in instance.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get EBS volume
        volume_ids = [device_list['Ebs']['VolumeId'] for device_list in instance.block_device_mappings]
        volume_list = []
        for volumeid in volume_ids:
            volume = ec2.Volume(volumeid)
            try:
                volume_name_tag = [tags['Value'] for tags in volume.tags if tags['Key'] == 'Name']
                volume_name_tag_value = volume_name_tag[0] if len(volume_name_tag) else ' '
            except TypeError:
                volume_name_tag_value = ' '
            volume_size = str(volume.size) + 'GiBs'
            volume_list.append(volumeid + ' (' + volume_name_tag_value + '): ' + volume_size + '<br>')
        volume_info = ''.join(volume_list)
        # Get security groups
        sg_names = [sg_list['GroupName'] for sg_list in instance.security_groups]
        sg_names.sort()
        sg_name = '<br>'.join(sg_names)
        # Create contents
        content.append('|'+name_tag_value+'|'+instance.instance_id+'|'+instance.instance_type+'|'+instance.private_ip_address+'|'+volume_info+'|'+sg_name+'|')
    return '\n'.join(content)

def parse_security_group_markdown():
    #See if any argument was passed. First argument is the script name, skip that one (-1)
    arguments = len(argv) - 1

    #Explicitly declaring variables here grants them global scope
    sgs = ""
    cidr_block = ""
    ip_protpcol = ""
    from_port = ""
    to_port = ""
    port_range = ""
    from_source = ""

    sg_markdown_content = ['# セキュリティグループ\n']
    sg_markdown_content.append("|%s|%s|%s||||" % ("Group-Name", "Group-ID", "Description"))
    sg_markdown_content.append("| ||%s|%s|%s|%s|" % ("In/Out","Protocol","Port","Source/Destination"))
    sg_markdown_content.append("|-|-|-|-|-|-|")

    for region in ["ap-northeast-1"]:
        ec2=boto3.client('ec2', region )

        if arguments == 0:
            sgs = ec2.describe_security_groups()["SecurityGroups"]
        else:
            #Filter on passed SG ID
            sgs = ec2.describe_security_groups(
                Filters=[
                    {
                        'Name': 'group-id',
                        'Values': [argv[1]]
                    }
                ]
            )["SecurityGroups"]

        for sg in sgs:
            group_description = sg['Description']
            group_name = sg['GroupName']
            group_id = sg['GroupId']
            sg_markdown_content.append("|%s|%s|%s||||" % (group_name,group_id,group_description))
            # InBound permissions ##########################################
            inbound = sg['IpPermissions']
            sg_markdown_content.append("|%s|%s|%s||||" % (" ","","Inbound"))
            for rule in inbound:
                if rule['IpProtocol'] == "-1":
                    traffic_type="All Trafic"
                    ip_protpcol="All"
                    to_port="All"
                else:
                    ip_protpcol = rule['IpProtocol']
                    from_port=rule['FromPort']
                    to_port=rule['ToPort']
                    if from_port == to_port:
                        port_range = from_port
                    else:
                        port_range = str(from_port) + ' - ' + str(to_port)
                    #If ICMP, report "N/A" for port #
                    if to_port == -1:
                        to_port = "N/A"

                #Is source/target an IP v4?
                if len(rule['IpRanges']) > 0:
                    for ip_range in rule['IpRanges']:
                        cidr_block = ip_range['CidrIp']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, cidr_block))

                #Is source/target an IP v6?
                if len(rule['Ipv6Ranges']) > 0:
                    for ip_range in rule['Ipv6Ranges']:
                        cidr_block = ip_range['CidrIpv6']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, cidr_block))

                #Is source/target a security group?
                if len(rule['UserIdGroupPairs']) > 0:
                    for source in rule['UserIdGroupPairs']:
                        from_source = source['GroupId']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, from_source))

            # OutBound permissions ##########################################
            outbound = sg['IpPermissionsEgress']
            sg_markdown_content.append("|%s|%s|%s||||" % (" ","","Outbound"))
            for rule in outbound:
                if rule['IpProtocol'] == "-1":
                    traffic_type="All Trafic"
                    ip_protpcol="All"
                    to_port="All"
                else:
                    ip_protpcol = rule['IpProtocol']
                    from_port=rule['FromPort']
                    to_port=rule['ToPort']
                    if from_port == to_port:
                        port_range = from_port
                    else:
                        port_range = str(from_port) + ' - ' + str(to_port)
                    #If ICMP, report "N/A" for port #
                    if to_port == -1:
                        to_port = "N/A"

                #Is source/target an IP v4?
                if len(rule['IpRanges']) > 0:
                    for ip_range in rule['IpRanges']:
                        cidr_block = ip_range['CidrIp']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, cidr_block))

                #Is source/target an IP v6?
                if len(rule['Ipv6Ranges']) > 0:
                    for ip_range in rule['Ipv6Ranges']:
                        cidr_block = ip_range['CidrIpv6']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, cidr_block))

                #Is source/target a security group?
                if len(rule['UserIdGroupPairs']) > 0:
                    for source in rule['UserIdGroupPairs']:
                        from_source = source['GroupId']
                        sg_markdown_content.append("|%s|%s|%s|%s|%s|%s|" % (" ", "", " ", ip_protpcol, port_range, from_source))
        
    return '\n'.join(sg_markdown_content)

def parse_vpc_markdown():
    content = []
    for vpc in ec2.vpcs.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in vpc.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get VPC DNS attributes
        vpc_dns = []
        vpc_dns.append(
            'EnableDnsSupport: '+
            str(vpc.describe_attribute(Attribute='enableDnsSupport')['EnableDnsSupport']['Value']))
        vpc_dns.append(
            'EnableDnsHostnames: '+
            str(vpc.describe_attribute(Attribute='enableDnsHostnames')['EnableDnsHostnames']['Value']))
        vpc_dns_attributes = '<br>'.join(vpc_dns)
        # Create contents
        content.append('|' + name_tag_value + '|' + vpc.vpc_id + '|' + vpc.cidr_block + '|' + vpc.dhcp_options_id + '|' + vpc_dns_attributes + '|' + vpc.instance_tenancy + '|')
    content.sort()
    content.insert(0, '# VPC\n')
    content.insert(1, '|Nameタグ|VPC ID|VPC CIDR|DHCP Options|DNS関連|テナンシー|')
    content.insert(2, '|-|-|-|-|-|-|')
    return '\n'.join(content)

def parse_vpc_subnet_markdown():
    content = []
    for subnet in ec2.subnets.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in subnet.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Create contents
        content.append('|' + name_tag_value + '|' + subnet.subnet_id + '|' + subnet.vpc_id + '|' + subnet.cidr_block + '|' + subnet.availability_zone + '|')
    content.sort()
    content.insert(0, '\n\n# サブネット\n')
    content.insert(1, '|Nameタグ|Subnet ID|VPC ID|CIDR|AZ|')
    content.insert(2, '|-|-|-|-|-|-|')
    return '\n'.join(content)

def parse_dhcp_options_markdown():
    content = []
    for dhcp_option in ec2.dhcp_options_sets.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in dhcp_option.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get dhcp_configurations
        key = []
        for dhcp_option_conf in dhcp_option.dhcp_configurations:
            conf_values = []
            for value in dhcp_option_conf.get('Values'):
                conf_values.append(value.get('Value'))
            conf_value = ', '.join(conf_values)
            key.append(dhcp_option_conf.get('Key') + ' = ' + conf_value)
        config = '<br>'.join(key)
        # Create contents
        content.append('|' + name_tag_value + '|' + dhcp_option.dhcp_options_id + '|' + config + '|')
    content.sort()
    content.insert(0, '\n\n# DHCPオプションセット\n')
    content.insert(1, '|Nameタグ|DHCPオプションセットID|オプション内容|')
    content.insert(2, '|-|-|-|')
    return '\n'.join(content)

def parse_igw_markdown():
    content = []
    for igw in ec2.internet_gateways.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in igw.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get VPC-ID
        if len(igw.attachments) != 0:
            for vpc in igw.attachments:
                vpc_id = vpc.get('VpcId')
        else:
            vpc_id = ' '
        # Create contents
        content.append('|' + name_tag_value + '|' + igw.internet_gateway_id + '|' + vpc_id + '|')
    content.sort()
    content.insert(0, '\n\n# インターネットゲートウェイ\n')
    content.insert(1, '|Nameタグ|IGW ID|VPC ID|')
    content.insert(2, '|-|-|-|')
    return '\n'.join(content) if len(content) != 3 else ''

def parse_vpc_peering_markdown():
    content = []
    for peering in ec2.vpc_peering_connections.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in peering.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Create contents
        requester_ownerid = peering.requester_vpc_info.get('OwnerId')
        requester_vpcid = peering.requester_vpc_info.get('VpcId')
        requester_region = peering.requester_vpc_info.get('Region')
        requester_cidr = peering.requester_vpc_info.get('CidrBlock')
        accepter_ownerid = peering.accepter_vpc_info.get('OwnerId')
        accepter_vpcid = peering.accepter_vpc_info.get('VpcId')
        accepter_region = peering.accepter_vpc_info.get('Region')
        accepter_cidr = peering.accepter_vpc_info.get('CidrBlock')
        content.append('|' + name_tag_value + '|' + peering.vpc_peering_connection_id + '|' \
            + peering.status.get('Code') + '|' \
            + 'AWSアカウント: ' + requester_ownerid + '<br>' \
            + 'VPC ID: ' + requester_vpcid + '<br>' \
            + 'VPCリージョン: ' + requester_region + '<br>' \
            + 'CIDR: ' + requester_cidr + '|' \
            + 'AWSアカウント: ' + accepter_ownerid + '<br>' \
            + 'VPC ID: ' + accepter_vpcid + '<br>' \
            + 'VPCリージョン: ' + accepter_region + '<br>' \
            + 'CIDR: ' + accepter_cidr + '|' \
        )
    content.sort()
    content.insert(0, '\n\n# VPCピアリング\n')
    content.insert(1, '|Nameタグ|Peering ID|ステータス|リクエスタ情報|アクセプタ情報|')
    content.insert(2, '|-|-|-|-|-|')
    return '\n'.join(content) if len(content) != 3 else ''

def parse_vpc_endpoint_markdown():
    content = ['\n\n# VPCエンドポイント\n']
    content_gateway = []
    content_interface = []
    client = boto3.client('ec2')
    vpc_endpoint_list = client.describe_vpc_endpoints().get('VpcEndpoints')
    for item in vpc_endpoint_list:
        if item.get('VpcEndpointType') == 'Gateway':
            content_gateway.append('|' + item.get('VpcEndpointId') + '|' \
                + item.get('VpcId') + '|' \
                + item.get('ServiceName') + '|' \
                + '<br>'.join(item.get('RouteTableIds')) + '|' \
                + json.dumps(json.loads(item.get('PolicyDocument')),indent=2).replace('\n','<br>').replace('  ','　') + '|'
            )
        elif item.get('VpcEndpointType') == 'Interface':
            dns_name_list = []
            subnet_list = []
            securitygroup_list = []
            for dns_entry in item.get('DnsEntries'):
                dns_name_list.append(dns_entry.get('DnsName'))
            for subnet in item.get('SubnetIds'):
                subnet_list.append(subnet)
            for security_group in item.get('Groups'):
                securitygroup_list.append(
                    'SG_ID: ' + security_group.get('GroupId') \
                    + '<br>SG_Name: ' + security_group.get('GroupName')
                )
            content_interface.append('|' + item.get('VpcEndpointId') + '|' \
                + item.get('VpcId') + '|' \
                + item.get('ServiceName') + '|' \
                + '<br>'.join(dns_name_list) + '|' \
                + '<br>'.join(subnet_list) + '|' \
                + '<br>'.join(securitygroup_list) + '|' \
                + str(item.get('PrivateDnsEnabled'))
            )
    content_gateway.sort()
    content_gateway.insert(0, '\n## ゲートウェイエンドポイント\n')
    content_gateway.insert(1, '|エンドポイントID|VPC ID|サービス名|ルートテーブルID|ポリシー|')
    content_gateway.insert(2, '|-|-|-|-|-|')
    content_interface.sort()
    content_interface.insert(0, '\n## インターフェイスエンドポイント\n')
    content_interface.insert(1, '|エンドポイントID|VPC ID|サービス名|DNS名|サブネット|セキュリティグループ|プライベートDNS|')
    content_interface.insert(2, '|-|-|-|-|-|-|-|')
    if len(content_gateway) != 3:
        content += content_gateway
    if len(content_interface) != 3:
        content += content_interface
    return '\n'.join(content) if len(content) != 1 else ''

def parse_vpc_routetable_markdown():
    content = []
    for routetable in ec2.route_tables.all():
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in routetable.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get accociation attributes
        subnet_ids = [rt_attribute.get('SubnetId') for rt_attribute in routetable.associations_attribute if rt_attribute.get('SubnetId') is not None]
        associated_subnet = '<br>'.join(subnet_ids) if len(subnet_ids) else ' '
        # Create contents
        content.append('|' + name_tag_value + '|' + routetable.route_table_id + '|' + associated_subnet + '|||')
        for attribute in routetable.routes_attribute:
            if attribute.get('DestinationCidrBlock') is not None:
                if attribute.get('GatewayId') is not None:
                    content.append('| |||' + attribute.get('DestinationCidrBlock') + '|' + attribute.get('GatewayId')+ '|')
                elif attribute.get('NatGatewayId') is not None:
                    content.append('| |||' + attribute.get('DestinationCidrBlock') + '|' + attribute.get('NatGatewayId')+ '|')
                elif attribute.get('VpcPeeringConnectionId') is not None:
                    content.append('| |||' + attribute.get('DestinationCidrBlock') + '|' + attribute.get('VpcPeeringConnectionId')+ '|')
    content.insert(0, '\n\n# ルートテーブル\n')
    content.insert(1, '|Nameタグ|RouteTable ID|サブネット|||')
    content.insert(2, '| |||宛先|ターゲット|')
    content.insert(3, '|-|-|-|-|-|')
    return '\n'.join(content)

def parse_nacl_markdown():
    content = []
    for nacl in ec2.network_acls.all():
        content_ingress = []
        content_egress = []
        # Get tags
        try:
            name_tag = [tags['Value'] for tags in nacl.tags if tags['Key'] == 'Name']
            name_tag_value = name_tag[0] if len(name_tag) else ' '
        except TypeError:
            name_tag_value = ' '
        # Get accociation attributes
        subnet_ids = [nacl_association.get('SubnetId') for nacl_association in nacl.associations if nacl_association.get('SubnetId') is not None]
        associated_subnet = '<br>'.join(subnet_ids) if len(subnet_ids) else ' '
        # Create contents
        content.append('|' + name_tag_value + '|' + nacl.network_acl_id + '|' + nacl.vpc_id + '|'+ associated_subnet +'||||')
        for nacl_entry in nacl.entries:
            if nacl_entry.get('Protocol') == '6':
                protocol_name = 'TCP'
            elif nacl_entry.get('Protocol') == '17':
                protocol_name = 'UDP'
            elif nacl_entry.get('Protocol') == '1':
                protocol_name = 'ICMP'
            elif nacl_entry.get('Protocol') == '-1':
                protocol_name = 'ALL'
            else:
                protocol_name = nacl_entry.get('Protocol')
            if nacl_entry.get('PortRange') is None:
                port = 'ALL'
            elif nacl_entry.get('PortRange').get('From') == nacl_entry.get('PortRange').get('To'):
                port = str(nacl_entry.get('PortRange').get('From'))
            else:
                port = str(nacl_entry.get('PortRange').get('From')) + ' - ' \
                    + str(nacl_entry.get('PortRange').get('To'))
            if nacl_entry.get('Egress'):
                content_egress.append('| ||' + str(nacl_entry.get('RuleNumber')).zfill(5) + '|' \
                    + protocol_name + '|' \
                    + port + '|' \
                    + nacl_entry.get('CidrBlock') + '|' \
                    + nacl_entry.get('RuleAction') + '|'
                )
            else:
                content_ingress.append('| ||' + str(nacl_entry.get('RuleNumber')).zfill(5) + '|' \
                    + protocol_name + '|' \
                    + port + '|' \
                    + nacl_entry.get('CidrBlock') + '|' \
                    + nacl_entry.get('RuleAction') + '|'
                )
        content_ingress.sort()
        content_ingress.insert(0, '| |インバウンドルール||||||')
        content_egress.sort()
        content_egress.insert(0, '| |アウトバウンドルール||||||')
        if len(content_ingress) != 1:
            content += content_ingress
        if len(content_egress) != 1:
            content += content_egress
    content.insert(0, '\n\n# ネットワークACL\n')
    content.insert(1, '|Nameタグ|Network ACL ID|VPC ID|適用サブネットID||||')
    content.insert(2, '| ||Rule ID|Protocol|Port Range|CIDR|Action|')
    content.insert(3, '|-|-|-|-|-|-|-|')
    return '\n'.join(content)

def lambda_handler(event, context):
    backlog_spaceid = aws_security.decrypt_text_by_kms(os.getenv('backlog_spaceid'))
    backlog_apikey = aws_security.decrypt_text_by_kms(os.getenv('backlog_apikey'))
    backlog_ec2_wikiid_encrypted = os.getenv('ec2_backlog_wikiid')
    ec2_backlog_url = backlog.generate_backlog_wiki_url(
        backlog_spaceid,
        aws_security.decrypt_text_by_kms(backlog_ec2_wikiid_encrypted),
        backlog_apikey
    )
    ec2_instances_markdown = parse_ec2_instances_markdown() + '\n\n' + parse_security_group_markdown()
    
    # EC2&SG
    if ec2_instances_markdown != backlog.get_backlog_wiki_content(ec2_backlog_url):
        if not backlog.update_backlog_wiki(ec2_backlog_url, ec2_instances_markdown).ok:
            print("Failed to update backlog EC2 wiki.")
        print('EC2 wiki Update completed successfully.')
    else:
        print('No differences found between EC2 wiki and resources.')
    
    # VPC
    backlog_vpc_wikiid_encrypted = os.getenv('vpc_backlog_wikiid')
    if backlog_vpc_wikiid_encrypted is not None:
        vpc_backlog_url = backlog.generate_backlog_wiki_url(
            backlog_spaceid,
            aws_security.decrypt_text_by_kms(backlog_vpc_wikiid_encrypted),
            backlog_apikey
        )
        vpc_markdown = parse_vpc_markdown()\
            + parse_vpc_subnet_markdown()\
            + parse_dhcp_options_markdown()\
            + parse_igw_markdown()\
            + parse_vpc_peering_markdown()\
            + parse_vpc_routetable_markdown()\
            + parse_vpc_endpoint_markdown()\
            + parse_nacl_markdown()
        if vpc_markdown != backlog.get_backlog_wiki_content(vpc_backlog_url):
            if not backlog.update_backlog_wiki(vpc_backlog_url, vpc_markdown).ok:
                print("Failed to update backlog VPC wiki.")
            print('VPC wiki update completed successfully.')
        else:
            print('No differences found between VPC wiki and resources.')
