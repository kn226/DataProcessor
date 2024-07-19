'''
Module to process .rules files containing the word 'exploit' and update messages based on translation.
'''
import os
import re

from translate import translate_text

exclude_file_list = ['emerging-deleted.rules']
file_list = ['emerging-exploit.rules', 'emerging-coinminer.rules']
classtype_list = ['command-and-control', 'coin-mining', 'credential-theft', 'successful-recon-largescale',
                  'successful-dos', 'non-standard-protocol', 'attempted-recon', 'web-application-attack',
                  'trojan-activity', 'unsuccessful-user', 'successful-user', 'successful-admin', 'shellcode-detect',
                  'attempted-user', 'attempted-admin']
# 定义 Set
portVars = set()


def process_files():
    """
    Process all .rules files in the 'rules' directory that contain the word 'exploit'.
    """
    for root, dirs, files in os.walk('rules'):
        for file in files:
            if file in exclude_file_list or not file.endswith('.rules'):
                print(f'Skipping {file}...')
                continue
            elif file in file_list:
                print(f'Processing {file}...')
                process_file(os.path.join(root, file), True)
            else:
                print(f'analysis {file}...')
                process_file(os.path.join(root, file), False)


def process_file(filepath, full_file):
    """
    Read a .rules file, extract messages, translate them, and write the results to csa.rules.
    """
    regex = re.compile(r'\s*alert [^\(]*\(msg:"([^"]+)";.*\)')
    classtype_regex = re.compile(r'\bclasstype:(\S+);')
    with open(filepath, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    with open("csa.rules", "a", encoding='utf-8') as output:
        for line in lines:
            if not line.strip().startswith('#'):
                match = regex.search(line)
                # 从 line 中提取 classtype 字段
                classtype_match = classtype_regex.search(line)
                if not full_file and classtype_match:
                    classtype = classtype_match.group(1)
                if match and (full_file or classtype in classtype_list):
                    # 从 line 中提取所有 \$\w+_PORTS
                    ports = re.findall(r'\$(\w+_PORTS)', line)
                    # 如果有则添加每一个匹配到的名称到 portVars 中
                    if ports:
                        portVars.update(ports)
                    original_msg = match.group(1)
                    # 删除开头的 'ET EXPLOIT ' 或 'GPL EXPLOIT '
                    original_simple_msg = original_msg.replace('ET EXPLOIT ', '').replace('GPL EXPLOIT ', '').replace(
                        '[NCC GROUP] ', '').replace('[PT Security] ', '').replace('[401TRG] ', '').replace(
                        'ET EXPLOIT_KIT ', '').replace('ET ACTIVEX ', '').replace('ET ADWARE_PUP', '').replace(
                        'ET ATTACK_RESPONSE ', 'ATTACK_RESPONSE ').replace(
                        'GPL ATTACK_RESPONSE ', 'ATTACK_RESPONSE ').replace('ET COINMINER ', '').replace(
                        'ET CURRENT_EVENTS ', '').replace('ET DNS ', '').replace('ET HUNTING ', '').replace(
                        'ET INFO ', '').replace('ET MALWARE ', 'MALWARE ').replace('ET CNC ', '').replace('[Fireeye] ',
                                                                                                          '')

                    translated_msg = translate_text(original_simple_msg)
                    modified_line = line.replace(f'msg:"{original_msg}"', f'msg:"{translated_msg}"')
                    output.write(modified_line)
        if portVars:
            print(f'务必在 suricata 配置文件中(/platform/appconf/dpdk_release.yaml)配置以下端口:  {portVars}')
