'''
Module to process .rules files containing the word 'exploit' and update messages based on translation.
'''
import os
import re
from translate import translate_text


def process_files():
    """
    Process all .rules files in the 'rules' directory that contain the word 'exploit'.
    """
    for root, dirs, files in os.walk('rules'):
        for file in files:
            if 'exploit.rules' in file and file.endswith('.rules'):
                process_file(os.path.join(root, file))


def process_file(filepath):
    """
    Read a .rules file, extract messages, translate them, and write the results to csa.rules.
    """
    regex = re.compile(r'\s*alert [^\(]*\(msg:"([^"]+)";.*\)')
    with open(filepath, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    with open("csa.rules", "a", encoding='utf-8') as output:
        # 定义 Set
        portVars = set()
        for line in lines:
            if not line.strip().startswith('#'):
                match = regex.search(line)
                if match:
                    # 从 line 中提取所有 \$\w+_PORTS
                    ports = re.findall(r'\$(\w+_PORTS)', line)
                    # 如果有则添加每一个匹配到的名称到 portVars 中
                    if ports:
                        portVars.update(ports)
                    original_msg = match.group(1)
                    # 删除开头的 'ET EXPLOIT ' 或 'GPL EXPLOIT '
                    original_simple_msg = original_msg.replace('ET EXPLOIT ', '').replace('GPL EXPLOIT ', '').replace('[NCC GROUP] ', '').replace('[PT Security] ', '').replace('[401TRG] ', '').replace('ET EXPLOIT_KIT ', '')
                    translated_msg = translate_text(original_simple_msg)
                    print(f'Original: {original_msg}, Translated: {translated_msg}')
                    modified_line = line.replace(f'msg:"{original_msg}"', f'msg:"{translated_msg}"')
                    output.write(modified_line)
        print(f'务必在 suricata 配置文件中(/platform/appconf/dpdk_release.yaml)配置以下端口:  {portVars}')
