import json

from suricata.desc_trans.constants import Constants
from suricata.desc_trans.trans.bot_factory import BaseBot

from openai import OpenAI

# Constants 文件省略
API_KEY = Constants.TONG_YI_API_KEY


class TongyiBot(BaseBot):

    def get_access_token(self):
        pass

    def ask_q(self, q: str, sid_cache: dict) -> dict:
        sid = self.get_sid(q)
        if sid in sid_cache:
            return {}
        msg = self.get_msg(q)
        client = OpenAI(
            api_key=API_KEY,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # 填写DashScope服务的base_url
        )
        completion = client.chat.completions.create(
            model="qwen-turbo",
            messages=[
                {'role': 'user', 'content': f"解释一下如下的工控规则{q if len(msg) == 0 else msg}"}
            ],
            temperature=0.8,
            top_p=0.8
        )
        resp = json.loads(completion.model_dump_json())

        ans = {'sid': sid, 'result': resp["choices"][0]['message']['content']}
        return ans

    @staticmethod
    def get_seq() -> int:
        return 2


if __name__ == '__main__':
    t = TongyiBot()
    resp = t.ask_q(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Telesquare SDT-CW3B1 1.1.0 - 操作系统命令注入漏洞 (CVE-2021-46422)"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/cgi-bin/admin.cgi?Command=sysCommand&Cmd="; fast_pattern; startswith; http.header_names; content:!"Referer"; reference:cve,2021-46422; reference:url,twitter.com/momika233/status/1528742287072980992; classtype:attempted-admin; sid:2036663; rev:1; metadata:attack_target Networking_Equipment, created_at 2022_05_23, cve CVE_2021_46422, deployment Perimeter, deployment SSLDecrypt, performance_impact Low, signature_severity Major, updated_at 2022_05_23, mitre_tactic_id TA0008, mitre_tactic_name Lateral_Movement, mitre_technique_id T1210, mitre_technique_name Exploitation_Of_Remote_Services;)',
        {})

    with open("../desc1.dict", 'a', encoding='utf-8') as output:
        output.write(str(resp) + "\n")
