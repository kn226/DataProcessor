import json

from suricata.desc_trans.trans.bot_factory import BaseBot

from openai import OpenAI


class TongyiBot(BaseBot):
    API_KEY = ""

    def get_access_token(self):
        pass

    def ask_q(self, q=None) -> dict:
        client = OpenAI(
            api_key=self.API_KEY,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",  # 填写DashScope服务的base_url
        )
        completion = client.chat.completions.create(
            model="qwen-turbo",
            messages=[
                {'role': 'user', 'content': f"解释一下 suricata 入侵检测规则: `{q}`"}
            ],
            temperature=0.8,
            top_p=0.8
        )
        resp = json.loads(completion.model_dump_json())

        ans = {'sid': self.get_sid(q), 'result': resp["choices"][0]['message']['content']}
        return ans

    @staticmethod
    def get_seq() -> int:
        return 2


if __name__ == '__main__':
    t = TongyiBot()
    resp = t.ask_q(
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"AVTECH 软件 ActiveX SendCommand 方法缓冲区溢出尝试"; flow:established,to_client; content:"<OBJECT "; nocase; content:"classid"; nocase; distance:0; content:"clsid"; nocase; distance:0; content:"8214B72E-B0CD-466E-A44D-1D54D926038D"; nocase; distance:0; content:"SendCommand"; nocase; reference:url,zeroscience.mk/en/vulnerabilities/ZSL-2010-4934.php; reference:url,exploit-db.com/exploits/12294; classtype:attempted-user; sid:2011200; rev:4; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, confidence High, signature_severity Major, tag ActiveX, updated_at 2019_09_27;)')

    with open("../desc1.dict", 'a', encoding='utf-8') as output:
        output.write(str(resp) + "\n")
