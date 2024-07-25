# sid:desc
import sys

from suricata.desc_trans.trans.bot_factory import BaseBot
from suricata.desc_trans.trans.doubao_bot import DoubaoBot
from suricata.desc_trans.trans.minimax_bot import MiniMaxBot
from suricata.desc_trans.trans.tongyi_bot import TongyiBot
from suricata.desc_trans.trans.xinghuo_bot import XinghuoBot
from suricata.desc_trans.trans.yiyan_bot import YiyanBot
from tqdm import tqdm

rule_d = {}
platform_d = {}


# todo
def read_rules(bot):
    with open("csa.rules", "r", encoding='utf-8') as file:
        lines = file.readlines()
        for i in tqdm(range(len(lines))):
            resp = bot.ask_q(lines[i])
            with open("desc.dict", 'a', encoding='utf-8') as output:
                output.write(str(resp) + "\n")


def init_platform(platform: int = 0):
    if platform == 0:
        b = YiyanBot()
    elif platform == 1:
        b = XinghuoBot()
    elif platform == 2:
        b = TongyiBot()
    elif platform == 3:
        b = MiniMaxBot()
    else:
        b = DoubaoBot()

    return b


if __name__ == '__main__':
    b = init_platform(0 if len(sys.argv) < 2 else sys.argv[1])
    read_rules(b)
