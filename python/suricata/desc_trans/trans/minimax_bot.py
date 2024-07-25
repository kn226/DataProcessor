from suricata.desc_trans.trans.bot_factory import BaseBot


class MiniMaxBot(BaseBot):

    def get_access_token(self):
        pass

    def ask_q(self, q=None) -> dict:
        pass

    @staticmethod
    def get_seq() -> int:
        return 3

