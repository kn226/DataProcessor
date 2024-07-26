import ast
import os
import importlib.util
import re
from abc import abstractmethod, ABC
from typing import Type

# def import_modules_from_folder():
#     # 所有实现类在当前文件夹下
#     folder = os.path.dirname(os.path.abspath(__file__))
#     for filename in os.listdir(folder):
#         if not filename.endswith(".py") or filename == os.path.basename(__file__):
#             continue
#         module_name = filename[:-3]
#         module_path = os.path.join(folder, filename)
#         spec = importlib.util.spec_from_file_location(module_name, module_path)
#         module = importlib.util.module_from_spec(spec)
#         spec.loader.exec_module(module)
#         globals()[module_name] = module
#         print(f"Imported module: {module_name}")


# def get_all_subclasses(cls):
#     subclasses = set(cls.__subclasses__())
#     for subclass in cls.__subclasses__():
#         subclasses.update(get_all_subclasses(subclass))
#     return subclasses

# 匹配并捕获一个或多个非双引号字符（[^"]+）
pattern = r'msg:"([^"]+)"'


class BaseBot(ABC):

    @abstractmethod
    def get_access_token(self):
        """
            获取鉴权签名
        """
        pass

    @abstractmethod
    def ask_q(self, q: str, sid_cache: dict) -> dict:
        """
            问题询问
        """
        pass

    @staticmethod
    @abstractmethod
    def get_seq() -> int:
        """
            模型序号
        """
        pass

    def get_sid(self, line: str) -> str:
        sub_line = line[line.index(" sid:"):]
        sid = sub_line[5:sub_line.index(";")]
        return sid

    def get_msg(self, line: str) -> str:
        # sub_line = line[line.index(" (msg:")]
        # msg = sub_line[6:sub_line.index("\";")]
        # return msg
        match = re.search(pattern, line)
        return "" if not match else match.group(1)


class BotFactory:
    def __init__(self, bot: Type[BaseBot]) -> None:
        self.bot = bot

    def instance(self) -> BaseBot:
        return self.bot()


def get_class_names_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        tree = ast.parse(file.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            return node.name

    return None


def get_class_names_from_folder():
    folder = os.path.dirname(os.path.abspath(__file__))
    ans = {}
    for root, dirs, files in os.walk(folder):
        for file in files:
            if not file.endswith('.py') or file == os.path.basename(__file__):
                continue
            module_name = file[:-3]
            file_path = os.path.join(root, file)
            class_name = get_class_names_from_file(file_path)
            if class_name is None:
                continue
            ans[module_name] = class_name
            # bot = BotFactory(class_name).instance()
            # subclasses[bot.get_seq()] = bot
    return ans


if __name__ == '__main__':
    pass
