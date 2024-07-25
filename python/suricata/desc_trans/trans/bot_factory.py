import os
import importlib.util
from abc import abstractmethod, ABC

all_subclasses = {}


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


class BaseBot(ABC):
    subclasses = {}

    # @classmethod
    # def __init_subclass__(cls, **kwargs):
    #     super().__init_subclass__(**kwargs)
    #     BaseBot.subclasses[cls.get_seq()] = cls
    #     print(f"Registered subclass: {cls.__name__} with sequence {cls.get_seq()}")

    @abstractmethod
    def get_access_token(self):
        """
            获取鉴权签名
        """
        pass

    @abstractmethod
    def ask_q(self, q=None) -> dict:
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

    # @classmethod
    # def initialize_all_subclasses(cls):
    #     """
    #         初始化所有子类并返回它们的实例句柄
    #     """
    #     instances = {}
    #     for seq, subclass in cls.subclasses.items():
    #         instances[seq] = subclass()
    #     return instances
