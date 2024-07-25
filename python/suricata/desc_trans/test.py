import json

import pandas as pd
import requests
from tqdm import tqdm

filename = "question.CSV"
# 格式：一列问题
filepath = "D:/MyProject/Threaten/"

API_KEY = "cYksJKINJyMB2BPujHdCLcbU"
SECRET_KEY = "e3aVJIze0wbTYxD8l9sQHqMuRMr2cWzT"

def ask_Q(question):
    url = "https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions?access_token=" + get_access_token()

    payload = json.dumps({
        "messages": [
            {
                "role": "user",
                "content": question
            }
        ]
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return response
    # print(response.text)


def get_access_token():
    """
    使用 AK，SK 生成鉴权签名（Access Token）
    :return: access_token，或是None(如果错误)
    """
    url = "https://aip.baidubce.com/oauth/2.0/token"
    params = {"grant_type": "client_credentials", "client_id": API_KEY, "client_secret": SECRET_KEY}
    return str(requests.post(url, params=params).json().get("access_token"))


#questions = pd.read_csv(filepath + filename, encoding="gbk", header=None, names=['questions'])
questions = pd.read_csv(filepath + filename, header=None, names=['questions'])
questions['answer'] = ""
# %%
for i in tqdm(range(len(questions))):
    question = questions.iloc[i, 0]
    Input = question
    ans = ask_Q(Input)
    ans = json.loads(ans.text)
    questions.loc[i, 'answer'] = ans['result']

questions.to_csv(filepath + '输出文件_文心一言.csv', encoding="gbk", index=False)